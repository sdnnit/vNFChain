/*
 * vnfc_net.c : Netdev interface of vNFCModule
 *
 * Copyright 2015-17 Ryota Kawashima <kawa1983@ieee.org> Nagoya Institute of Technology
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/virtio_net.h>
#include "vnfc.h"
#include "vnfc_net.h"
#include "vnfc_flow.h"
#include "vnfc_ethtool.h"
#include "vnfc_service.h"


static inline struct net_device *vnfc_alloc_netdev(const char *name,
                                                   size_t nr_queues)
{
    return alloc_netdev_mqs(sizeof(struct vnfc_struct), name,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
                            NET_NAME_UNKNOWN,
#endif
                            vnfc_link_ops.setup, nr_queues, nr_queues);
}


static inline void vnfc_free_netdev(struct net_device *dev)
{
    struct vnfc_struct *vnfc;

    vnfc = netdev_priv(dev);
    BUG_ON(!(list_empty(&vnfc->disabled)));
    vnfc_flow_uninit(vnfc);
    free_netdev(dev);
}


static void vnfc_net_init(struct net_device *dev)
{
    ether_setup(dev);
    dev->priv_flags &= ~IFF_TX_SKB_SHARING;
    dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;

    eth_hw_addr_random(dev);

    dev->tx_queue_len = VNFC_QUEUE_LEN;  /* We prefer our own queue length */
}


/* Net device detach from fd. */
static void vnfc_net_uninit(struct net_device *dev)
{
    vnfc_detach_all(dev);
}


static int vnfc_net_open(struct net_device *dev)
{
    netif_tx_start_all_queues(dev);

    return 0;
}


static int vnfc_net_close(struct net_device *dev)
{
    netif_tx_stop_all_queues(dev);

    return 0;
}


static netdev_tx_t vnfc_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct vnfc_struct *vnfc;
    struct vnfc_file   *vfile;
    u32 nr_queues;

    vnfc = netdev_priv(dev);
    nr_queues = 1; /* TODO: Multi queue support for services */

    rcu_read_lock();

    if (list_empty(&vnfc->services_down) ||
        (skb->head[0] == VIRTIO_NET_HDR_F_DOWNSTREAM)) {
        /* The packet is forwarded to the VM */
        int txq = skb->queue_mapping;

        vfile = rcu_dereference(vnfc->vfile_vms[txq]);
        nr_queues = ACCESS_ONCE(vnfc->nr_queues);
        if (txq >= nr_queues) {
            goto drop;
        }
    } else if (skb->head[0] == VIRTIO_NET_HDR_F_UPSTREAM) {
        BUG_ON(list_empty(&vnfc->services_up));
        /* The packet is forwarded to the last service (Tx-path) */
        vfile = list_first_entry(&vnfc->services_up, struct vnfc_service,
                                 list_up)->vfile_to_svc;
    } else {
        /* The packet is forwarded to the first service (Rx-path) */
        vfile = list_first_entry(&vnfc->services_down, struct vnfc_service,
                                 list_down)->vfile_to_svc;
    }
    BUG_ON(!vfile);

    /* Limit the number of packets queued by dividing txq length with the
     * number of queues.
     */
    if (skb_queue_len(&vfile->socket.sk->sk_receive_queue) * nr_queues
                      >= dev->tx_queue_len) {
        goto drop;
    }

    /* Orphan the skb - required as we might hang on to it
       for indefinite time. */
    if (unlikely(skb_orphan_frags(skb, GFP_ATOMIC))) {
        goto drop;
    }
    skb_orphan(skb);

    nf_reset(skb);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
    if (skb_array_produce(&vfile->tx_array, skb)) {
        goto drop;
    }
#else
    /* Enqueue the packet */
    skb_queue_tail(&vfile->socket.sk->sk_receive_queue, skb);
#endif

    /* Notify and wake up the reader */
    if (vfile->flags & VNFC_FASYNC) {
        kill_fasync(&vfile->fasync, SIGIO, POLL_IN);
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
    vfile->socket.sk->sk_data_ready(vfile->socket.sk);
#else
    wake_up_interruptible_poll(&vfile->wq.wait, POLLIN |
                                                POLLRDNORM |
                                                POLLRDBAND);
#endif

    pr_devel("[%s] (%s) xmit a packet: %d bytes\n",
             DRV_NAME, dev->name, skb->len);

    rcu_read_unlock();
    return NETDEV_TX_OK;

drop:
    dev->stats.tx_dropped++;
    skb_tx_error(skb);
    kfree_skb(skb);
    rcu_read_unlock();
    return NETDEV_TX_OK;
}


#define MIN_MTU 68
#define MAX_MTU 65535

static int vnfc_net_change_mtu(struct net_device *dev, int new_mtu)
{
    if ((new_mtu < MIN_MTU) || ((new_mtu + dev->hard_header_len) > MAX_MTU)) {
        return -EINVAL;
    }
    dev->mtu = new_mtu;
    return 0;
}


static netdev_features_t vnfc_net_fix_features(struct net_device *dev,
                                               netdev_features_t features)
{
    struct vnfc_struct *vnfc = netdev_priv(dev);

    return (features & vnfc->set_features) | (features & ~VNFC_USER_FEATURES);
}


#ifdef CONFIG_NET_POLL_CONTROLLER
static void vnfc_net_poll_controller(struct net_device *dev)
{
    pr_devel("[%s] (%s) vnfc_net_poll_controller\n", DRV_NAME, dev->name);
}
#endif


static inline int vnfc_flags(struct vnfc_struct *vnfc)
{
    int flags;

    flags = IFF_VNFC;

    if (vnfc->flags & VNFC_ONE_QUEUE) {
        flags |= IFF_ONE_QUEUE;
    }
    if (vnfc->flags & VNFC_VNET_HDR) {
        flags |= IFF_VNET_HDR;
    }
    if (vnfc->flags & VNFC_MULTI_QUEUE) {
        flags |= IFF_MULTI_QUEUE;
    }

    return flags;
}


static ssize_t vnfc_show_flags(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct vnfc_struct *vnfc;

    vnfc = netdev_priv(to_net_dev(dev));

    return sprintf(buf, "0x%x\n", vnfc_flags(vnfc));
}


static ssize_t vnfc_show_owner(struct device *dev,
                               struct device_attribute *attr, char *buf)
{
    struct vnfc_struct *vnfc;

    vnfc = netdev_priv(to_net_dev(dev));
    if (uid_valid(vnfc->owner)) {
        return sprintf(buf, "%u\n",
                       from_kuid_munged(current_user_ns(), vnfc->owner));
    }
    return sprintf(buf, "-1\n");
}


static ssize_t vnfc_show_group(struct device *dev,
                               struct device_attribute *attr, char *buf)
{
    struct vnfc_struct *vnfc;

    vnfc = netdev_priv(to_net_dev(dev));

    if (gid_valid(vnfc->group)) {
        return sprintf(buf, "%u\n",
                       from_kgid_munged(current_user_ns(), vnfc->group));
    }
    return sprintf(buf, "-1\n");
}


static DEVICE_ATTR(vnfc_flags, 0444, vnfc_show_flags, NULL);
static DEVICE_ATTR(owner, 0444, vnfc_show_owner, NULL);
static DEVICE_ATTR(group, 0444, vnfc_show_group, NULL);


static inline bool vnfc_not_capable(struct vnfc_struct *vnfc)
{
    const struct cred *cred = current_cred();
    struct net *net = dev_net(vnfc->dev);

    return ((uid_valid(vnfc->owner) && !uid_eq(cred->euid, vnfc->owner)) ||
            (gid_valid(vnfc->group) && !in_egroup_p(vnfc->group))) &&
            !ns_capable(net->user_ns, CAP_NET_ADMIN);
}


static int vnfc_alloc_device(struct vnfc_file *vfile, struct net *net, struct ifreq *ifr, struct net_device **pdev)
{
    struct vnfc_struct *vnfc;
    struct net_device   *dev;
    char *name;
    size_t nr_queues;
    int err;

#ifndef DEBUG
    if (!ns_capable(net->user_ns, CAP_NET_ADMIN)) {
        return -EPERM;
    }
#endif

    /* Set the device name */
    if (*ifr->ifr_name) {
        name = ifr->ifr_name;
    } else {
#ifdef FAKE_TUN
        name = "tap%d";
#else
        name = "vnfc%d";
#endif
    }

    if (ifr->ifr_flags & IFF_MULTI_QUEUE) {
        nr_queues = MAX_VNFC_QUEUES;
    } else {
        nr_queues = 1;
    }

    /* Allocate a net device */
    dev = vnfc_alloc_netdev(name, nr_queues);
    if (unlikely(!dev)) {
        return -ENOMEM;
    }

    dev_net_set(dev, net);
    dev->rtnl_link_ops = &vnfc_link_ops;
    dev->ifindex       = vfile->ifindex;

    vnfc = netdev_priv(dev);
    vnfc->dev         = dev;
    vnfc->flags       = VNFC_DEV;
    vnfc->vnet_hdr_sz = sizeof(struct virtio_net_hdr);
    vnfc->sndbuf      = vfile->socket.sk->sk_sndbuf;

    spin_lock_init(&vnfc->lock);

    vnfc_net_init(dev);

    err = vnfc_flow_init(vnfc);
    if (err < 0) {
        goto err_free_dev;
    }

    INIT_LIST_HEAD(&vnfc->disabled);
    err = vnfc_attach(vnfc, vfile);
    if (err < 0) {
        goto err_free_flow;
    }

    /* Register the net device */
    err = register_netdevice(dev);
    if (err < 0) {
        goto err_detach;
    }

    if (device_create_file(&dev->dev, &dev_attr_vnfc_flags) ||
        device_create_file(&dev->dev, &dev_attr_owner) ||
        device_create_file(&dev->dev, &dev_attr_group)) {
        pr_warn("[%s] (%s): Failed to create the sys file\n", DRV_NAME, dev->name);
    }

    *pdev = dev;
    return 0;

err_detach:
    vnfc_detach_all(dev);
err_free_flow:
    vnfc_flow_uninit(vnfc);
err_free_dev:
    free_netdev(dev);
    return err;
}


static int vnfc_check_device_settings(struct vnfc_file *vfile,
                                      struct net_device *dev,
                                      struct ifreq *ifr)
{
    struct vnfc_struct *vnfc;
    int err;

    vnfc = netdev_priv(dev);

    if (ifr->ifr_flags & IFF_VNFC_EXCL) {
        return -EBUSY;
    }
    if (!!(ifr->ifr_flags & IFF_MULTI_QUEUE) !=
        !!(vnfc->flags & VNFC_MULTI_QUEUE)) {
        return -EINVAL;
    }
#ifndef DEBUG
    if (vnfc_not_capable(vnfc)) {
        return -EPERM;
    }
#endif
    err = vnfc_attach(vnfc, vfile);
    if (err < 0) {
        return err;
    }

    if ((vnfc->flags & VNFC_MULTI_QUEUE) &&
        (vnfc->nr_queues + vnfc->nr_disabled > 1)) {
        /* One or more queue has already been attached, no need
         * to initialize the device again.
         */
        return 0;
    }

    return 0;
}


extern int vnfc_set_iff(struct net *net, struct vnfc_file *vfile,
                        struct ifreq *ifr)
{
    struct vnfc_struct *vnfc;
    struct net_device   *dev;
    int err;

    if (vfile->detached) {
        return -EINVAL;
    }

    dev = __dev_get_by_name(net, ifr->ifr_name);
    if (dev) {
        err = vnfc_check_device_settings(vfile, dev, ifr);
        if (unlikely(err == -EALREADY)) {
            return 0;
        }
    } else {
        err = vnfc_alloc_device(vfile, net, ifr, &dev);
    }
    if (unlikely(err)) {
        return err;
    }

    vnfc = netdev_priv(dev);
    BUG_ON(!vnfc);

    netif_carrier_on(vnfc->dev);

    if (ifr->ifr_flags & IFF_ONE_QUEUE) {
        vnfc->flags |= VNFC_ONE_QUEUE;
    } else {
        vnfc->flags &= ~VNFC_ONE_QUEUE;
    }
    if (ifr->ifr_flags & IFF_VNET_HDR) {
        vnfc->flags |= VNFC_VNET_HDR;
    } else {
        vnfc->flags &= ~VNFC_VNET_HDR;
    }
    if (ifr->ifr_flags & IFF_MULTI_QUEUE) {
        vnfc->flags |= VNFC_MULTI_QUEUE;
    } else {
        vnfc->flags &= ~VNFC_MULTI_QUEUE;
    }

    if (netif_running(vnfc->dev)) {
        netif_tx_wake_all_queues(vnfc->dev);
    }

    strcpy(ifr->ifr_name, vnfc->dev->name);

    pr_info("[%s] set the interface: %s\n", DRV_NAME, vnfc->dev->name);

    return 0;
}


extern int vnfc_get_iff(struct net *net, struct vnfc_struct *vnfc, struct ifreq *ifr)
{
    strcpy(ifr->ifr_name, vnfc->dev->name);

    ifr->ifr_flags = vnfc_flags(vnfc);

    return 0;
}


/* We try to identify a flow through its rxhash first. The reason that
 * we do not check rxq no. is becuase some cards(e.g 82599), chooses
 * the rxq based on the txq where the last packet of the flow comes. As
 * the userspace application move between processors, we may get a
 * different rxq no. here. If we could not get rxhash, then we would
 * hope the rxq no. may help here.
 */
static u16 vnfc_select_queue(struct net_device *dev, struct sk_buff *skb
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
                             , void *accel_priv, select_queue_fallback_t fallback
#endif
                             )
{
    struct vnfc_struct *vnfc = netdev_priv(dev);
    struct vnfc_flow_entry *entry;
    u32 rxhash;
    u32 nr_queues;

    rcu_read_lock();
    nr_queues = ACCESS_ONCE(vnfc->nr_queues);

    rxhash = skb_get_hash(skb);
    if (rxhash) {
        entry = vnfc_flow_find(vnfc, rxhash);
        if (entry) {
            rxhash = entry->queue_index;
        } else {
            /* use multiply and shift instead of expensive divide */
            rxhash = ((u64)rxhash * nr_queues) >> 32;
        }
    } else if (likely(skb_rx_queue_recorded(skb))) {
        rxhash = skb_get_rx_queue(skb);
        while (unlikely(rxhash >= nr_queues)) {
            rxhash -= nr_queues;
        }
    }

    rcu_read_unlock();
    return rxhash;
}


static void vnfc_rtnl_setup(struct net_device *dev)
{
    struct vnfc_struct *vnfc;

    /* Initialize the vnfc device */

    vnfc = netdev_priv(dev);
    vnfc->dev         = dev;
    vnfc->owner       = INVALID_UID;
    vnfc->group       = INVALID_GID;
    vnfc->vnet_hdr_sz = sizeof(struct virtio_net_hdr);
    vnfc->sndbuf      = INT_MAX;
    vnfc->flags       = VNFC_DEV;

    INIT_LIST_HEAD(&vnfc->services);
    INIT_LIST_HEAD(&vnfc->services_up);
    INIT_LIST_HEAD(&vnfc->services_down);

    /* Initialize the net device */

    dev->hw_features   = NETIF_F_SG | NETIF_F_FRAGLIST | VNFC_USER_FEATURES |
                         NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_STAG_TX;
    dev->features      = dev->hw_features;
    dev->vlan_features = dev->features & ~(NETIF_F_HW_VLAN_CTAG_TX |
                                           NETIF_F_HW_VLAN_STAG_TX);

    dev->rtnl_link_ops = &vnfc_link_ops;
    dev->netdev_ops    = &vnfc_netdev_ops;
    dev->ethtool_ops   = &vnfc_ethtool_ops;
    dev->destructor    = vnfc_free_netdev;
}


static int vnfc_rtnl_validate(struct nlattr *tb[], struct nlattr *data[])
{
    return -EINVAL;
}


struct net_device_ops vnfc_netdev_ops = {
    .ndo_uninit          = vnfc_net_uninit,
    .ndo_open            = vnfc_net_open,
    .ndo_stop            = vnfc_net_close,
    .ndo_start_xmit      = vnfc_net_xmit,
    .ndo_change_mtu      = vnfc_net_change_mtu,
    .ndo_fix_features    = vnfc_net_fix_features,
    .ndo_set_mac_address = eth_mac_addr,
    .ndo_validate_addr   = eth_validate_addr,
    .ndo_select_queue    = vnfc_select_queue,
#ifdef CONFIG_NET_POLL_CONTROLLER
    .ndo_poll_controller = vnfc_net_poll_controller,
#endif
};


struct rtnl_link_ops vnfc_link_ops __read_mostly = {
    .kind      = DRV_NAME,
    .priv_size = sizeof(struct vnfc_struct),
    .setup     = vnfc_rtnl_setup,
    .validate  = vnfc_rtnl_validate,
};
