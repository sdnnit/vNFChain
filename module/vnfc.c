/*
 * vnfc.c : Main body of vNFCModule
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
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/miscdevice.h>
#include <linux/skbuff.h>
#include <linux/errno.h>
#include "vnfc.h"
#include "vnfc_file.h"
#include "vnfc_net.h"
#include "vnfc_flow.h"
#include "vnfc_ethtool.h"


static struct miscdevice vnfc_miscdev = {
#ifdef FAKE_TUN
    .minor    = TUN_MINOR,
    .name     = "tun",
    .nodename = "net/tun",
#else
    .minor    = VNFC_MINOR,
    .name     = DRV_NAME,
    .nodename = "net/vnfc",
#endif
    .fops     = &vnfc_fops,
};


extern struct vnfc_struct *vnfc_get(struct vnfc_file *vfile)
{
    struct vnfc_struct *vnfc;

    rcu_read_lock();
    vnfc = rcu_dereference(vfile->vnfc);
    if (vnfc) {
        dev_hold(vnfc->dev);
    }
    rcu_read_unlock();

    return vnfc;
}


extern void vnfc_put(struct vnfc_struct *vnfc)
{
    dev_put(vnfc->dev);
}


static struct vnfc_struct *vnfc_enable_queue(struct vnfc_file *vfile)
{
    struct vnfc_struct *vnfc = vfile->detached;

    vfile->detached = NULL;
    list_del_init(&vfile->next);
    vnfc->nr_disabled--;
    return vnfc;
}


static void vnfc_disable_queue(struct vnfc_struct *vnfc,
                               struct vnfc_file *vfile)
{
    vfile->detached = vnfc;
    list_add_tail(&vfile->next, &vnfc->disabled);
    vnfc->nr_disabled++;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
static void vnfc_queue_purge(struct vnfc_file *vfile)
{
    struct sk_buff *skb;

    while ((skb = skb_array_consume(&vfile->tx_array)) != NULL) {
        kfree_skb(skb);
    }

    skb_queue_purge(&vfile->sk.sk_error_queue);
}
#endif


static void vnfc_set_real_num_queues(struct vnfc_struct *vnfc)
{
    netif_set_real_num_tx_queues(vnfc->dev, vnfc->nr_queues);
    netif_set_real_num_rx_queues(vnfc->dev, vnfc->nr_queues);
}


/**
 * vnfc_attach - attach the file instance to the vnfc device
 * @vnfc: vnfc device instance
 * @vfile: vnfc file instance
 */
extern int vnfc_attach(struct vnfc_struct *vnfc, struct vnfc_file *vfile)
{
    int err;

    if (rtnl_dereference(vfile->vnfc) && !vfile->detached) {
        err = -EINVAL;
        goto out;
    }

    if (!(vnfc->flags & VNFC_MULTI_QUEUE) && vnfc->nr_queues == 1) {
        err = -EBUSY;
        goto out;
    }

    if (!vfile->detached &&
        vnfc->nr_queues + vnfc->nr_disabled == MAX_VNFC_QUEUES) {
        err = -E2BIG;
        goto out;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
    if (!vfile->detached && skb_array_init(&vfile->tx_array, vnfc->dev->tx_queue_len, GFP_KERNEL)) {
        err = -ENOMEM;
        goto out;
    }
#endif
    err = 0;

    vfile->queue_index = vnfc->nr_queues++;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
    vfile->socket.sk->sk_shutdown &= ~RCV_SHUTDOWN;
#endif
    rcu_assign_pointer(vfile->vnfc, vnfc);
    rcu_assign_pointer(vnfc->vfile_vms[vfile->queue_index], vfile);

    if (vfile->detached) {
        vnfc_enable_queue(vfile);
    } else {
        sock_hold(&vfile->sk);
    }
    vnfc_set_real_num_queues(vnfc);

out:
    return err;
}


extern void __vnfc_detach(struct vnfc_file *vfile, bool clean)
{
    struct vnfc_struct *vnfc;

    vnfc = rtnl_dereference(vfile->vnfc);

    if (vnfc && !vfile->detached) {
        struct vnfc_file *moved;

        u16 index = vfile->queue_index;
        BUG_ON(index >= vnfc->nr_queues);

        /* Move last entry to the deleted space */
        rcu_assign_pointer(vnfc->vfile_vms[index],
                           vnfc->vfile_vms[vnfc->nr_queues - 1]);
        moved = rtnl_dereference(vnfc->vfile_vms[index]);
        moved->queue_index = index;

        vnfc->nr_queues--;
        if (clean) {
            rcu_assign_pointer(vfile->vnfc, NULL);
            sock_put(&vfile->sk);
        } else {
            vnfc_disable_queue(vnfc, vfile);
        }

        synchronize_net();

        vnfc_flow_delete_by_queue(vnfc, vnfc->nr_queues + 1);

        /* Drop read queue */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
        vnfc_queue_purge(vfile);
#else
        skb_queue_purge(&vfile->sk.sk_receive_queue);
#endif
        vnfc_set_real_num_queues(vnfc);
    } else if (vfile->detached && clean) {
        vnfc = vnfc_enable_queue(vfile);
        sock_put(&vfile->sk);
    }

    if (clean) {
        if (vnfc && vnfc->nr_queues == 0 && vnfc->nr_disabled == 0) {
            netif_carrier_off(vnfc->dev);

            if (!(vnfc->flags & VNFC_PERSIST) &&
                vnfc->dev->reg_state == NETREG_REGISTERED) {
                unregister_netdevice(vnfc->dev);
            }
        }
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 8, 0)
        if (vnfc) {
            skb_array_cleanup(&vfile->tx_array);
        }
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 2, 0)
        sock_put(&vfile->sk);
#else
        BUG_ON(!test_bit(SOCK_EXTERNALLY_ALLOCATED, &vfile->socket.flags));
        sk_release_kernel(&vfile->sk);
#endif
    }
}


/**
 * vnfc_detach - detach the file instance from the vnfc device
 * @vfile: vnfc file instance
 */
extern void vnfc_detach(struct vnfc_file *vfile, bool clean)
{
    rtnl_lock();
    __vnfc_detach(vfile, clean);
    rtnl_unlock();
}


extern void vnfc_detach_all(struct net_device *dev)
{
    struct vnfc_struct *vnfc = netdev_priv(dev);
    struct vnfc_file *vfile, *tmp;
    int nr_queues;
    int i;

    nr_queues = vnfc->nr_queues;
    for (i = 0; i < nr_queues; i++) {
        vfile = rtnl_dereference(vnfc->vfile_vms[i]);
        BUG_ON(!vfile);
        wake_up_all(&vfile->wq.wait);
        rcu_assign_pointer(vfile->vnfc, NULL);
        vnfc->nr_queues--;
    }
    list_for_each_entry(vfile, &vnfc->disabled, next) {
        wake_up_all(&vfile->wq.wait);
        rcu_assign_pointer(vfile->vnfc, NULL);
    }
    BUG_ON(vnfc->nr_queues != 0);

    synchronize_net();
    for (i = 0; i < nr_queues; i++) {
        vfile = rtnl_dereference(vnfc->vfile_vms[i]);
        /* Drop read queue */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
        vnfc_queue_purge(vfile);
#else
        skb_queue_purge(&vfile->sk.sk_receive_queue);
#endif
        sock_put(&vfile->sk);
    }
    list_for_each_entry_safe(vfile, tmp, &vnfc->disabled, next) {
        vnfc_enable_queue(vfile);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
        vnfc_queue_purge(vfile);
#else
        skb_queue_purge(&vfile->sk.sk_receive_queue);
#endif
        sock_put(&vfile->sk);
    }
    BUG_ON(vnfc->nr_disabled != 0);

    if (vnfc->flags & VNFC_PERSIST) {
        module_put(THIS_MODULE);
    }
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
static int vnfc_queue_resize(struct vnfc_struct *vnfc)
{
    struct net_device *dev;
    struct vnfc_file *vfile;
    struct skb_array **arrays;
    int n;
    int ret;
    int i;

    n = vnfc->nr_queues + vnfc->nr_disabled;
    arrays = kmalloc(sizeof(*arrays) * n, GFP_KERNEL);
    if (! arrays) {
        return -ENOMEM;
    }

    for (i = 0; i < vnfc->nr_queues; i++) {
        vfile = rtnl_dereference(vnfc->vfile_vms[i]);
        arrays[i] = &vfile->tx_array;
    }

    list_for_each_entry(vfile, &vnfc->disabled, next) {
        arrays[i++] = &vfile->tx_array;
    }

    ret = skb_array_resize_multiple(arrays, n, dev->tx_queue_len, GFP_KERNEL);
    kfree(arrays);
    return ret;
}


static int vnfc_device_event(struct notifier_block *unused,
                              unsigned long event, void *ptr)
{
    struct net_device *dev;
    struct vnfc_struct *vnfc;

    dev = netdev_notifier_info_to_dev(ptr);
    vnfc = netdev_priv(dev);

    if (dev->rtnl_link_ops != &vnfc_link_ops) {
        return NOTIFY_DONE;
    }

    switch (event) {
    case NETDEV_CHANGE_TX_QUEUE_LEN:
        if (vnfc_queue_resize(vnfc)) {
            return NOTIFY_BAD;
        }
        break;
    default:
        break;
    }

    return NOTIFY_DONE;
}


static struct notifier_block vnfc_notifier_block __read_mostly = {
    .notifier_call = vnfc_device_event,
};
#endif

static int __init vnfc_init(void)
{
    int err;

    pr_info("[%s] %s, %s\n", DRV_NAME, DRV_DESCRIPTION, DRV_VERSION);
    pr_info("[%s] %s\n", DRV_NAME, DRV_AUTHOR);

    err = rtnl_link_register(&vnfc_link_ops);
    if (err) {
        pr_err("[%s] Can't register link operations\n", DRV_NAME);
        goto err_linkops;
    }

    err = misc_register(&vnfc_miscdev);
    if (err) {
        pr_err("[%s] Can't register misc device: %d\n", DRV_NAME, VNFC_MINOR);
        goto err_misc;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
    register_netdevice_notifier(&vnfc_notifier_block);
#endif
    return 0;

err_misc:
    rtnl_link_unregister(&vnfc_link_ops);

err_linkops:
    return err;
}


static void vnfc_cleanup(void)
{
    misc_deregister(&vnfc_miscdev);
    rtnl_link_unregister(&vnfc_link_ops);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
    unregister_netdevice_notifier(&vnfc_notifier_block);
#endif
}

#ifdef FAKE_TUN
/* Get an underlying socket object from tun file.  Returns error unless file is
 * attached to a device.  The returned object works like a packet socket, it
 * can be used for sock_sendmsg/sock_recvmsg.  The caller is responsible for
 * holding a reference to the file for as long as the socket is in use. */
struct socket *tun_get_socket(struct file *file)
{
    struct vnfc_file *vfile;
    if (file->f_op != &vnfc_fops) {
        return ERR_PTR(-EINVAL);
    }
    vfile = file->private_data;
    if (!vfile) {
        return ERR_PTR(-EBADFD);
    }
    return &vfile->socket;
}
EXPORT_SYMBOL_GPL(tun_get_socket);
#endif

module_init(vnfc_init);
module_exit(vnfc_cleanup);

MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR(DRV_AUTHOR);
MODULE_LICENSE("GPL");
MODULE_ALIAS_MISCDEV(VNFC_MINOR);
