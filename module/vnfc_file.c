/*
 * vnfc_file.c : File interface of vNFCModule
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
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/if_vlan.h>
#include <linux/nsproxy.h>
#include <linux/virtio_net.h>
#include "vnfc.h"
#include "vnfc_net.h"
#include "vnfc_flow.h"
#include "vnfc_service.h"

#define GOODCOPY_LEN	128

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
#define SOCKWQ_ASYNC_NOSPACE SOCK_ASYNC_NOSPACE
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
static int vnfc_sendmsg(struct socket *sock, struct msghdr *m,
                        size_t total_len);
static int vnfc_recvmsg(struct socket *sock, struct msghdr *m,
                        size_t total_len, int flags);
#else
static int vnfc_sendmsg(struct kiocb *iocb, struct socket *sock,
                        struct msghdr *m, size_t total_len);
static int vnfc_recvmsg(struct kiocb *iocb, struct socket *sock,
                        struct msghdr *m, size_t total_len, int flags);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
static int vnfc_peek_len(struct socket *sock);
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 1, 0)
static int vnfc_release(struct socket *sock);
#endif


static struct proto vnfc_proto = {
    .name     = DRV_NAME,
    .owner    = THIS_MODULE,
    .obj_size = sizeof(struct vnfc_file),
};


static const struct proto_ops vnfc_socket_ops = {
    .sendmsg  = vnfc_sendmsg,
    .recvmsg  = vnfc_recvmsg,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
    .peek_len = vnfc_peek_len,
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 1, 0)
    .release  = vnfc_release,
#endif
};


#ifdef CONFIG_VNFC_VNET_CROSS_LE
static inline bool vnfc_legacy_is_little_endian(struct vnfc_struct *vnfc)
{
    return vnfc->flags & vnfc_VNET_BE ? false :
                                        virtio_legacy_is_little_endian();
}


static long vnfc_get_vnet_be(struct vnfc_struct *vnfc, int __user *argp)
{
    int be = !!(vnfc->flags & vnfc_VNET_BE);

    if (put_user(be, argp)) {
        return -EFAULT;
    }
    return 0;
}


static long vnfc_set_vnet_be(struct vnfc_struct *vnfc, int __user *argp)
{
    int be;

    if (get_user(be, argp)) {
        return -EFAULT;
    }
    if (be) {
        vnfc->flags |= vnfc_VNET_BE;
    } else {
        vnfc->flags &= ~vnfc_VNET_BE;
    }
    return 0;
}
#else
static inline bool vnfc_legacy_is_little_endian(struct vnfc_struct *vnfc)
{
    return virtio_legacy_is_little_endian();
}


static long vnfc_get_vnet_be(struct vnfc_struct *vnfc, int __user *argp)
{
    return -EINVAL;
}


static long vnfc_set_vnet_be(struct vnfc_struct *vnfc, int __user *argp)
{
    return -EINVAL;
}
#endif /* CONFIG_VNFC_VNET_CROSS_LE */


static inline bool vnfc_is_little_endian(struct vnfc_struct *vnfc)
{
    return vnfc->flags & VNFC_VNET_LE ||
           vnfc_legacy_is_little_endian(vnfc);
}


static inline u16 vnfc16_to_cpu(struct vnfc_struct *vnfc, __virtio16 val)
{
    return __virtio16_to_cpu(vnfc_is_little_endian(vnfc), val);
}


static inline __virtio16 cpu_to_vnfc16(struct vnfc_struct *vnfc, u16 val)
{
    return __cpu_to_virtio16(vnfc_is_little_endian(vnfc), val);
}


static void vnfc_sock_write_space(struct sock *sk)
{
    struct vnfc_file *vfile;
    wait_queue_head_t *wqueue;

    if (! sock_writeable(sk)) {
        return ;
    }

    if (! test_and_clear_bit(SOCKWQ_ASYNC_NOSPACE, &sk->sk_socket->flags)) {
        return ;
    }

    wqueue = sk_sleep(sk);
    if (wqueue && waitqueue_active(wqueue)) {
        wake_up_interruptible_sync_poll(wqueue, POLLOUT |
                                                POLLWRNORM |
                                                POLLWRBAND);
    }

    vfile = container_of(sk, struct vnfc_file, sk);
    kill_fasync(&vfile->fasync, SIGIO, POLL_OUT);
}


static struct sk_buff *vnfc_alloc_skb(struct vnfc_file *vfile, size_t prepad,
                                      size_t len, size_t linear, bool nonblock)
{
    struct sock *sk;
    struct sk_buff *skb;
    int err;

    sk = vfile->socket.sk;

    /* Under a page?  Don't bother with paged skb. */
    if ((prepad + len < PAGE_SIZE) || (linear == 0)) {
        linear = len;
    }

    skb = sock_alloc_send_pskb(sk, prepad + linear, len - linear, nonblock,
                               &err, 0);
    if (unlikely(! skb)) {
        return ERR_PTR(err);
    }

    skb_reserve(skb, prepad);
    skb->head[0] = 0; /* This field is used for service direction */
    skb_put(skb, linear);
    skb->data_len = len - linear;
    skb->len += skb->data_len;

    return skb;
}


static inline ssize_t vnfc_xmit_skb_to_service(struct sk_buff *skb,
                                            struct net_device *dev)
{
    skb->head[0] = VIRTIO_NET_HDR_F_UPSTREAM;
    return dev->netdev_ops->ndo_start_xmit(skb, dev);
}


static inline ssize_t vnfc_xmit_skb_to_down(struct sk_buff *skb,
                                            struct net_device *dev)
{
    skb->head[0] = VIRTIO_NET_HDR_F_DOWNSTREAM;
    return dev->netdev_ops->ndo_start_xmit(skb, dev);
}


static ssize_t vnfc_xmit_skb_to_up(struct vnfc_struct *vnfc,
                                   struct sk_buff *skb, size_t data_len,
                                   struct virtio_net_hdr *gso, u32 *rxhash)
{
    if (gso->gso_type != VIRTIO_NET_HDR_GSO_NONE) {
        switch (gso->gso_type & ~VIRTIO_NET_HDR_GSO_ECN) {
        case VIRTIO_NET_HDR_GSO_TCPV4:
            skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
            break;
        case VIRTIO_NET_HDR_GSO_TCPV6:
            skb_shinfo(skb)->gso_type = SKB_GSO_TCPV6;
            break;
        case VIRTIO_NET_HDR_GSO_UDP:
            skb_shinfo(skb)->gso_type = SKB_GSO_UDP;
            break;
        default:
            return -EINVAL;
        }

        if (gso->gso_type & VIRTIO_NET_HDR_GSO_ECN) {
            skb_shinfo(skb)->gso_type |= SKB_GSO_TCP_ECN;
        }

        skb_shinfo(skb)->gso_size = vnfc16_to_cpu(vnfc, gso->gso_size);
        if (skb_shinfo(skb)->gso_size == 0) {
            return -EINVAL;
        }

        /* Header must be checked, and gso_segs computed. */
        skb_shinfo(skb)->gso_type |= SKB_GSO_DODGY;
        skb_shinfo(skb)->gso_segs = 0;
    }

    skb_reset_network_header(skb);
    skb_probe_transport_header(skb, 0);

    *rxhash = skb_get_hash(skb);

    return netif_rx_ni(skb);
}


#if LINUX_VERSION_CODE <  KERNEL_VERSION(3,12,0)
/* set skb frags from iovec, this can move to core network code for reuse */
static int zerocopy_sg_from_iovec(struct sk_buff *skb, const struct iovec *from,
                                  int offset, size_t count)
{
    int len = iov_length(from, count) - offset;
    int copy = skb_headlen(skb);
    int size, offset1 = 0;
    int i = 0;

    /* Skip over from offset */
    while (count && (offset >= from->iov_len)) {
        offset -= from->iov_len;
        ++from;
        --count;
    }

    /* copy up to skb headlen */
    while (count && (copy > 0)) {
        size = min_t(unsigned int, copy, from->iov_len - offset);
        if (copy_from_user(skb->data + offset1, from->iov_base + offset, size))
            return -EFAULT;
        if (copy > size) {
            ++from;
            --count;
            offset = 0;
        } else {
            offset += size;
        }
        copy -= size;
        offset1 += size;
    }

    if (len == offset1) {
        return 0;
    }

    while (count--) {
        struct page *page[MAX_SKB_FRAGS];
        int num_pages;
        unsigned long base;
        unsigned long truesize;

        len = from->iov_len - offset;
        if (!len) {
            offset = 0;
            ++from;
            continue;
        }
        base = (unsigned long)from->iov_base + offset;
        size = ((base & ~PAGE_MASK) + len + ~PAGE_MASK) >> PAGE_SHIFT;
        if (i + size > MAX_SKB_FRAGS) {
            return -EMSGSIZE;
        }
        num_pages = get_user_pages_fast(base, size, 0, &page[i]);
        if (num_pages != size) {
            int j;

            for (j = 0; j < num_pages; j++) {
                put_page(page[i + j]);
            }
            return -EFAULT;
        }
        truesize = size * PAGE_SIZE;
        skb->data_len += len;
        skb->len += len;
        skb->truesize += truesize;
        atomic_add(truesize, &skb->sk->sk_wmem_alloc);
        while (len) {
            int off = base & ~PAGE_MASK;
            int size = min_t(int, len, PAGE_SIZE - off);
            __skb_fill_page_desc(skb, i, page[i], off, size);
            skb_shinfo(skb)->nr_frags++;
            /* increase sk_wmem_alloc */
            base += size;
            len -= size;
            i++;
        }
        offset = 0;
        ++from;
    }
    return 0;
}


static unsigned long iov_pages(const struct iovec *iv, int offset,
                               unsigned long nr_segs)
{
    unsigned long seg, base;
    int pages = 0, len, size;

    while (nr_segs && (offset >= iv->iov_len)) {
        offset -= iv->iov_len;
        iv++;
        nr_segs--;
    }

    for (seg = 0; seg < nr_segs; seg++) {
        base = (unsigned long)iv[seg].iov_base + offset;
        len = iv[seg].iov_len - offset;
        size = ((base & ~PAGE_MASK) + len + ~PAGE_MASK) >> PAGE_SHIFT;
        pages += size;
        offset = 0;
    }

    return pages;
}
#endif


/** Get packet from user space buffer
 * @total_len: Total data length of all the i/o vectors
 * @iov_len: The number of i/o vectors
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)

static ssize_t vnfc_get_user(struct vnfc_struct *vnfc,
                             struct vnfc_file *vfile, void *msg_control,
                             struct iov_iter *from,  bool nonblock)
{
    struct net_device *dev;
    struct sk_buff *skb;
    struct virtio_net_hdr gso;
    size_t total_len;
    size_t data_len;
    size_t copy_len;
    size_t linear_len;
    size_t good_linear_len;
    size_t align;
    int err;
    bool zerocopy;
    bool do_vnfc;

    dev         = vnfc->dev;
    total_len   = iov_iter_count(from);
    data_len    = total_len;
    align       = NET_SKB_PAD + NET_IP_ALIGN;
    zerocopy    = false;

    memset(&gso, 0, sizeof(gso));

    if (vnfc->flags & VNFC_VNET_HDR) {
        if (unlikely(data_len < vnfc->vnet_hdr_sz)) {
            return -EINVAL;
        }
        data_len -= vnfc->vnet_hdr_sz;

        if (copy_from_iter(&gso, sizeof(gso), from) != sizeof(gso)) {
            return -EFAULT;
        }
        if (gso.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) {
            u16 csum_start  = vnfc16_to_cpu(vnfc, gso.csum_start);
            u16 csum_offset = vnfc16_to_cpu(vnfc, gso.csum_offset);
            u16 hdr_len     = vnfc16_to_cpu(vnfc, gso.hdr_len);

            if (csum_start + csum_offset + 2 > hdr_len) {
                gso.hdr_len = cpu_to_vnfc16(vnfc, csum_start + csum_offset + 2);
            }
        }
        if (unlikely(vnfc16_to_cpu(vnfc, gso.hdr_len) > data_len)) {
            return -EINVAL;
        }
        iov_iter_advance(from, vnfc->vnet_hdr_sz - sizeof(gso));
    }

    if (unlikely((data_len < ETH_HLEN) ||
        (gso.hdr_len && vnfc16_to_cpu(vnfc, gso.hdr_len) < ETH_HLEN))) {
        return -EINVAL;
    }

    if (list_empty(&vnfc->services)) {
        /* There is no service in the vnfc */
        do_vnfc = false;
    } else {
        if (vfile->service) {
            /* The packet is forwarded from a service */
            do_vnfc = false;
        } else if (list_empty(&vnfc->services_up)) {
            /* There is no upstream service */
            do_vnfc = false;
        } else {
            do_vnfc = true;
        }
    }

    good_linear_len = SKB_MAX_HEAD(align);

    if (msg_control) {
        struct iov_iter i = *from;

        /* There are 256 bytes to be copied in skb, so there is
         * enough room for skb expand head in case it is used.
         * The rest of the buffer is mapped from userspace.
         */
        copy_len = gso.hdr_len ? vnfc16_to_cpu(vnfc, gso.hdr_len) :
                                 GOODCOPY_LEN;
        if (copy_len > good_linear_len) {
            copy_len = good_linear_len;
        }
        linear_len = copy_len;
        iov_iter_advance(&i, copy_len);
        if (iov_iter_npages(&i, INT_MAX) <= MAX_SKB_FRAGS) {
            zerocopy = true;
        }
    }

    if (!zerocopy) {
        copy_len = data_len;
        if (vnfc16_to_cpu(vnfc, gso.hdr_len) > good_linear_len) {
            linear_len = good_linear_len;
        } else {
            linear_len = vnfc16_to_cpu(vnfc, gso.hdr_len);
        }
    }

    skb = vnfc_alloc_skb(vfile, align, copy_len, linear_len, nonblock);
    if (unlikely(IS_ERR(skb))) {
        if (PTR_ERR(skb) != -EAGAIN) {
            dev->stats.rx_dropped++;
        }
        return PTR_ERR(skb);
    }

    if (zerocopy) {
        err = zerocopy_sg_from_iter(skb, from);
        skb_shinfo(skb)->destructor_arg = msg_control;
        skb_shinfo(skb)->tx_flags |= SKBTX_DEV_ZEROCOPY;
        skb_shinfo(skb)->tx_flags |= SKBTX_SHARED_FRAG;
    } else {
        err = skb_copy_datagram_from_iter(skb, 0, from, data_len);
        if (!err && msg_control) {
            struct ubuf_info *uarg = msg_control;
            uarg->callback(uarg, false);
        }
    }

    if (unlikely(err)) {
        kfree_skb(skb);
        goto drop;
    }

    err = virtio_net_hdr_to_skb(skb, &gso, vnfc_is_little_endian(vnfc));
    if (unlikely(err)) {
        kfree_skb(skb);
        goto frame_err;
    }

    if (do_vnfc) {
        /* The packet is forwarded to the service */
        err = vnfc_xmit_skb_to_service(skb, dev);
    } else {
        if (gso.flags & VIRTIO_NET_HDR_F_DOWNSTREAM) {
            /* The packet is forwarded to the VM */
            err = vnfc_xmit_skb_to_down(skb, dev);
        } else {
            u32 rxhash;

            /* The packet is forwarded to the vswitch */
            skb->protocol = eth_type_trans(skb, dev);

            err = vnfc_xmit_skb_to_up(vnfc, skb, data_len, &gso, &rxhash);
            if (likely(!err)) {
                dev->stats.rx_packets++;
                dev->stats.rx_bytes += data_len;
                vnfc_flow_update(vnfc, rxhash, vfile);
            }
        }
    }

    if (err == NET_RX_DROP) {
        goto drop;
    } else if (err) {
        goto frame_err;
    }

    return total_len;

frame_err:
    dev->stats.rx_frame_errors++;
    return -EINVAL;

drop:
    dev->stats.rx_dropped++;
    return -EFAULT;
}

#else

static ssize_t vnfc_get_user(struct vnfc_struct *vnfc,
                             struct vnfc_file *vfile, void *msg_control,
                             const struct iovec *iv,
                             size_t total_len,
                             size_t iov_len, bool nonblock)
{
    struct net_device *dev;
    struct sk_buff *skb;
    struct virtio_net_hdr gso;
    size_t data_len;
    size_t copy_len;
    size_t linear_len;
    size_t good_linear_len;
    size_t align;
    off_t data_offset;
    int err;
    bool zerocopy;
    bool do_vnfc;

    dev         = vnfc->dev;
    data_len    = total_len;
    data_offset = 0;
    align       = NET_SKB_PAD + NET_IP_ALIGN;
    zerocopy    = false;

    memset(&gso, 0, sizeof(gso));

    if (vnfc->flags & VNFC_VNET_HDR) {
        if (unlikely(data_len < vnfc->vnet_hdr_sz)) {
            return -EINVAL;
        }
        data_len -= vnfc->vnet_hdr_sz;

        if (memcpy_fromiovecend((void*)&gso, iv, 0, sizeof(gso))) {
            return -EFAULT;
        }
        if (gso.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) {
            u16 csum_start  = vnfc16_to_cpu(vnfc, gso.csum_start);
            u16 csum_offset = vnfc16_to_cpu(vnfc, gso.csum_offset);
            u16 hdr_len     = vnfc16_to_cpu(vnfc, gso.hdr_len);

            if (csum_start + csum_offset + 2 > hdr_len) {
                gso.hdr_len = cpu_to_vnfc16(vnfc, csum_start + csum_offset + 2);
            }
        }
        if (unlikely(vnfc16_to_cpu(vnfc, gso.hdr_len) > data_len)) {
            return -EINVAL;
        }
        data_offset += vnfc->vnet_hdr_sz;
    }

    if (unlikely((data_len < ETH_HLEN) ||
        (gso.hdr_len && vnfc16_to_cpu(vnfc, gso.hdr_len) < ETH_HLEN))) {
        return -EINVAL;
    }

    if (list_empty(&vnfc->services)) {
        /* There is no service in the vnfc */
        do_vnfc = false;
    } else {
        if (vfile->service) {
            /* The packet is forwarded from a service */
            do_vnfc = false;
        } else if (list_empty(&vnfc->services_up)) {
            /* There is no upstream service */
            do_vnfc = false;
        } else {
            do_vnfc = true;
        }
    }

    good_linear_len = SKB_MAX_HEAD(align);

    if (msg_control) {
        /* There are 256 bytes to be copied in skb, so there is
         * enough room for skb expand head in case it is used.
         * The rest of the buffer is mapped from userspace.
         */
        copy_len = gso.hdr_len ? vnfc16_to_cpu(vnfc, gso.hdr_len) :
                                 GOODCOPY_LEN;
        if (copy_len > good_linear_len) {
            copy_len = good_linear_len;
        }
        linear_len = copy_len;

        if (iov_pages(iv, data_offset + copy_len, iov_len) <= MAX_SKB_FRAGS) {
            zerocopy = true;
        }
    }

    if (!zerocopy) {
        copy_len = data_len;
        if (vnfc16_to_cpu(vnfc, gso.hdr_len) > good_linear_len) {
            linear_len = good_linear_len;
        } else {
            linear_len = vnfc16_to_cpu(vnfc, gso.hdr_len);
        }
    }

    skb = vnfc_alloc_skb(vfile, align, copy_len, linear_len, nonblock);
    if (unlikely(IS_ERR(skb))) {
        if (PTR_ERR(skb) != -EAGAIN) {
            dev->stats.rx_dropped++;
        }
        return PTR_ERR(skb);
    }

    if (zerocopy) {
        err = zerocopy_sg_from_iovec(skb, iv, data_offset, iov_len);
        skb_shinfo(skb)->destructor_arg = msg_control;
        skb_shinfo(skb)->tx_flags |= SKBTX_DEV_ZEROCOPY;
        skb_shinfo(skb)->tx_flags |= SKBTX_SHARED_FRAG;
    } else {
        err = skb_copy_datagram_from_iovec(skb, 0, iv, data_offset, data_len);
        if (!err && msg_control) {
            struct ubuf_info *uarg = msg_control;
            uarg->callback(uarg, false);
        }
    }

    if (unlikely(err)) {
        kfree_skb(skb);
        goto drop;
    }

    if (gso.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) {
        if (! skb_partial_csum_set(skb, vnfc16_to_cpu(vnfc, gso.csum_start),
                                   vnfc16_to_cpu(vnfc, gso.csum_offset))) {
            kfree_skb(skb);
            goto frame_err;
        }
    }

    if (do_vnfc) {
        /* The packet is forwarded to the service */
        err = vnfc_xmit_skb_to_service(skb, dev);
    } else {
        if (gso.flags & VIRTIO_NET_HDR_F_DOWNSTREAM) {
            /* The packet is forwarded to the VM */
            err = vnfc_xmit_skb_to_down(skb, dev);
        } else {
            u32 rxhash;

            /* The packet is forwarded to the vswitch */
            skb->protocol = eth_type_trans(skb, dev);

            err = vnfc_xmit_skb_to_up(vnfc, skb, data_len, &gso, &rxhash);
            if (likely(!err)) {
                dev->stats.rx_packets++;
                dev->stats.rx_bytes += data_len;
                vnfc_flow_update(vnfc, rxhash, vfile);
            }
        }
    }

    if (err == NET_RX_DROP) {
        goto drop;
    } else if (err) {
        goto frame_err;
    }

    return total_len;

frame_err:
    dev->stats.rx_frame_errors++;
    return -EINVAL;

drop:
    dev->stats.rx_dropped++;
    return -EFAULT;
}
#endif

/* Put packet to the user space buffer */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
static ssize_t vnfc_put_user(struct vnfc_struct *vnfc, struct sk_buff *skb,
                             struct iov_iter *iter)
{
    ssize_t total_len;
    int vlan_offset = 0;
    int vlan_hlen = 0;
    int vnet_hdr_sz = 0;

    if (skb_vlan_tag_present(skb)) {
        vlan_hlen = VLAN_HLEN;
    }

    if (vnfc->flags & VNFC_VNET_HDR) {
        vnet_hdr_sz = vnfc->vnet_hdr_sz;
    }

    total_len = skb->len + vlan_hlen + vnet_hdr_sz;

    if (vnet_hdr_sz) {
        struct virtio_net_hdr gso;
        int ret;

        memset(&gso, 0, sizeof(gso));

        if (unlikely(iov_iter_count(iter) < vnet_hdr_sz)) {
            return -EINVAL;
        }

        ret = virtio_net_hdr_from_skb(skb, &gso, vnfc_is_little_endian(vnfc));
        if (ret) {
            struct skb_shared_info *shinfo = skb_shinfo(skb);
            pr_err("unexpected GSO type: 0x%x, gso_size %d, hdr_len %d\n",
                   shinfo->gso_type, vnfc16_to_cpu(vnfc, gso.gso_size),
                   vnfc16_to_cpu(vnfc, gso.hdr_len));
            WARN_ON_ONCE(1);
            return -EINVAL;
        }

        if (! list_empty(&vnfc->services)) {
            if (skb->head[0] == VIRTIO_NET_HDR_F_DOWNSTREAM) {
                gso.flags |= VIRTIO_NET_HDR_F_DOWNSTREAM;
            } else if (skb->head[0] == VIRTIO_NET_HDR_F_UPSTREAM) {
                gso.flags |= VIRTIO_NET_HDR_F_UPSTREAM;
            }
        }

        if (unlikely(copy_to_iter(&gso, sizeof(gso), iter) != sizeof(gso))) {
            return -EFAULT;
        }
        iov_iter_advance(iter, vnet_hdr_sz - sizeof(gso));
    }

    if (vlan_hlen) {
        int ret;
        struct {
            __be16 h_vlan_proto;
            __be16 h_vlan_TCI;
        } veth;

        veth.h_vlan_proto = skb->vlan_proto;
        veth.h_vlan_TCI = htons(skb_vlan_tag_get(skb));

        vlan_offset = offsetof(struct vlan_ethhdr, h_vlan_proto);

        ret = skb_copy_datagram_iter(skb, 0, iter, vlan_offset);
        if (ret || !iov_iter_count(iter)) {
            goto done;
        }

        ret = copy_to_iter(&veth, sizeof(veth), iter);
        if (ret != sizeof(veth) || !iov_iter_count(iter)) {
            goto done;
        }
    }

    skb_copy_datagram_iter(skb, vlan_offset, iter, skb->len - vlan_offset);

done:
    vnfc->dev->stats.tx_packets++;
    vnfc->dev->stats.tx_bytes += skb->len + vlan_hlen;

    return total_len;
}

#else /* < KERNEL_VERSION(3, 19, 0) */

static ssize_t vnfc_put_user(struct vnfc_struct *vnfc, struct sk_buff *skb,
                             const struct iovec *iv, ssize_t buf_len)
{
    ssize_t total_len;
    ssize_t copy_len;
    int vlan_hlen;
    off_t from_offset;
    off_t to_offset;

    total_len = 0;
    copy_len  = buf_len;

    if (skb_vlan_tag_present(skb)) {
        vlan_hlen = VLAN_HLEN;
    } else {
        vlan_hlen = 0;
    }

    if (vnfc->flags & VNFC_VNET_HDR) {
        struct virtio_net_hdr gso;
        memset(&gso, 0, sizeof(gso));

        copy_len -= vnfc->vnet_hdr_sz;
        if (unlikely(copy_len < 0)) {
            return -EINVAL;
        }

        if (skb_is_gso(skb)) {
            struct skb_shared_info *shinfo;
            shinfo = skb_shinfo(skb);

            /* This is a hint as to how much should be linear. */
            gso.hdr_len  = cpu_to_vnfc16(vnfc, skb_headlen(skb));
            gso.gso_size = cpu_to_vnfc16(vnfc, shinfo->gso_size);

            if (shinfo->gso_type & SKB_GSO_TCPV4) {
                gso.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
            } else if (shinfo->gso_type & SKB_GSO_TCPV6) {
                gso.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
            } else if (shinfo->gso_type & SKB_GSO_UDP) {
                gso.gso_type = VIRTIO_NET_HDR_GSO_UDP;
            } else {
                WARN_ON_ONCE(1);
                return -EINVAL;
            }
            if (shinfo->gso_type & SKB_GSO_TCP_ECN) {
                gso.gso_type |= VIRTIO_NET_HDR_GSO_ECN;
            }
        } else {
            gso.gso_type = VIRTIO_NET_HDR_GSO_NONE;
        }

        if (skb->ip_summed == CHECKSUM_PARTIAL) {
            gso.flags       = VIRTIO_NET_HDR_F_NEEDS_CSUM;
            gso.csum_start  = cpu_to_vnfc16(vnfc,
                                             skb_checksum_start_offset(skb) +
                                             vlan_hlen);
            gso.csum_offset = cpu_to_vnfc16(vnfc, skb->csum_offset);
        } else if (skb->ip_summed == CHECKSUM_UNNECESSARY) {
            gso.flags = VIRTIO_NET_HDR_F_DATA_VALID;
        }

        if (! list_empty(&vnfc->services)) {
            if (skb->head[0] == VIRTIO_NET_HDR_F_DOWNSTREAM) {
                gso.flags |= VIRTIO_NET_HDR_F_DOWNSTREAM;
            } else if (skb->head[0] == VIRTIO_NET_HDR_F_UPSTREAM) {
                gso.flags |= VIRTIO_NET_HDR_F_UPSTREAM;
            }
        }

        if (unlikely(memcpy_toiovecend(iv, (void*)&gso, 0, sizeof(gso)))) {
            return -EFAULT;
        }
        total_len += vnfc->vnet_hdr_sz;
    }

    from_offset = 0;
    to_offset   = total_len;
    copy_len = min_t(int, skb->len + vlan_hlen, copy_len);
    total_len += skb->len + vlan_hlen;

    if (vlan_hlen) {
        int copy, ret;
        struct {
            __be16 h_vlan_proto;
            __be16 h_vlan_TCI;
        } veth;

        veth.h_vlan_proto = skb->vlan_proto;
        veth.h_vlan_TCI = htons(skb_vlan_tag_get(skb));

        from_offset += offsetof(struct vlan_ethhdr, h_vlan_proto);

        copy = min_t(int, from_offset, copy_len);
        ret = skb_copy_datagram_const_iovec(skb, 0, iv, to_offset, copy);
        copy_len -= copy;
        to_offset += copy;
        if (ret || !copy_len)
            goto done;

        copy = min_t(int, sizeof(veth), copy_len);
        ret = memcpy_toiovecend(iv, (void *)&veth, to_offset, copy);
        copy_len -= copy;
        to_offset += copy;
        if (ret || !copy_len)
            goto done;
    }

    skb_copy_datagram_const_iovec(skb, from_offset, iv, to_offset, copy_len);

done:
    vnfc->dev->stats.tx_packets++;
    vnfc->dev->stats.tx_bytes += copy_len;

    return total_len;
}
#endif

static int vnfc_file_open(struct inode *inode, struct file *file)
{
    struct vnfc_file *vfile;

    /* Allocate vnfc file */
    vfile = (struct vnfc_file*)sk_alloc(&init_net, AF_UNSPEC, GFP_KERNEL,
                                        &vnfc_proto
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
                                         , 0
#endif
                                        );
    if (unlikely(! vfile)) {
        return -ENOMEM;
    }

    /* Initialize the vnfc file */
    rcu_assign_pointer(vfile->vnfc, NULL);
    rcu_assign_pointer(vfile->service, NULL);
    vfile->net     = get_net(current->nsproxy->net_ns);
    vfile->flags   = 0;
    vfile->ifindex = 0;

    rcu_assign_pointer(vfile->socket.wq, &vfile->wq);
    init_waitqueue_head(&vfile->wq.wait);

    vfile->socket.file = file;
    vfile->socket.ops  = &vnfc_socket_ops;

    sock_init_data(&vfile->socket, &vfile->sk);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
    sk_change_net(&vfile->sk, vfile->net);
#endif

    vfile->sk.sk_write_space = vnfc_sock_write_space;
    vfile->sk.sk_sndbuf      = INT_MAX;

    file->private_data = vfile;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
    set_bit(SOCK_EXTERNALLY_ALLOCATED, &vfile->socket.flags);
#endif
    INIT_LIST_HEAD(&vfile->next);

    sock_set_flag(&vfile->sk, SOCK_ZEROCOPY);

    pr_info("[%s] open a vnfc file\n", DRV_NAME);

    return 0;
}


static int vnfc_file_close(struct inode *inode, struct file *file)
{
    struct vnfc_file *vfile;
    struct net *net;

    vfile = file->private_data;
    net   = vfile->net;

    if (vfile->service) {
        service_file_close(vfile);
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 2, 0)
        sock_put(&vfile->sk);
#else
        sk_release_kernel(&vfile->sk);
#endif
    } else {
        struct vnfc_struct *vnfc;
        vnfc = rtnl_dereference(vfile->vnfc);
        if (vnfc && vnfc->dev) {
            pr_info("[%s] close the vnfc file: %s\n", DRV_NAME, vnfc->dev->name);
        }
        vnfc_detach(vfile, true);
    }
    put_net(net);

    return 0;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)

static struct sk_buff *vnfc_ring_recv(struct vnfc_file *vfile, bool nonblock,
                                      int *err)
{
    DECLARE_WAITQUEUE(wait, current);
    struct sk_buff *skb;
    int error = 0;

    skb = skb_array_consume(&vfile->tx_array);
    if (skb) {
        goto out;
    }
    if (nonblock) {
        error = -EAGAIN;
        goto out;
    }

    add_wait_queue(&vfile->wq.wait, &wait);
    current->state = TASK_INTERRUPTIBLE;

    while (true) {
        skb = skb_array_consume(&vfile->tx_array);
        if (skb) {
            break;
        }
        if (signal_pending(current)) {
            error = -ERESTARTSYS;
            break;
        }
        if (vfile->socket.sk->sk_shutdown & RCV_SHUTDOWN) {
            error = -EFAULT;
            break;
        }

        schedule();
    }

    current->state = TASK_RUNNING;
    remove_wait_queue(&vfile->wq.wait, &wait);

out:
    *err = error;
    return skb;
}


static ssize_t vnfc_do_read(struct vnfc_struct *vnfc, struct vnfc_file *vfile,
                            struct iov_iter *to, bool nonblock)
{
    struct sk_buff *skb;
    ssize_t ret;
    int err;

    if (! iov_iter_count(to)) {
        return 0;
    }

    /* Read frames from ring */
    skb = vnfc_ring_recv(vfile, nonblock, &err);
    if (! skb) {
        return err;
    }

    ret = vnfc_put_user(vnfc, skb, to);
    if (unlikely(ret < 0)) {
        kfree_skb(skb);
    } else {
        consume_skb(skb);
    }

    return ret;
}

#else

static ssize_t vnfc_do_read(struct vnfc_struct *vnfc, struct vnfc_file *vfile,
                            struct kiocb *iocb, const struct iovec *iv,
                            ssize_t buf_len, bool nonblock)
{
    DECLARE_WAITQUEUE(wait, current);
    ssize_t ret;

    if (unlikely(! nonblock)) {
        add_wait_queue(&vfile->wq.wait, &wait);
    }

    ret = 0;
    while (buf_len > 0) {
        struct sk_buff *skb;

        current->state = TASK_INTERRUPTIBLE;

        /* Read a frame from the queue */
        skb = skb_dequeue(&vfile->socket.sk->sk_receive_queue);
        if (!skb) {
            if (nonblock) {
                ret = -EAGAIN;
                break;
            }
            if (signal_pending(current)) {
                ret = -ERESTARTSYS;
                break;
            }
            if (vnfc->dev->reg_state != NETREG_REGISTERED) {
                ret = -EIO;
                break;
            }

            /* Nothing to read, let's sleep */
            schedule();
            continue;
        }

        ret = vnfc_put_user(vnfc, skb, iv, buf_len);
        if (unlikely(ret < 0)) {
            kfree_skb(skb);
        } else {
            consume_skb(skb);
        }
        break;
    }

    current->state = TASK_RUNNING;
    if (unlikely(!nonblock)) {
        remove_wait_queue(&vfile->wq.wait, &wait);
    }
    WARN_ON(ret > buf_len);
    return ret;
}
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
static ssize_t vnfc_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
    struct vnfc_struct *vnfc;
    struct vnfc_file   *vfile;
    struct file *file;
    ssize_t buf_len;
    ssize_t ret;

    file  = iocb->ki_filp;
    vfile = file->private_data;
    vnfc = vnfc_get(vfile);

    if (unlikely(! vnfc)) {
        return -EBADFD;
    }

    buf_len = iov_iter_count(to);

    pr_devel("[%s] (%s) reading: %ld bytes\n",
             DRV_NAME, vnfc->dev->name, buf_len);

    ret = vnfc_do_read(vnfc, vfile, to,
                        file->f_flags & O_NONBLOCK);
    ret = min_t(ssize_t, ret, buf_len);
    if (ret > 0) {
        iocb->ki_pos = ret;
    }
    vnfc_put(vnfc);
    return ret;
}

#else

static ssize_t vnfc_file_aio_read(struct kiocb *iocb, const struct iovec *iv,
                                  unsigned long iov_len, loff_t pos)
{
    struct vnfc_struct *vnfc;
    struct vnfc_file   *vfile;
    struct file *file;
    ssize_t buf_len;
    ssize_t ret;

    file  = iocb->ki_filp;
    vfile = file->private_data;
    vnfc = vnfc_get(vfile);

    if (unlikely(! vnfc)) {
        return -EBADFD;
    }

    buf_len = iov_length(iv, iov_len);
    if (buf_len < 0) {
        ret = -EINVAL;
        goto out;
    }

    pr_devel("[%s] (%s) reading: %ld bytes\n",
             DRV_NAME, vnfc->dev->name, buf_len);

    ret = vnfc_do_read(vnfc, vfile, iocb, iv, buf_len,
                        file->f_flags & O_NONBLOCK);
    ret = min_t(ssize_t, ret, buf_len);
out:
    vnfc_put(vnfc);
    return ret;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
static ssize_t vnfc_get_service(struct vnfc_struct *vnfc,
                                struct vnfc_file *vfile,
                                const struct msghdr *msg,
                                struct iov_iter *from,
                                bool nonblock)
{
    size_t iov_len;
    ssize_t ret;
    int i;

    iov_len = from->nr_segs;

    if (unlikely(iov_len & 0x1)) {
        return -EINVAL;
    }

    ret = 0;
    for (i = 0; i < iov_len; i += 2) {
        size_t nr_bytes = iov_length(from->iov, 2);
        ssize_t n;

        pr_debug("[%s] (%s) writing: %ld bytes\n",
                 DRV_NAME, vnfc->dev->name, nr_bytes);

        n = vnfc_get_user(vnfc, vfile, (msg ? msg->msg_control : NULL),
                           from, nonblock);
        if (n <= 0) {
            pr_err("[%s] (%s) Can't send %d-th packet\n",
                   DRV_NAME, vnfc->dev->name, i + 1);
            return -EFAULT;
        }
        ret += n;
    }

    return ret;
}
#else
static ssize_t vnfc_get_service(struct vnfc_struct *vnfc,
                                struct vnfc_file *vfile,
                                const struct msghdr *msg,
                                const struct iovec *iv,
                                size_t iov_len, bool nonblock)
{
    ssize_t ret;
    int i;

    if (unlikely(iov_len & 0x1)) {
        return -EINVAL;
    }

    ret = 0;
    for (i = 0; i < iov_len; i += 2) {
        size_t nr_bytes = iov_length(&iv[i], 2);
        ssize_t n;

        pr_debug("[%s] (%s) writing: %ld bytes\n",
                 DRV_NAME, vnfc->dev->name, nr_bytes);

        n = vnfc_get_user(vnfc, vfile, (msg ? msg->msg_control : NULL),
                           &iv[i], nr_bytes, 2, nonblock);
        if (n <= 0) {
            pr_err("[%s] (%s) Can't send %d-th packet\n",
                   DRV_NAME, vnfc->dev->name, i + 1);
            return -EFAULT;
        }
        ret += n;
    }

    return ret;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
static ssize_t vnfc_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
    struct vnfc_struct *vnfc;
    struct vnfc_file   *vfile;
    struct file *file;
    ssize_t ret;

    file  = iocb->ki_filp;
    vfile = file->private_data;
    vnfc = vnfc_get(vfile);

    if (unlikely(! vnfc)) {
        return -EBADFD;
    }

    if (vfile->service) {
        ret = vnfc_get_service(vnfc, vfile, NULL, from,
                               (file->f_flags & O_NONBLOCK));
    } else {
        ret = vnfc_get_user(vnfc, vfile, NULL, from, (file->f_flags & O_NONBLOCK));
    }

    vnfc_put(vnfc);
    return ret;
}
#else

static ssize_t vnfc_file_aio_write(struct kiocb *iocb, const struct iovec *iv,
                                   unsigned long iov_len, loff_t pos)
{
    struct vnfc_struct *vnfc;
    struct vnfc_file   *vfile;
    struct file *file;
    ssize_t ret;

    file  = iocb->ki_filp;
    vfile = file->private_data;
    vnfc = vnfc_get(vfile);

    if (unlikely(! vnfc)) {
        return -EBADFD;
    }

    if (vfile->service) {
        ret = vnfc_get_service(vnfc, vfile, NULL, iv, iov_len,
                               (file->f_flags & O_NONBLOCK));
    } else {
        ret = vnfc_get_user(vnfc, vfile, NULL, iv, iov_length(iv, iov_len),
                            iov_len, (file->f_flags & O_NONBLOCK));
    }

    vnfc_put(vnfc);
    return ret;
}
#endif


static unsigned int vnfc_file_poll(struct file *file, poll_table *wait)
{
    struct vnfc_struct *vnfc;
    struct vnfc_file   *vfile;
    struct sock *sk;
    unsigned int mask;

    vfile = file->private_data;
    vnfc = vnfc_get(vfile);

    if (unlikely(!vnfc)) {
        return POLLERR;
    }

    pr_devel("[%s] (%s) polling...\n", DRV_NAME, vnfc->dev->name);

    poll_wait(file, &vfile->wq.wait, wait);

    sk   = vfile->socket.sk;
    mask = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
    if (! skb_array_empty(&vfile->tx_array)) {
#else
    if (! skb_queue_empty(&sk->sk_receive_queue)) {
#endif
        /* There are frames in the queue */
        mask |= POLLIN | POLLRDNORM;
    }
    if (sock_writeable(sk) ||
        (!test_and_set_bit(SOCKWQ_ASYNC_NOSPACE, &sk->sk_socket->flags) &&
         sock_writeable(sk))) {
        /* There is a space to write in the queue */
        mask |= POLLOUT | POLLWRNORM;
    }

    if (vnfc->dev->reg_state != NETREG_REGISTERED) {
        mask = POLLERR;
    }

    vnfc_put(vnfc);
    return mask;
}


static int vnfc_file_fasync(int fd, struct file *file, int on)
{
    struct vnfc_file *vfile;
    int err;

    vfile = file->private_data;

    err = fasync_helper(fd, file, on, &vfile->fasync);
    if (err < 0) {
        goto out;
    }

    if (on) {
        __f_setown(file, task_pid(current), PIDTYPE_PID, 0);
        vfile->flags |= VNFC_FASYNC;
    } else {
        vfile->flags &= ~VNFC_FASYNC;
    }
    err = 0;

out:
    return err;
}


static int vnfc_set_offload(struct vnfc_struct *vnfc, unsigned long arg)
{
    netdev_features_t features = 0;

    if (arg & VNFC_F_CSUM) {
        features |= NETIF_F_HW_CSUM;
        arg &= ~VNFC_F_CSUM;

        if (arg & (VNFC_F_TSO4 | VNFC_F_TSO6)) {
            if (arg & VNFC_F_TSO_ECN) {
                features |= NETIF_F_TSO_ECN;
                arg &= ~VNFC_F_TSO_ECN;
            }
            if (arg & VNFC_F_TSO4) {
                features |= NETIF_F_TSO;
            }
            if (arg & VNFC_F_TSO6) {
                features |= NETIF_F_TSO6;
            }
            arg &= ~(VNFC_F_TSO4 | VNFC_F_TSO6);
        }
        if (arg & VNFC_F_UFO) {
            features |= NETIF_F_UFO;
            arg &= ~VNFC_F_UFO;
        }
    }

    if (arg) {
        return -EINVAL;
    }

    vnfc->set_features = features;
    netdev_update_features(vnfc->dev);

    return 0;
}


static void vnfc_set_sndbuf(struct vnfc_struct *vnfc)
{
    struct vnfc_file *vfile;
    int i;

    for (i = 0; i < vnfc->nr_queues; i++) {
        vfile = rtnl_dereference(vnfc->vfile_vms[i]);
        vfile->socket.sk->sk_sndbuf = vnfc->sndbuf;
    }
}


static int vnfc_set_queue(struct file *file, struct ifreq *ifr)
{
    struct vnfc_file   *vfile;
    struct vnfc_struct *vnfc;
    int ret;

    vfile = file->private_data;
    ret = 0;

    rtnl_lock();

    if (ifr->ifr_flags & IFF_ATTACH_QUEUE) {
        vnfc = vfile->detached;
        if (!vnfc) {
            ret = -EINVAL;
            goto unlock;
        }
        ret = vnfc_attach(vnfc, vfile);
    } else if (ifr->ifr_flags & IFF_DETACH_QUEUE) {
        vnfc = rtnl_dereference(vfile->vnfc);
        if (!vnfc || !(vnfc->flags & VNFC_MULTI_QUEUE) || vfile->detached)
            ret = -EINVAL;
        else
            __vnfc_detach(vfile, false);
    } else {
        ret = -EINVAL;
    }
unlock:
    rtnl_unlock();
    return ret;
}


static int vnfc_ioctl_service(struct vnfc_file *vfile, unsigned int cmd,
                              void __user *argp)
{
    struct vnfc_req req;
    int err;

    memset(&req, 0, sizeof(req));

    err = 0;

    if (cmd == VNFC_SET_SERVICE) {
        if (copy_from_user(&req, argp, sizeof(req))) {
            return -EFAULT;
        }
        if (req.flags & SERVICE_DETACH) {
            err = service_file_detach(vfile);
        } else {
            err = service_file_attach(vfile, &req);
        }
    } else if (cmd == VNFC_GET_SERVICE) {
        /* Set req */

        if (copy_to_user(argp, &req, sizeof(req))) {
            return -EFAULT;
        }
    } else {
        err = -EINVAL;
    }

    return err;
}


static long vnfc_ioctl_others(struct vnfc_struct *vnfc,
                              struct vnfc_file *vfile, unsigned int cmd,
                              unsigned long arg, struct ifreq *ifr)
{
    kuid_t owner;
    kgid_t group;
    int data;
    int err;
    void __user *argp;

    argp = (void __user*)arg;
    err  = 0;

    switch (cmd) {
    case VNFC_GET_IFF:
        /* Get the device settings */
        vnfc_get_iff(current->nsproxy->net_ns, vnfc, ifr);
        if (vfile->detached) {
            ifr->ifr_flags |= IFF_DETACH_QUEUE;
        }
        if (copy_to_user(argp, ifr, sizeof(*ifr))) {
            err = -EFAULT;
        }
        break;
    case VNFC_SET_PERSIST:
        if (arg && !(vnfc->flags & VNFC_PERSIST)) {
            vnfc->flags |= VNFC_PERSIST;
            __module_get(THIS_MODULE);
        }
        if (!arg && (vnfc->flags & VNFC_PERSIST)) {
            vnfc->flags &= ~VNFC_PERSIST;
            module_put(THIS_MODULE);
        }
        break;
    case VNFC_SET_OWNER:
        /* Set owner of the device */
        owner = make_kuid(current_user_ns(), arg);
        if (!uid_valid(owner)) {
            err = -EINVAL;
            break;
        }
        vnfc->owner = owner;
        break;
    case VNFC_SET_GROUP:
        /* Set group of the device */
        group = make_kgid(current_user_ns(), arg);
        if (!gid_valid(group)) {
            err = -EINVAL;
            break;
        }
        vnfc->group = group;
        break;
	case VNFC_SET_LINK:
        /* Only allow setting the type when the itnerface is down */
        if (vnfc->dev->flags & IFF_UP) {
            err = -EBUSY;
        } else {
            vnfc->dev->type = (int)arg;
            err = 0;
        }
        break;
    case VNFC_SET_OFFLOAD:
        err = vnfc_set_offload(vnfc, arg);
        break;
    case VNFC_SET_SNDBUF:
        if (copy_from_user(&data, argp, sizeof(data))) {
            err = -EFAULT;
            break;
        }
        vnfc->sndbuf = data;
        vnfc_set_sndbuf(vnfc);
        break;
    case VNFC_GET_SNDBUF:
        data = vfile->socket.sk->sk_sndbuf;
        if (copy_to_user(argp, &data, sizeof(data))) {
            err = -EFAULT;
        }
        break;
    case VNFC_SET_VNET_HDR_SZ:
        if (copy_from_user(&data, argp, sizeof(data))) {
            err = -EFAULT;
            break;
        }
        if (data < (int)sizeof(struct virtio_net_hdr)) {
            err = -EINVAL;
            break;
        }
        vnfc->vnet_hdr_sz = data;
        break;
    case VNFC_GET_VNET_HDR_SZ:
        data = vnfc->vnet_hdr_sz;
        if (copy_to_user(argp, &data, sizeof(data))) {
            err = -EFAULT;
        }
        break;
    case SIOCSIFHWADDR:
        /* Set hw address */
        err = dev_set_mac_address(vnfc->dev, &ifr->ifr_hwaddr);
        break;
    case SIOCGIFHWADDR:
        memcpy(ifr->ifr_hwaddr.sa_data, vnfc->dev->dev_addr, ETH_ALEN);
        ifr->ifr_hwaddr.sa_family = vnfc->dev->type;
        if (copy_to_user(argp, ifr, sizeof(*ifr))) {
            err = -EFAULT;
        }
        break;
    case VNFC_GET_VNET_LE:
        data = !!(vnfc->flags & VNFC_VNET_LE);
        if (put_user(data, (int __user*)argp)) {
            err = -EFAULT;
        }
        break;
    case VNFC_SET_VNET_LE:
        if (get_user(data, (int __user*)argp)) {
            err = -EFAULT;
            break;
        }
        if (data) {
            vnfc->flags |= VNFC_VNET_LE;
        } else {
            vnfc->flags &= ~VNFC_VNET_LE;
        }
        break;
    case VNFC_GET_VNET_BE:
        err = vnfc_get_vnet_be(vnfc, argp);
        break;
    case VNFC_SET_VNET_BE:
        err = vnfc_set_vnet_be(vnfc, argp);
        break;
    default:
        err = -EINVAL;
        break;
    }

    return err;
}


static long __vnfc_file_ioctl(struct vnfc_file *vfile, unsigned int cmd,
                              unsigned long arg, struct ifreq *ifr)
{
    struct vnfc_struct *vnfc;
    void __user *argp;
    int err;

    argp = (void __user*)arg;

    rtnl_lock();

    vnfc = vnfc_get(vfile);

    /* ioctl for services */

    if ((cmd == VNFC_SET_SERVICE) || (cmd == VNFC_GET_SERVICE)) {
        err = vnfc_ioctl_service(vfile, cmd, argp);
        goto unlock;
    }

    /* ioctl for the device */

    if ((cmd == VNFC_SET_IFF) && ! vnfc) {
        ifr->ifr_name[IFNAMSIZ - 1] = '\0';

        /* Create a vnfc device and attach the file */
        err = vnfc_set_iff(vfile->net, vfile, ifr);
        if (err) {
            goto unlock;
        }
        if (copy_to_user(argp, ifr, sizeof(*ifr))) {
            err = -EFAULT;
        }
        goto unlock;
    }
    if (cmd == VNFC_SET_IF_INDEX) {
        unsigned int ifindex;

        if (vnfc) {
            err = -EPERM;
            goto unlock;
        }
        if (copy_from_user(&ifindex, argp, sizeof(ifindex))) {
            err = -EFAULT;
            goto unlock;
        }
        err = 0;
        vfile->ifindex = ifindex;
        goto unlock;
    }
    if (!vnfc) {
        err = -EBADFD;
        goto unlock;
    }
    err = vnfc_ioctl_others(vnfc, vfile, cmd, arg, ifr);

unlock:
    rtnl_unlock();
    if (vnfc) {
        vnfc_put(vnfc);
    }
    return err;
}


static long vnfc_file_ioctl(struct file *file, unsigned int cmd,
							unsigned long arg)
{
    struct ifreq ifr;
    void __user *argp;

    argp = (void __user*)arg;

    pr_info("[%s] ioctl: cmd = %d\n", DRV_NAME, _IOC_NR(cmd));

    if ((cmd == VNFC_SET_IFF) || (cmd == VNFC_SET_QUEUE) ||
        (_IOC_TYPE(cmd) == 0x89)) {
        if (copy_from_user(&ifr, argp, sizeof(ifr))) {
            return -EFAULT;
        }
    } else {
        memset(&ifr, 0, sizeof(ifr));
    }

    if (cmd == VNFC_GET_FEATURES) {
        return put_user(IFF_VNFC | IFF_ONE_QUEUE | IFF_VNET_HDR |
                        IFF_MULTI_QUEUE, (unsigned int __user*)argp);
    } else if (cmd == VNFC_SET_QUEUE) {
        return vnfc_set_queue(file, &ifr);
    }

    return __vnfc_file_ioctl(file->private_data, cmd, arg, &ifr);
}


const struct file_operations vnfc_fops = {
    .owner          = THIS_MODULE,
    .open           = vnfc_file_open,
    .release        = vnfc_file_close,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
    .read_iter      = vnfc_file_read_iter,
    .write_iter     = vnfc_file_write_iter,
#else
    .read           = do_sync_read,
    .aio_read       = vnfc_file_aio_read,
    .write          = do_sync_write,
    .aio_write      = vnfc_file_aio_write,
#endif
    .poll           = vnfc_file_poll,
    .fasync         = vnfc_file_fasync,
    .llseek         = no_llseek,
    .unlocked_ioctl = vnfc_file_ioctl,
};


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
static int vnfc_sendmsg(struct socket *sock,
                         struct msghdr *m, size_t total_len)
{
    struct vnfc_struct *vnfc;
    struct vnfc_file   *vfile;
    int ret;

    vfile = container_of(sock, struct vnfc_file, socket);
    vnfc = vnfc_get(vfile);

    if (unlikely(!vnfc)) {
        return -EBADFD;
    }

    if (vfile->service) {
        ret = vnfc_get_service(vnfc, vfile, m, &m->msg_iter,
                                (m->msg_flags & MSG_DONTWAIT));
    } else {
        ret = vnfc_get_user(vnfc, vfile, m->msg_control, &m->msg_iter,
                             (m->msg_flags & MSG_DONTWAIT));
    }

    vnfc_put(vnfc);
    return ret;
}
#else
static int vnfc_sendmsg(struct kiocb *iocb,
                         struct socket *sock,
                         struct msghdr *m, size_t total_len)
{
    struct vnfc_struct *vnfc;
    struct vnfc_file   *vfile;
    int ret;

    vfile = container_of(sock, struct vnfc_file, socket);
    vnfc = vnfc_get(vfile);

    if (unlikely(!vnfc)) {
        return -EBADFD;
    }

    if (vfile->service) {
        ret = vnfc_get_service(vnfc, vfile, m, m->msg_iov, m->msg_iovlen,
                                (m->msg_flags & MSG_DONTWAIT));
    } else {
        ret = vnfc_get_user(vnfc, vfile, m->msg_control, m->msg_iov,
                             total_len, m->msg_iovlen,
                             (m->msg_flags & MSG_DONTWAIT));
    }

    vnfc_put(vnfc);
    return ret;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
static int vnfc_recvmsg(struct socket *sock, struct msghdr *m,
                        size_t total_len, int flags)
{
    struct vnfc_struct *vnfc;
    struct vnfc_file   *vfile;
    int ret;

    vfile = container_of(sock, struct vnfc_file, socket);
    vnfc = vnfc_get(vfile);

    if (unlikely(!vnfc)) {
        return -EBADFD;
    }

    if (flags & ~(MSG_DONTWAIT | MSG_TRUNC | MSG_ERRQUEUE)) {
        ret = -EINVAL;
        goto out;
    }

    pr_devel("[%s] (%s) receiving: %ld bytes",
             DRV_NAME, vnfc->dev->name, total_len);

    ret = vnfc_do_read(vnfc, vfile, &m->msg_iter, (flags & MSG_DONTWAIT));
    if (ret > total_len) {
        m->msg_flags |= MSG_TRUNC;
        ret = flags & MSG_TRUNC ? ret : total_len;
    }

out:
    vnfc_put(vnfc);
    return ret;
}
#else

static int vnfc_recvmsg(struct kiocb *iocb, struct socket *sock,
                        struct msghdr *m, size_t total_len, int flags)
{
    struct vnfc_struct *vnfc;
    struct vnfc_file   *vfile;
    int ret;

    vfile = container_of(sock, struct vnfc_file, socket);
    vnfc = vnfc_get(vfile);

    if (unlikely(!vnfc)) {
        return -EBADFD;
    }

    if (flags & ~(MSG_DONTWAIT | MSG_TRUNC)) {
        ret = -EINVAL;
        goto out;
    }

    pr_devel("[%s] (%s) receiving: %ld bytes",
             DRV_NAME, vnfc->dev->name, total_len);

    ret = vnfc_do_read(vnfc, vfile, iocb, m->msg_iov, total_len,
                        (flags & MSG_DONTWAIT));
    if (ret > total_len) {
        m->msg_flags |= MSG_TRUNC;
        ret = flags & MSG_TRUNC ? ret : total_len;
    }

out:
    vnfc_put(vnfc);
    return ret;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
static int vnfc_peek_len(struct socket *sock)
{
    struct vnfc_file *vfile;
    struct vnfc_struct *vnfc;
    int ret;

    vfile = container_of(sock, struct vnfc_file, socket);
    vnfc = vnfc_get(vfile);
    if (!vnfc) {
        return 0;
    }

    ret = skb_array_peek_len(&vfile->tx_array);
    vnfc_put(vnfc);

    return ret;
}

#else

static int vnfc_release(struct socket *sock)
{
    if (sock->sk) {
        sock_put(sock->sk);
    }

    return 0;
}
#endif
