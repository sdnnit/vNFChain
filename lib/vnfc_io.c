/*
 * vnfc_io.c : Datapath handling of vNFCLib
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

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <linux/limits.h>
#include <linux/virtio_net.h>

#ifdef USE_DPDK
#include <rte_mbuf.h>
#endif

#include "if_vnfc.h"
#include "vnfc.h"
#include "vnfc_utils.h"
#include "vnfc_io.h"
#include "vnfc_pktpool.h"
#include "vnfc_packet.h"
#include "utils/print.h"
#include "utils/socket.h"
#include "utils/poll.h"
#include "vhu/server.h"

#ifdef USE_DPDK
#include "dpdk/dpdk.h"
#include "dpdk/ring_client.h"
#endif

VNFC_DEFINE_PRINT_MODULE("vnfc");


extern void vnfc_vhu_restart(struct vnfc *vnfc);

#ifdef USE_DPDK
static const uint32_t MAX_POLL_COUNT = 16;
static uint32_t g_poll_counter;
#endif

/*******************************************************************************
* Tx processing
*******************************************************************************/

static void default_vnet_hdr(struct virtio_net_hdr *vnet, bool upstream)
{
    /* The packet is passed from vhu or created by the service */
    vnet->flags       = VIRTIO_NET_HDR_F_DATA_VALID;
    vnet->gso_type    = VIRTIO_NET_HDR_GSO_NONE;
    vnet->hdr_len     = 0;
    vnet->gso_size    = 0;
    vnet->csum_start  = 0;
    vnet->csum_offset = 0;

    if (upstream) {
        vnet->flags |= VIRTIO_NET_HDR_F_UPSTREAM;
    } else {
        vnet->flags |= VIRTIO_NET_HDR_F_DOWNSTREAM;
    }
}


static bool vnfc_send_packet_to_device(struct vnfc *vnfc,
                                       struct vnfc_packet_vec *vector)
{
    struct iovec iov[MAX_BURST_PACKETS * 2];
    struct virtio_net_hdr _vnet = { 0 };
    ssize_t n;
    bool is_vhu;
    int i;

    is_vhu = is_vhu_packet(vector->packets[0]);
    if (is_vhu) {
        assert(vector->upstream);
    }

    for (i = 0; i < vector->size; i++) {
        struct vnfc_packet *packet;
        struct virtio_net_hdr *vnet;

        packet = vector->packets[i];

        if (is_vhu) {
            vnet = &_vnet;
        } else {
            vnet = &packet->meta->gso;
        }

        if (vnet->flags == 0) {
            default_vnet_hdr(vnet, vector->upstream);
        }

        iov[i * 2].iov_base     = (uint8_t*)vnet;
        iov[i * 2].iov_len      = sizeof(*vnet);
        iov[i * 2 + 1].iov_base = get_vnfc_packet_data(packet);
        iov[i * 2 + 1].iov_len  = get_vnfc_packet_len(packet);
    }

    n = writev(vnfc->fd_vnfc_out, iov, vector->size * 2);
    if (n == 0) {
        VNFC_ERR_PRINT("Output fd has been closed\n");
        poll_delete_fd(vnfc->poll, vnfc->fd_vnfc_out);
    } else if (n < 0) {
        VNFC_PERROR("writev (fd_vnfc_out)");
    }

    free_vnfc_packet_vec(vector);

    if (is_vhu) {
        vhu_update_used(vnfc->vhu);
    }

    return (n > 0);
}


static bool vnfc_service_connect(struct vnfc *vnfc, pid_t pid, bool upstream)
{
    struct sock_client *client;
    char path[PATH_MAX];

    VNFC_DBG_PRINT("Chaining services: %d => %d\n", getpid(), pid);

    vnfc_make_sock_path(path, pid, upstream);
    client = sock_client_init(path, false);
    if (! client) {
        return false;
    }

    if (upstream) {
        vnfc->clt_up               = client;
        vnfc->need_to_connect_up   = false;
        vnfc->pid_to_up            = -1;
    } else {
        vnfc->clt_down             = client;
        vnfc->need_to_connect_down = false;
        vnfc->pid_to_down          = -1;
    }

    return true;
}


static bool vnfc_send_packet_to_service_copy(int sock, struct vnfc *vnfc,
                                             struct iovec *iov,
                                             struct vnfc_packet_vec *vector)
{
    uint32_t indexes[MAX_BURST_PACKETS];
    struct vnfc_packet tmp_packet;
    size_t nr_send;
    ssize_t n;
    int i;

    nr_send = 0;
    for (i = 0; i < vector->size; i++) {
        struct vnfc_packet *packet = vector->packets[i];
        uint8_t *data     = get_vnfc_packet_data(packet);
        size_t   data_len = get_vnfc_packet_len(packet);

        if (! alloc_packet_wait(vnfc, &tmp_packet, data_len, vector->upstream,
                                2)) {
            VNFC_ERR_PRINT("Can't allocate a packet for the next service\n");
            return false; /* TODO: Free packets */
        } else {
            vnfc_memcpy(tmp_packet.data, data, data_len);
            indexes[i] = tmp_packet.index;
            iov[i].iov_base = (uint8_t*)&indexes[i];
            iov[i].iov_len  = sizeof(indexes[i]);
            nr_send++;
        }
    }

    if (is_vhu_server(vnfc)) {
        vhu_update_used(vnfc->vhu);
    }

    free_vnfc_packet_vec(vector);

    n = writev(sock, iov, nr_send);
    if (n < 0) {
        VNFC_PERROR("writev");
    }

    return (n >= 0);
}


static bool vnfc_send_packet_to_service(struct vnfc *vnfc,
                                        struct vnfc_packet_vec *vector)
{
    struct iovec iov[MAX_BURST_PACKETS];
    ssize_t n;
    int sock;
    int i;

    if ((vector->upstream && vnfc->need_to_connect_up) ||
        (!vector->upstream && vnfc->need_to_connect_down)) {
        pid_t pid = (vector->upstream) ? vnfc->pid_to_up : vnfc->pid_to_down;

        if (! vnfc_service_connect(vnfc, pid, vector->upstream)) {
            VNFC_ERR_PRINT("Can't connect to the next service (%d)\n", pid);
            return false;
        }
    }

    if (vector->upstream) {
        sock = vnfc->clt_up->sock;
    } else {
        sock = vnfc->clt_down->sock;
    }

#ifdef USE_DPDK
    if (is_dpdk_packet(vector->packets[0])) {
        /* Workaround for zerocopy rx */
        return vnfc_send_packet_to_service_copy(sock, vnfc, iov, vector);
    }
#endif

    if (is_vhu_packet(vector->packets[0])) {
        /* Workaround for zerocopy tx */
        return vnfc_send_packet_to_service_copy(sock, vnfc, iov, vector);
    }

    for (i = 0; i < vector->size; i++) {
        iov[i].iov_base = (uint32_t*)&vector->packets[i]->index;
        iov[i].iov_len  = sizeof(vector->packets[i]->index);
    }

    n = writev(sock, iov, vector->size);
    if (n < 0) {
        VNFC_PERROR("writev");
        return false;
    }

    vector->size = 0;

    return true;
}


static bool vnfc_send_packet_to_vhu(struct vnfc *vnfc,
                                    struct vnfc_packet_vec *vector)
{
    ssize_t n;
    int i;

    if (is_vhu_ready(vnfc->vhu)) {
        for (i = 0; i < vector->size; i++) {
            struct vnfc_packet *packet = vector->packets[i];
            n = vhu_send_packet(vnfc->vhu, get_vnfc_packet_data(packet),
                                get_vnfc_packet_len(packet));
            if (n <= 0) {
                VNFC_ERR_PRINT("Can't send %d-th packet\n", i + 1);
            }
        }
        vhu_update_avail(vnfc->vhu);
    } else {
        VNFC_DBG_PRINT("The VHU has not been ready: %lu packets are dropped\n", vector->size);
    }

    free_vnfc_packet_vec(vector);

    return true;
}


#ifdef USE_DPDK
static bool vnfc_mod_vec_to_mbufs(struct vnfc_packet_vec *vector)
{
    struct dpdk *dpdk = get_dpdk();
    struct rte_mbuf *mbufs[MAX_BURST_PACKETS];
    size_t nr_packets;
    int i;

    nr_packets = vector->size;

    if (rte_pktmbuf_alloc_bulk(dpdk->mp, mbufs, nr_packets) != 0) {
        VNFC_ERR_PRINT("Can't allocate the bulk rte_mbuf\n");
        return false;
    }

    for (i = 0; i < nr_packets; i++) {
        struct rte_mbuf *m = mbufs[i];
        struct vnfc_packet *p = vector->packets[i];
        assert(!is_dpdk_packet(p));
        if (! rte_pktmbuf_append(m, p->data_len)) {
            goto free_mbufs;
        }
        vnfc_memcpy(rte_pktmbuf_mtod(m, void*), p->data, p->data_len);
    }

    free_vnfc_packet_vec(vector);

    for (i = 0; i < nr_packets; i++) {
        vector->packets[i] = (struct vnfc_packet*)mbufs[i];
    }
    vector->size = nr_packets;

    return true;

free_mbufs:
    for (i = 0; i < nr_packets; i++) {
        rte_pktmbuf_free(mbufs[i]);
    }
    return false;
}


static bool vnfc_send_packet_to_ring(struct vnfc *vnfc, struct vnfc_packet_vec *vector)
{
    if (! is_dpdk_packet(vector->packets[0])) {
        if (! vnfc_mod_vec_to_mbufs(vector)) {
            return false;
        }
        assert(is_dpdk_packet(vector->packets[0]));
    }

    ring_client_tx_burst(vnfc->ring, vector);
    assert(vector->size == 0);

    if (is_vhu_server(vnfc)) {
        vhu_update_used(vnfc->vhu);
    }

    return true;
}
#endif


bool vnfc_send_packet_burst(struct vnfc *vnfc, struct vnfc_packet_vec *vector)
{
    if (! vnfc) {
        VNFC_ERR_PRINT("Invalid vnfc: null\n");
        return false;
    } else if (! vector) {
        VNFC_ERR_PRINT("Invalid vector: null\n");
        return false;
    } else if (! vector->size || MAX_BURST_PACKETS < vector->size) {
        VNFC_ERR_PRINT("Invalid the number of packets: %ld\n", vector->size);
        return false;
    }

#ifdef USE_DPDK
    if (is_ring_client(vnfc) && vector->upstream) {
        return vnfc_send_packet_to_ring(vnfc, vector);
    }
#endif

    if (is_vhu_server(vnfc) && !vector->upstream) {
        return vnfc_send_packet_to_vhu(vnfc, vector);
    }

    if (is_singular(vnfc) ||
        (vector->upstream && is_last_up(vnfc)) ||
        (!vector->upstream && is_last_down(vnfc))) {
        return vnfc_send_packet_to_device(vnfc, vector);
    }

    return vnfc_send_packet_to_service(vnfc, vector);
}


/*******************************************************************************
* Rx processing
*******************************************************************************/

static bool vnfc_receive_packet_from_device_impl(struct vnfc *vnfc,
                                                 struct vnfc_packet *packet)
{
    struct iovec iov[2];
    struct virtio_net_hdr *vnet;
    ssize_t n;

    vnet = &packet->meta->gso;
    memset(vnet, 0, sizeof(*vnet));

    iov[0].iov_base = (uint8_t*)vnet;
    iov[0].iov_len  = sizeof(*vnet);
    iov[1].iov_base = packet->data;
    iov[1].iov_len  = packet->data_len;

    n = readv(vnfc->fd_vnfc_in, iov, 2);
    if (n == 0) {
        VNFC_ERR_PRINT("The device fd has been closed\n");
        poll_delete_fd(vnfc->poll, vnfc->fd_vnfc_in);
        return false;
    } else if (n < 0) {
        VNFC_PERROR("readv (fd_VNFC_in)");
        return false;
    }

    n -= sizeof(*vnet);
    if (n <= 0) {
        VNFC_ERR_PRINT("No packet data is received\n");
        return false;
    }

    pktpool_trim_packet(vnfc->pool, packet, n);
    if (is_singular(vnfc)) {
        packet->upstream = (vnet->flags & VIRTIO_NET_HDR_F_UPSTREAM);
    }

    return true;
}


static bool vnfc_receive_packet_from_device(struct vnfc *vnfc,
                                            struct vnfc_packet_vec *vector)
{
    struct vnfc_packet *packet;
    bool upstream = (is_singular(vnfc) || vnfc->clt_up ||
                     vnfc->need_to_connect_up);

    use_vnfc_packet_default(vector, 0);
    packet = vector->packets[0];

    if (! alloc_packet_wait(vnfc, packet, MAX_PACKET_SIZE, upstream, 2)) {
        VNFC_ERR_PRINT("Can't allocate the packet buf: %d\n", MAX_PACKET_SIZE);
        return false;
    }

    if (! vnfc_receive_packet_from_device_impl(vnfc, packet)) {
        return false;
    }

    vector->size = 1;

    return true;
}


static bool vnfc_receive_packet_from_service(int fd, struct vnfc *vnfc,
                                             struct vnfc_packet_vec *vector)
{
    struct iovec iov[MAX_BURST_PACKETS];
    uint32_t indexes[MAX_BURST_PACKETS];
    size_t nr_packets;
    ssize_t n;
    int i;

    nr_packets = MAX_BURST_PACKETS;

    for (i = 0; i < nr_packets; i++) {
        iov[i].iov_base = &indexes[i];
        iov[i].iov_len  = sizeof(indexes[i]);
    }

    n = readv(fd, iov, nr_packets);
    if (n == 0) {
        VNFC_ERR_PRINT("The service socket has been closed\n");
        reset_sock_server_polling(vnfc, (fd == vnfc->svr_up->sock));
        return false;
    } else if (n < 0) {
        VNFC_PERROR("readv");
        return false;
    }

    nr_packets = n / sizeof(indexes[0]);

    for (i = 0; i < nr_packets; i++) {
        uint32_t index = *(uint32_t*)iov[i].iov_base;
        assert(iov[i].iov_len == sizeof(index));

        use_vnfc_packet_default(vector, i);
        if (! pktpool_get_packet(vnfc->pool, vector->packets[i], index,
                                 (fd == vnfc->svr_up->sock))) {
            VNFC_DBG_PRINT("Invalid packet index: %u\n", index);
            /* TODO: Free packets */
            return false;
        }
    }

    vector->size = nr_packets;

    return true;
}


static bool vnfc_receive_packet_from_vhu(struct vnfc *vnfc,
                                         struct vnfc_packet_vec *vector)
{
    ssize_t n;
    size_t  nr_avail;
    int i;

    if (! vhu_get_kick(vnfc->vhu)) {
        vnfc_vhu_restart(vnfc);
        return false;
    }

    nr_avail = vhu_get_avail_num(vnfc->vhu);
    if (! nr_avail) {
        VNFC_DBG_PRINT("No available packet\n");
        return false;
    } else if (nr_avail > MAX_BURST_PACKETS) {
        nr_avail = MAX_BURST_PACKETS;
    }

    VNFC_DBG_PRINT("Received %ld packets from the vhu client\n", nr_avail);

    for (i = 0; i < nr_avail; i++) {
        uint8_t *buf;
        uint32_t buf_idx;

        n = vhu_read_packet(vnfc->vhu, &buf_idx, &buf);
        if (n <= 0) {
            break;
        }

        use_vnfc_packet_default(vector, i);
        if (! set_vnfc_packet_vhu(vector->packets[i], buf_idx, buf, n)) {
            break;
        }
    }
    vector->size = i;

    if (vector->size != nr_avail) {
        VNFC_ERR_PRINT("%ld packets are lost\n", nr_avail - vector->size);
    }

    return true;
}


static bool vnfc_handle_data_fd(int fd, struct vnfc *vnfc,
                                 struct vnfc_packet_vec *vector)
{
    bool success = false;

    if (fd == vnfc->fd_vnfc_in) {
        success = vnfc_receive_packet_from_device(vnfc, vector);
    } else if (fd == vnfc->svr_up->sock || fd == vnfc->svr_down->sock) {
        success = vnfc_receive_packet_from_service(fd, vnfc, vector);
    } else if (is_vhu_server(vnfc)) {
        if (fd == vhu_get_data_socket(vnfc->vhu)) {
            success = vnfc_receive_packet_from_vhu(vnfc, vector);
        } else {
            goto unknown;
        }
    } else {
        goto unknown;
    }

    if (success) {
        assert(vector->size > 0);
#ifdef USE_DPDK
        assert(! is_dpdk_packet(vector->packets[0]));
#endif
        vector->upstream = vector->packets[0]->upstream;
    }

    return success;

unknown:
    VNFC_ERR_PRINT("Unknown data fd: %d\n", fd);
    vector->size = 0;
    return false;
}


static void vnfc_receive_server_packet_from_service(int svr_sock, struct vnfc *vnfc)
{
    struct sock_server *server;

    if (svr_sock == vnfc->svr_up->svr_sock) {
        server = vnfc->svr_up;
    } else {
        server = vnfc->svr_down;
    }

    if (! sock_server_accept(server)) {
        VNFC_ERR_PRINT("Can't accept the client (%s)\n",
                        (server == vnfc->svr_up) ? "up" : "down");
        return ;
    }

    poll_delete_fd(vnfc->poll, svr_sock);
    poll_add_fd(vnfc->poll, server->sock);
}


static void vnfc_receive_msg_packet_from_vhu(int msg_sock, struct vnfc *vnfc)
{
    bool is_closing = is_vhu_ready(vnfc->vhu);
    int  kickfd  = is_closing ? vhu_get_data_socket(vnfc->vhu) : -1;

    if (vhu_handle_message(vnfc->vhu)) {
        if (is_closing) {
            if (kickfd != -1 && kickfd != vhu_get_data_socket(vnfc->vhu)) {
                poll_delete_fd(vnfc->poll, kickfd);
                vnfc_vhu_restart(vnfc);
            }
        } else if (is_vhu_ready(vnfc->vhu)) {
            VNFC_PRINT("Ready for a vhu data connection\n");
            poll_add_fd(vnfc->poll, vhu_get_data_socket(vnfc->vhu));
        }
    } else {
        vnfc_vhu_restart(vnfc);
    }
}


static void vnfc_receive_server_packet_from_vhu(int svr_sock, struct vnfc *vnfc)
{
    if (! vhu_server_accept(vnfc->vhu)) {
        VNFC_ERR_PRINT("Can't accept the vhu client\n");
        return ;
    }

    /* Only single VHU client is suppoted */
    poll_delete_fd(vnfc->poll, svr_sock);
    poll_add_fd(vnfc->poll, vhu_get_message_socket(vnfc->vhu));
}


static bool vnfc_handle_ctl_fd(int fd, struct vnfc *vnfc)
{
    bool ret = false;

    if (fd == vnfc->svr_up->svr_sock || fd == vnfc->svr_down->svr_sock) {
        vnfc_receive_server_packet_from_service(fd, vnfc);
        ret = true;
    } else if (is_vhu_server(vnfc)) {
        if (fd == vhu_get_message_socket(vnfc->vhu)) {
            vnfc_receive_msg_packet_from_vhu(fd, vnfc);
            ret = true;
        } else if (fd == vhu_get_server_socket(vnfc->vhu)) {
            vnfc_receive_server_packet_from_vhu(fd, vnfc);
            ret = true;
        }
    }

    return ret;
}


#ifdef USE_DPDK
static bool vnfc_receive_packet_from_ring(struct vnfc *vnfc,
                                          struct vnfc_packet_vec *vector)
{
    if (! ring_client_rx_burst(vnfc->ring, vector)) {
        return false;
    }

    vector->upstream = false;

    return true;
}
#endif


bool vnfc_recv_packet_burst(int event_fd, struct vnfc *vnfc,
                            struct vnfc_packet_vec *vector)
{
    int fd;

    if (event_fd < 0 || MAX_EPOLL_EVENTS <= event_fd) {
        VNFC_ERR_PRINT("Invalid event fd: %d\n", event_fd);
        return false;
    } else if (! vnfc) {
        VNFC_ERR_PRINT("Invalid vnfc: null\n");
        return false;
    } else if (! vector) {
        VNFC_ERR_PRINT("Invalid packet vector: null\n");
        return false;
    }

    vector->size = 0;

#ifdef USE_DPDK
    if (g_poll_counter > 0) {
        if (is_ring_client(vnfc)) {
            vnfc_receive_packet_from_ring(vnfc, vector);
        }
        return true;
    }
#endif

    fd = poll_get_event_fd(vnfc->poll, event_fd);

    if (vnfc_handle_ctl_fd(fd, vnfc)) {
        /* No data packet */
        return true;
    }

    return vnfc_handle_data_fd(fd, vnfc, vector);
}


inline int vnfc_wait_for_recv(struct vnfc *vnfc, int timeout)
{
#ifdef USE_DPDK
    if (is_ring_client(vnfc) && ring_client_has_rx_packet(vnfc->ring)) {
        if (++g_poll_counter < MAX_POLL_COUNT) {
            return 1; /* Do the polling */
        }
    }
    g_poll_counter = 0;
#endif
    return poll_wait(vnfc->poll, timeout);
}


void vnfc_drop_packet(struct vnfc *vnfc, struct vnfc_packet_vec *vector, int index)
{
    if (index < 0 || vector->size < index) {
        VNFC_ERR_PRINT("Can't drop the packet: invalid params\n");
        return ;
    }

    free_vnfc_packet(vector->packets[index]);
}


void vnfc_drop_packet_burst(struct vnfc *vnfc, struct vnfc_packet_vec *vector)
{
    if (! vnfc) {
        VNFC_ERR_PRINT("Invalid vnfc: null\n");
        return ;
    } else if (! vector) {
        VNFC_ERR_PRINT("Invalid vector: null\n");
        return ;
    } else if (vector->size == 0) {
        return ;
    }

    if (is_vhu_packet(vector->packets[0])) {
        assert(vnfc->vhu);
        vhu_update_used(vnfc->vhu);
    }

    free_vnfc_packet_vec(vector);
}
