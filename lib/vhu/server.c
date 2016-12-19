/*
 * server.c : vhost-user server
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
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <sys/stat.h>
#include <unistd.h>

#include "utils/print.h"
#include "utils/socket.h"
#include "vhu/proto.h"
#include "vhu/vring.h"
#include "vhu/memory.h"
#include "vhu/server.h"

#ifdef VNFC_DEBUG
#include "vhu/debug.h"
#endif

VNFC_DEFINE_PRINT_MODULE("vhu");

static const char *SOCKET_PATH = "/tmp/vhu";


inline bool is_vhu_ready(const struct vhu_server *server)
{
    const struct vhu_vring *tx = VRING_TX(server->vtable);
    const struct vhu_vring *rx = VRING_RX(server->vtable);

    return (tx->vring.desc && rx->vring.desc &&
            tx->kickfd > 0 && rx->kickfd > 0 &&
            tx->callfd > 0 && rx->callfd > 0);
}


bool vhu_get_kick(const struct vhu_server *server)
{
    if (! vring_get_kick(VRING_RX(server->vtable)->kickfd)) {
        VNFC_ERR_PRINT("Can't get a kick\n");
        return false;
    }

    VNFC_DBG_PRINT("Got a kick\n");

    return true;
}


inline int vhu_get_server_socket(const struct vhu_server *server)
{
    return server->sock_svr->svr_sock;
}


inline int vhu_get_message_socket(const struct vhu_server *server)
{
    return server->sock_svr->sock;
}


inline int vhu_get_data_socket(const struct vhu_server *server)
{
    return VRING_RX(server->vtable)->kickfd;
}


inline size_t vhu_get_avail_num(const struct vhu_server *server)
{
    return vring_get_avail_num(server->vtable);
}


inline void vhu_update_avail(const struct vhu_server *server)
{
    vring_update_avail(server->vtable);

    vring_kick(VRING_TX(server->vtable)->callfd);
}


inline void vhu_update_used(struct vhu_server *server)
{
    vring_update_used(server->vtable);
}


ssize_t vhu_send_packet(struct vhu_server *server, const uint8_t *buf, size_t buf_len)
{
    if (! vring_write(server->vtable, buf, buf_len)) {
        VNFC_ERR_PRINT("Can't write to the vring\n");
        return -1;
    }

    return buf_len;
}


ssize_t vhu_read_packet(struct vhu_server *server, uint32_t *pidx, uint8_t **pbuf)
{
    ssize_t n;

    n = vring_read(server->vtable, pidx, pbuf);
    if (n < 0) {
        VNFC_ERR_PRINT("Can't read from the vring\n");
    } else if (n == 0) {
        /* Do noting */
    } else {
#ifdef VNFC_DEBUG
        dump_buffer(*pbuf, n);
#endif
    }
    return n;
}


inline ssize_t vhu_get_packet_by_index(const struct vhu_server *server,
                                       uint32_t index,
                                       uint8_t **pbuf)
{
    return vring_get_packet_by_index(server->vtable, index, pbuf);
}


bool vhu_handle_message(struct vhu_server *server)
{
    struct vhu_message msg;
    int msg_sock;
    ssize_t n;
    bool do_reply;

    memset(&msg, 0, sizeof(msg));
    msg_sock = vhu_get_message_socket(server);

    n = vhu_recv_message(msg_sock, &msg);
    if (n < 0) {
        VNFC_ERR_PRINT("Can't receive the message\n");
        goto out;
    } else if (n == 0) {
        VNFC_ERR_PRINT("The messaging socket has been closed\n");
        goto reset;
    }

#ifdef VNFC_DEBUG
    VNFC_PRINT("Received a message: %s\n", get_vhostmsg_name(&msg));

    dump_vhostmsg(&msg);
#endif

    if (! vhu_msg_handlers[msg.type]) {
        VNFC_ERR_PRINT("A message handler is not set\n");
        goto out;
    }

    do_reply = (vhu_msg_handlers[msg.type])(server, &msg);
    if (do_reply) {
        msg.flags &= ~VHOST_USER_VERSION_MASK;
        msg.flags |= (VHOST_USER_VERSION | VHOST_USER_REPLY_MASK);

        n = vhu_send_reply(msg_sock, &msg);
        if (n < 0) {
            VNFC_ERR_PRINT("Can't send a reply message\n");
            goto out;
        } else if (n == 0) {
            VNFC_ERR_PRINT("The messaging socket has been closed\n");
            goto reset;
        }
    }

out:
    return true;

reset:
    return false;
}


inline bool vhu_server_accept(struct vhu_server *server)
{
    return sock_server_accept(server->sock_svr);
}


static uintptr_t map_handler(void* context, uint64_t addr)
{
    struct vhu_server *server = (struct vhu_server*)context;
    return vhu_map_guest_addr(server->memory, addr);
}


static bool _vhu_server_init_impl(struct vhu_server *server,
                                  const char *path)
{
    mode_t def_mask;

    memset(server, 0, sizeof(*server));

    def_mask = umask(S_IWOTH);
    server->sock_svr = sock_server_init(path, true);
    if (! server->sock_svr) {
        VNFC_ERR_PRINT("Can't initialize the socket\n");
        return false;
    }
    umask(def_mask);

    server->memory = vhu_server_memory_init();
    if (! server->memory) {
        VNFC_ERR_PRINT("Can't initialize the memory\n");
        return false;
    }

    server->vtable = vring_table_init(map_handler, server);
    if (! server->vtable) {
        VNFC_ERR_PRINT("Can't initialize the vring\n");
        return false;
    }

    return true;
}


static void make_sock_path(char *path, const char *dev_name)
{
    sprintf(path, "%s_%s.sock", SOCKET_PATH, dev_name);
}


struct vhu_server *vhu_server_init(const char *dev_name)
{
    struct vhu_server *server;
    char path[UNIX_PATH_MAX];

    if (! dev_name || strlen(dev_name) >= sizeof(path)) {
        VNFC_ERR_PRINT("Invalid device name\n");
        return NULL;
    }

    make_sock_path(path, dev_name);

    server = (struct vhu_server*)malloc(sizeof(struct vhu_server));
    if (! server) {
        VNFC_ERR_PRINT("Can't allocate memory\n");
        return NULL;
    }

    if (! _vhu_server_init_impl(server, path)) {
        vhu_server_exit(server);
        return NULL;
    }

    return server;
}


void vhu_server_exit(struct vhu_server *server)
{
    if (! server) {
        return ;
    }

    if (server->sock_svr) {
        sock_server_exit(server->sock_svr);
    }
    if (server->memory) {
        vhu_server_memory_exit(server->memory);
    }
    if (server->vtable) {
        vring_table_exit(server->vtable);
    }

    free(server);
}
