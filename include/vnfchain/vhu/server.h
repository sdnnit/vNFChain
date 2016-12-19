/*
 * server.h
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

#ifndef __VNFC_LIB_VHU_SERVER_H__
#define __VNFC_LIB_VHU_SERVER_H__

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sock_server;
struct vhu_server_memory;
struct vring_table;

struct vhu_server{
    struct sock_server       *sock_svr;
    struct vhu_server_memory *memory;
    struct vring_table       *vtable;
};

struct vhu_server *vhu_server_init(const char *dev_name);
void               vhu_server_exit(struct vhu_server *server);
bool               vhu_server_accept(struct vhu_server *server);
bool               vhu_handle_message(struct vhu_server *server);
bool               is_vhu_ready(const struct vhu_server *server);
bool               vhu_get_kick(const struct vhu_server *server);
int                vhu_get_server_socket(const struct vhu_server *server);
int                vhu_get_message_socket(const struct vhu_server *server);
int                vhu_get_data_socket(const struct vhu_server *server);
size_t             vhu_get_avail_num(const struct vhu_server *server);
void               vhu_update_avail(const struct vhu_server *server);
void               vhu_update_used(struct vhu_server *server);
ssize_t            vhu_send_packet(struct vhu_server *server, const uint8_t *buf, size_t buf_len);
ssize_t            vhu_read_packet(struct vhu_server *server, uint32_t *pidx, uint8_t **pbuf);
ssize_t            vhu_get_packet_by_index(const struct vhu_server *server, uint32_t index, uint8_t **pbuf);

#ifdef __cplusplus
}
#endif

#endif /* __VNFC_LIB_VHU_SERVER_H__ */
