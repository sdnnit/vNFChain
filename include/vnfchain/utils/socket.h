/*
 * socket.h
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

#ifndef __VNFC_LIB_UTILS_SOCKET_H__
#define __VNFC_LIB_UTILS_SOCKET_H__

#include <stdbool.h>
#include <linux/un.h>

#ifdef __cplusplus
extern "C" {
#endif


struct sock_server
{
    struct sockaddr_un addr;
    int    svr_sock;
    int    sock;
    bool   is_stream;
};


struct sock_client
{
    struct sockaddr_un addr;
    int    sock;
    bool   is_stream;
};


struct sock_server *sock_server_init(const char *path, bool is_stream);
void                sock_server_exit(struct sock_server *server);
bool                sock_server_accept(struct sock_server *server);
struct sock_client *sock_client_init(const char *path, bool is_stream);
void                sock_client_exit(struct sock_client *client);


#ifdef __cplusplus
}
#endif

#endif /* __VNFC_LIB_UTILS_SOCKET_H__ */
