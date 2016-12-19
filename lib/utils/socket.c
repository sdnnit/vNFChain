/*
 * socket.c : socket wrapper
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
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>

#include "utils/print.h"
#include "utils/socket.h"

VNFC_DEFINE_PRINT_MODULE("utils");


static int sock_open(struct sockaddr_un *addr, const char *path, bool is_stream)
{
    int sock;

    if (! path || strlen(path) >= UNIX_PATH_MAX) {
        return -1;
    }

    strcpy(addr->sun_path, path);

    VNFC_DBG_PRINT("socket path: %s\n", addr->sun_path);

    addr->sun_family = AF_LOCAL;

    sock = socket(addr->sun_family, is_stream ? SOCK_STREAM : SOCK_DGRAM, 0);
    if (sock < 0) {
        VNFC_PERROR("socket");
        return -1;
    }

    return sock;
}


static void sock_close(int sock)
{
    if (sock >= 0) {
        close(sock);
    }
}


static bool sock_server_open(struct sock_server *server, const char *path,
                             bool is_stream)
{
    struct sockaddr_un *addr;
    int sock;

    addr = &server->addr;

    sock = sock_open(addr, path, is_stream);
    if (sock < 0) {
        return -1;
    }

    unlink(addr->sun_path);

    if (bind(sock, (struct sockaddr*)addr, sizeof(*addr)) < 0) {
        VNFC_PERROR("bind");
        goto err;
    }

    if (is_stream) {
        int value;

        if (listen(sock, 1) < 0) {
            VNFC_PERROR("listen");
            goto err;
        }

        value = fcntl(sock, F_GETFL, 0);
        if (fcntl(sock, F_SETFL, value | O_NONBLOCK) < 0) {
            VNFC_PERROR("fcntl");
            goto err;
        }

        server->svr_sock  = sock;
        server->is_stream = true;
    } else {
        server->sock = sock;
    }

    return true;

err:
    close(sock);
    return false;
}


bool sock_server_accept(struct sock_server *server)
{
    struct sockaddr_un addr;
    socklen_t len;
    int clt_sock;

    memset(&addr, 0, sizeof(addr));
    len = sizeof(addr);

    clt_sock = accept(server->svr_sock, (struct sockaddr*)&addr, &len);
    if (clt_sock < 0) {
        VNFC_PERROR("accept");
        return false;
    }

    server->sock = clt_sock;
    return true;
}


struct sock_server *sock_server_init(const char *path, bool is_stream)
{
    struct sock_server *server;

    server = (struct sock_server*)malloc(sizeof(struct sock_server));
    if (! server) {
        return NULL;
    }
    memset(server, 0, sizeof(*server));
    server->svr_sock = -1;
    server->sock     = -1;

    if (! sock_server_open(server, path, is_stream)) {
        goto err;
    }

    return server;

err:
    sock_server_exit(server);
    return NULL;
}


void sock_server_exit(struct sock_server *server)
{
    if (server) {
        sock_close(server->svr_sock);
        sock_close(server->sock);
        unlink(server->addr.sun_path);
        free(server);
    }
}


static bool sock_client_connect(struct sock_client *client)
{
    int err;

    err = connect(client->sock, (struct sockaddr*)&client->addr,
                  sizeof(client->addr));
    if (err < 0) {
        VNFC_PERROR("connect");
        return false;
    }

    return true;
}


static bool sock_client_open(struct sock_client *client, const char *path,
                             bool is_stream)
{
    struct sockaddr_un *addr;
    int sock;

    addr = &client->addr;

    sock = sock_open(addr, path, is_stream);
    if (sock < 0) {
        return false;
    }

    client->sock      = sock;
    client->is_stream = is_stream;

    return true;
}


struct sock_client *sock_client_init(const char *path, bool is_stream)
{
    struct sock_client *client;

    client = (struct sock_client*)malloc(sizeof(struct sock_client));
    if (! client) {
        return NULL;
    }
    memset(client, 0, sizeof(*client));
    client->sock = -1;

    if (! sock_client_open(client, path, is_stream)) {
        goto err;
    }

    if (! sock_client_connect(client)) {
        goto err;
    }

    return client;

err:
    sock_client_exit(client);
    return NULL;
}


void sock_client_exit(struct sock_client *client)
{
    if (client) {
        sock_close(client->sock);
        free(client);
    }
}
