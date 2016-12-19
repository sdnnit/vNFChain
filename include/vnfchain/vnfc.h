/*
 * vnfc.h : Definition of structures for vNFCLib
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

#ifndef __VNFC_LIB_VNFC_H__
#define __VNFC_LIB_VNFC_H__

#include <stdint.h>
#include <stdbool.h>
#include <net/if.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VNFC_UPSTREAM     0x01
#define VNFC_DOWNSTREAM   0x02
#define VNFC_BIDIRECTION  (VNFC_UPSTREAM | VNFC_DOWNSTREAM)
#define VNFC_DPDK_RING    0x04

struct vnfc_pktpool;
struct sock_server;
struct sock_client;
struct poll_struct;
#ifdef USE_DPDK
struct ring_client;
#endif

struct vnfc {
    struct vhu_server   *vhu;
#ifdef USE_DPDK
    struct ring_client  *ring;
#else
    void                *unused;
#endif

    /* Basic information of the servie */
    char                 svc_name[IF_NAMESIZE];
    char                 dev_name[IF_NAMESIZE];
    uint64_t             flags;

    /* File descriptors of vNFCModule */
    int                  fd_vnfc_in;
    int                  fd_vnfc_out;

    /* Packet pool */
    struct vnfc_pktpool *pool;

    /* IPC information for next/Previous uVNFs */
    struct sock_server  *svr_up;
    struct sock_server  *svr_down;
    struct sock_client  *clt_up;
    struct sock_client  *clt_down;
    bool                 need_to_connect_up;
    bool                 need_to_connect_down;
    pid_t                pid_to_up;
    pid_t                pid_to_down;

    /* For event handling */
    struct poll_struct  *poll;
};


struct vnfc *vnfc_attach(const char *svc_name, const char *dev_name,
                         uint64_t flags);
void         vnfc_detach(struct vnfc *vnfc);

#ifdef __cplusplus
}
#endif

#endif /* __VNFC_LIB_VNFC_H__ */
