/*
 * if_vnfc.h
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

#ifndef __VNFC_IF_VNFC_H__
#define __VNFC_IF_VNFC_H__

#ifdef __KERNEL__
#include <linux/if.h>
#else
#include <net/if.h>
#endif

#include <linux/if_tun.h>

/* Device features */
#define VNFC_DEV                      (IFF_TAP | IFF_NO_PI)     /* Tap device emulation */
#define VNFC_FASYNC                    IFF_ATTACH_QUEUE         /* Asynchronous notification */
#define VNFC_NOCHECKSUM                TUN_NOCHECKSUM           /* CHECKSUM_UNNECESSARY */
#define VNFC_PERSIST                   IFF_PERSIST              /* Persist mode */
#define VNFC_VNET_HDR                  IFF_VNET_HDR             /* Offload control */
#define VNFC_ONE_QUEUE                 IFF_ONE_QUEUE            /* Single queue mode */
#define VNFC_MULTI_QUEUE               IFF_MULTI_QUEUE          /* Multi queue mode */

#define VNFC_VNET_LE                   0x80000000
#define VNFC_VNET_BE                   0x40000000

/* Interface flags */
#define IFF_VNFC                       VNFC_DEV                 /* Tap device emulation */
#define IFF_VNFC_EXCL                  IFF_TUN_EXCL             /* Exclusive mode */

/* ioctl commands */
#define VNFC_SET_IFF                   TUNSETIFF                /* Attach to the device */
#define VNFC_GET_IFF                   TUNGETIFF                /* Get interface flags */
#define VNFC_SET_PERSIST               TUNSETPERSIST            /* Set persist mode */
#define VNFC_SET_SNDBUF                TUNSETSNDBUF             /* Set send buffer size of the socket */
#define VNFC_GET_SNDBUF                TUNGETSNDBUF             /* Get send buffer size of the socket */
#define VNFC_GET_FEATURES              TUNGETFEATURES           /* Get interface flags */
#define VNFC_SET_OFFLOAD               TUNSETOFFLOAD            /* Set offloading features */
#define VNFC_SET_NOCSUM                TUNSETNOCSUM             /* Set checksum mode */
#define VNFC_SET_OWNER                 TUNSETOWNER              /* Set a user of the device */
#define VNFC_SET_GROUP                 TUNSETGROUP              /* Set a group of the device */
#define VNFC_SET_LINK                  TUNSETLINK               /* Set a link type of the device */
#define VNFC_SET_VNET_HDR_SZ           TUNSETVNETHDRSZ          /* Set a size of virtio_net_hdr */
#define VNFC_GET_VNET_HDR_SZ           TUNGETVNETHDRSZ          /* Get a size of virtio_net_hdr */
#define VNFC_SET_QUEUE                 TUNSETQUEUE
#define VNFC_SET_IF_INDEX              TUNSETIFINDEX
#define VNFC_SET_VNET_LE               TUNSETVNETLE
#define VNFC_GET_VNET_LE               TUNGETVNETLE
#define VNFC_SET_VNET_BE               TUNSETVNETBE
#define VNFC_GET_VNET_BE               TUNGETVNETBE

/* ioctl commands (ext.) */
#define VNFC_SET_SERVICE              _IOW('T', 230, int)      /* Set network services */
#define VNFC_GET_SERVICE              _IOW('T', 231, int)      /* Get network service */

/* Additional flags for services */
#define VIRTIO_NET_HDR_F_UPSTREAM      0x20                     /* Upstream direction */
#define VIRTIO_NET_HDR_F_DOWNSTREAM    0x40                     /* Downstream direction */

/* Offloading features */
#define VNFC_F_CSUM                    TUN_F_CSUM
#define VNFC_F_TSO4                    TUN_F_TSO4
#define VNFC_F_TSO6                    TUN_F_TSO6
#define VNFC_F_TSO_ECN                 TUN_F_TSO_ECN
#define VNFC_F_UFO                     TUN_F_UFO

#define VNFC_USER_FEATURES            (NETIF_F_HW_CSUM | NETIF_F_TSO_ECN | \
                                       NETIF_F_TSO | NETIF_F_TSO6 | NETIF_F_UFO)

#define SERVICE_DETACH                 0x01
#define SERVICE_UPSTREAM               0x02
#define SERVICE_DOWNSTREAM             0x04
#define SERVICE_OUTPUT_FILE            0x08
#define SERVICE_INPUT_FILE             0x10

#define SIG_VNFCHAIN                   44

struct vnfc_req
{
    pid_t                 pid;
    char                  svc_name[IFNAMSIZ];
    char                  dev_name[IFNAMSIZ];
    unsigned long         flags;
    unsigned long         value;
};

#endif /* __VNFC_IF_VNFC_H__ */
