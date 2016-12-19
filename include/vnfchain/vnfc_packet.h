/*
 * vnfc_packet.h : Definition of packet structures
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

#ifndef __VNFC_LIB_PACKET_H__
#define __VNFC_LIB_PACKET_H__

#ifdef __cplusplus
extern "C" {

#define class class2  // Workaround for linux/virio_net.h

#endif

#include <stdint.h>
#include <stdbool.h>
#include <linux/virtio_net.h>

#ifdef USE_DPDK
#include <rte_mbuf.h>
#endif

#define MIN_PACKET_SIZE  14
#define MAX_PACKET_SIZE  65554 /* Max. IP packet + ether + vlan */

enum { MAX_BURST_PACKETS = 128 };


struct vnfc_packet_meta
{
    size_t                buf_len;
    struct virtio_net_hdr gso;
};


struct vnfc_packet
{
    uint64_t                     zero;      /* Used to distinguish rte_mbuf */

    /* Following fields are used by only non-DPDK μVNFs */

    union {
        uint8_t                 *head;
        struct vnfc_packet_meta *meta;
    };
    uint8_t                     *data;
    struct vnfc_pktpool         *pool;
    size_t                       data_len;
    uint32_t                     index;     /* pool idx or vring idx */
    bool                         upstream;
};


struct vnfc_packet_vec
{
    /* Array of vnfc_packet or rte_mbuf */
    struct vnfc_packet *packets[MAX_BURST_PACKETS];

    /* Array of vnfc_packet */
    struct vnfc_packet  def_packets[MAX_BURST_PACKETS];
    size_t              size;
    bool                upstream;
};

struct vnfc_pktpool;

uint8_t *get_vnfc_packet_data(const struct vnfc_packet *packet);
size_t   get_vnfc_packet_len(const struct vnfc_packet *packet);

bool     is_empty_packet(const struct vnfc_packet *packet);
bool     is_vnfc_packet(const struct vnfc_packet *packet);
bool     is_vhu_packet(const struct vnfc_packet *packet);
#ifdef USE_DPDK
bool     is_dpdk_packet(const struct vnfc_packet *packet);
#endif

void     use_vnfc_packet_default(struct vnfc_packet_vec *vector, int index);

bool     set_vnfc_packet(struct vnfc_packet *packet, struct vnfc_pktpool *pool,
                         uint32_t index, uint8_t *buf, size_t len, bool upstream);

bool     set_vnfc_packet_vhu(struct vnfc_packet *packet, uint32_t index,
                             uint8_t *buf, size_t len);
void     free_vnfc_packet(struct vnfc_packet *packet);
void     free_vnfc_packet_vec(struct vnfc_packet_vec *vector);


#ifdef __cplusplus
}
#endif

#endif /* __VNFC_LIB_PACKET_H__ */
