/*
 * vnfc_packet.c
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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_ether.h>

#ifdef USE_DPDK
#include <rte_mbuf.h>
#endif

#include "vnfc_pktpool.h"
#include "vnfc_packet.h"
#include "utils/print.h"

VNFC_DEFINE_PRINT_MODULE("vnfc");


inline uint8_t *get_vnfc_packet_data(const struct vnfc_packet *packet)
{
#ifdef USE_DPDK
    if (is_dpdk_packet(packet)) {
        return rte_pktmbuf_mtod((struct rte_mbuf*)packet, uint8_t*);
    }
#endif
    return packet->data;
}


inline size_t get_vnfc_packet_len(const struct vnfc_packet *packet)
{
#ifdef USE_DPDK
    if (is_dpdk_packet(packet)) {
        return ((struct rte_mbuf*)packet)->data_len;
    }
#endif
    return packet->data_len;
}


inline bool is_empty_packet(const struct vnfc_packet *packet)
{
    return (! packet->zero && ! packet->data);
}


inline bool is_vnfc_packet(const struct vnfc_packet *packet)
{
    return (! packet->zero && packet->pool && packet->data);
}

inline bool is_vhu_packet(const struct vnfc_packet *packet)
{
    return (! packet->zero && ! packet->pool && packet->data);
}


#ifdef USE_DPDK
inline bool is_dpdk_packet(const struct vnfc_packet *packet)
{
    return (((const struct rte_mbuf*)packet)->buf_addr);
}
#endif


inline void use_vnfc_packet_default(struct vnfc_packet_vec *vector, int index)
{
    vector->packets[index] = &vector->def_packets[index];
}


static bool set_vnfc_packet_impl(struct vnfc_packet *packet,
                                 struct vnfc_pktpool *pool, uint32_t index,
                                 uint8_t *buf, size_t len, bool upstream)
{
    if (! packet || ! buf) {
        return false;
    } else if (len < MIN_PACKET_SIZE + sizeof(struct vnfc_packet_meta) ||
               MAX_PACKET_SIZE + sizeof(struct vnfc_packet_meta) < len) {
        VNFC_ERR_PRINT("Invalid packet len: %lu\n", len);
        return false;
    }

    memset(packet, 0, sizeof(*packet));

    if (pool) {
        packet->head          = buf;
        packet->meta->buf_len = len;
        packet->pool          = pool;
        buf = (uint8_t*)(packet->meta + 1);
        len -= sizeof(*packet->meta);
    }
    packet->data          = buf;
    packet->data_len      = len;
    packet->index         = index;
    packet->upstream      = upstream;

    return true;
}


bool inline set_vnfc_packet(struct vnfc_packet *packet, struct vnfc_pktpool *pool,
                            uint32_t index, uint8_t *buf, size_t len, bool upstream)
{
    return set_vnfc_packet_impl(packet, pool, index, buf, len, upstream);
}


inline bool set_vnfc_packet_vhu(struct vnfc_packet *packet, uint32_t index,
                               uint8_t *buf, size_t len)
{
    return set_vnfc_packet_impl(packet, NULL, index, buf, len, true);
}


static inline void free_vnfc_packet_default(struct vnfc_packet *packet)
{
    pktpool_release_packet(packet);
}


static inline void free_vnfc_packet_vhu(struct vnfc_packet *packet)
{

}


#ifdef USE_DPDK
static inline void free_vnfc_packet_dpdk(struct vnfc_packet *packet)
{
    rte_pktmbuf_free((struct rte_mbuf*)packet);
}
#endif


void free_vnfc_packet(struct vnfc_packet *packet)
{
    if (! packet) {
        return ;
    }

#ifdef USE_DPDK
    if (is_dpdk_packet(packet)) {
        free_vnfc_packet_dpdk(packet);
    } else
#endif
    if (is_vhu_packet(packet)) {
        free_vnfc_packet_vhu(packet);
    } else {
        free_vnfc_packet_default(packet);
    }

    memset(packet, 0, sizeof(*packet));
}


void free_vnfc_packet_vec(struct vnfc_packet_vec *vector)
{
    int i;

    for (i = 0; i < vector->size; i++) {
        free_vnfc_packet(vector->packets[i]);
        vector->packets[i] = NULL;
    }

    vector->size = 0;
}
