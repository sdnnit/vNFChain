/*
 * ring_client.h
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

#ifndef __VNFC_LIB_DPDK_RING_CLIENT_H__
#define __VNFC_LIB_DPDK_RING_CLIENT_H__

#include <stdint.h>
#include <stdbool.h>
#include <net/if.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rte_ring;

struct ring_client
{
    uint32_t id;
    char tx_name[IF_NAMESIZE];
    char rx_name[IF_NAMESIZE];
    struct rte_ring *txr;
    struct rte_ring *rxr;
};

struct vnfc_packet_vec;

struct ring_client *ring_client_init(uint32_t client_id);
void                ring_client_exit(struct ring_client *ring);
bool                ring_client_has_rx_packet(const struct ring_client *ring);
void                ring_client_tx_burst(struct ring_client *ring, struct vnfc_packet_vec *vector);
bool                ring_client_rx_burst(struct ring_client *ring, struct vnfc_packet_vec *vector);

#ifdef __cplusplus
}
#endif

#endif /* __VNFC_LIB_DPDK_RING_CLIENT_H__ */
