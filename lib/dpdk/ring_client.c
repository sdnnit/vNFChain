/*
 * ring_client.c
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

#include <rte_ring.h>

#include "vnfc_packet.h"
#include "utils/print.h"
#include "dpdk/ring_client.h"


VNFC_DEFINE_PRINT_MODULE("dpdk");


inline bool ring_client_has_rx_packet(const struct ring_client *ring)
{
    return (!rte_ring_empty(ring->rxr));
}


void ring_client_tx_burst(struct ring_client *ring, struct vnfc_packet_vec *vector)
{
    int ret;

    do {
        ret = rte_ring_enqueue_bulk(ring->txr, (void**)vector->packets, vector->size);
    } while (ret == -ENOBUFS);

    vector->size = 0;
}


bool ring_client_rx_burst(struct ring_client *ring, struct vnfc_packet_vec *vector)
{
    uint32_t nr_packets = MAX_BURST_PACKETS;

    do {
        if (rte_ring_dequeue_bulk(ring->rxr, (void**)vector->packets, nr_packets) == 0) {
            break;
        }
        nr_packets = (uint16_t)RTE_MIN(rte_ring_count(ring->rxr), MAX_BURST_PACKETS);
    } while (nr_packets > 0);

    if (nr_packets == 0) {
        return false;
    }

    vector->size = nr_packets;

    return true;
}


struct ring_client *ring_client_init(uint32_t client_id)
{
    struct ring_client *ring;


    ring = (struct ring_client*)malloc(sizeof(struct ring_client));
    if (! ring) {
        VNFC_ERR_PRINT("Can't allocate memory\n");
        return NULL;
    }

    memset(ring, 0, sizeof(*ring));

    ring->id = client_id;
    snprintf(ring->tx_name, sizeof(ring->tx_name), "dpdkr%u_rx", ring->id);
    snprintf(ring->rx_name, sizeof(ring->rx_name), "dpdkr%u_tx", ring->id);

    ring->txr = rte_ring_lookup(ring->tx_name);
    if (! ring->txr) {
        VNFC_ERR_PRINT("Can't get the tx ring: %s\n", ring->tx_name);
        goto err;
    }

    VNFC_PRINT("A ring %s has been attached\n", ring->tx_name);

    ring->rxr = rte_ring_lookup(ring->rx_name);
    if (! ring->rxr) {
        VNFC_ERR_PRINT("Can't get the rx ring: %s\n", ring->rx_name);
        goto err;
    }

    VNFC_PRINT("A ring %s has been attached\n", ring->rx_name);

    return ring;

err:
    free(ring);
    return NULL;
}


void ring_client_exit(struct ring_client *ring)
{
    if (ring) {
        free(ring);
    }
}
