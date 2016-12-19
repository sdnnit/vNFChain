/*
 * dpdk.c
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
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <net/if.h>

#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include "utils/print.h"
#include "dpdk/dpdk.h"

VNFC_DEFINE_PRINT_MODULE("dpdk");

static struct dpdk *g_dpdk;

inline struct dpdk *get_dpdk(void)
{
    return g_dpdk;
}


static struct rte_mempool *dpdk_get_mempool_from_ovs(int socket_id)
{
    struct rte_mempool *mp;
    uint32_t nr_elements = 4096 * 64;
    char name[IF_NAMESIZE];

    mp_hdlr_init_ops_mp_mc();

    do {
        sprintf(name, "ovs_mp_2030_%d_%u", socket_id, nr_elements);
        mp = rte_mempool_lookup(name);
        nr_elements >>= 1;
    } while (!mp && nr_elements >= 16384);

    return mp;
}


bool dpdk_init(int argc, char **argv)
{
    struct dpdk *dpdk;
    int res;

    dpdk = (struct dpdk*)malloc(sizeof(struct dpdk));
    if (! dpdk) {
        VNFC_ERR_PRINT("Can't allocate memory\n");
        return false;
    }

    memset(dpdk, 0, sizeof(*dpdk));

    res = rte_eal_init(argc, argv);
    if (res < 0) {
        VNFC_ERR_PRINT("Can't initialize dpdk\n");
        goto err;
    }

    dpdk->socket_id = rte_socket_id();

    dpdk->mp = dpdk_get_mempool_from_ovs(dpdk->socket_id);
    if (! dpdk->mp) {
        VNFC_ERR_PRINT("Can't initialize the mempool\n");
        goto err;
    }

    g_dpdk = dpdk;

    return true;

err:
    if (dpdk) {
        free(dpdk);
    }
    return false;
}


void dpdk_exit(void)
{
    if (g_dpdk) {
        if (g_dpdk->mp) {
            rte_mempool_free(g_dpdk->mp);
            g_dpdk->mp = NULL;
        }
        free(g_dpdk);
        g_dpdk = NULL;
    }
}
