/*
 * vnfc_pktpool.c
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
#include <assert.h>
#include "vnfc_packet.h"
#include "vnfc_pktpool.h"
#include "utils/objpool.h"
#include "utils/print.h"

VNFC_DEFINE_PRINT_MODULE("vnfc");


#define DEFAULT_PACKET_SIZE   128
#define DEFAULT_NR_CHUNKS     (4096 * 64)

#define POSTFIX_UP_KEY       "_pktpool_up.dat"
#define POSTFIX_DOWN_KEY     "_pktpool_down.dat"


bool pktpool_set_packet(struct vnfc_pktpool *pool, struct vnfc_packet *packet,
                        size_t len, bool upstream)
{
    struct objpool *opool;
    uint32_t index;
    uint8_t *buf;

    if (! packet) {
        VNFC_ERR_PRINT("Invalid packet buf\n");
        return false;
    } else if (len < MIN_PACKET_SIZE || MAX_PACKET_SIZE < len) {
        VNFC_ERR_PRINT("Invalid required packet len: %lu\n", len);
        return false;
    }

    opool = (upstream) ? pool->up : pool->down;
    len += sizeof(struct vnfc_packet_meta);

    buf = objpool_alloc_chunks(opool, len, &index);
    if (! buf) {
        VNFC_ERR_PRINT("Can't get free chunks\n");
        return false;
    }

    return set_vnfc_packet(packet, pool, index, buf, len, upstream);
}


bool pktpool_get_packet(struct vnfc_pktpool *pool, struct vnfc_packet *packet,
                        uint32_t index, bool upstream)
{
    struct objpool *opool;
    struct vnfc_packet_meta *meta;

    if (! packet) {
        VNFC_ERR_PRINT("Invalid packet buf\n");
        return false;
    }

    opool = (upstream) ? pool->up : pool->down;
    meta = (struct vnfc_packet_meta*)get_chunk_from_index(opool, index);

    if (meta->buf_len < MIN_PACKET_SIZE + sizeof(*meta) ||
        MAX_PACKET_SIZE + sizeof(*meta) < meta->buf_len) {
            VNFC_ERR_PRINT("buf_len = %lu\n", meta->buf_len);
        VNFC_ERR_PRINT("Invalid packet len: %lu\n",
                       meta->buf_len - sizeof(*meta));
        return false;
    }

    return set_vnfc_packet(packet, pool, index, (uint8_t*)meta, meta->buf_len,
                           upstream);
}


void pktpool_trim_packet(const struct vnfc_pktpool *pool,
                         struct vnfc_packet *packet, size_t newlen)
{
    assert(is_vnfc_packet(packet));
    newlen += sizeof(struct vnfc_packet_meta);

    if (packet->meta->buf_len > newlen) {
        uint32_t diff = packet->meta->buf_len - newlen;
        if (objpool_trim_chunks((packet->upstream) ? pool->up : pool->down,
                                packet->index, packet->meta->buf_len, newlen)) {
            packet->meta->buf_len -= diff;
        } else {
            VNFC_DBG_PRINT("Can't trim the buf %u (%lu => %lu)\n",
                           packet->index, packet->meta->buf_len, newlen);
        }
        packet->data_len -= diff;
    }
}


void pktpool_release_packet(struct vnfc_packet *packet)
{
    struct objpool *opool;

    assert(is_vnfc_packet(packet));

    if (packet->upstream) {
        opool = packet->pool->up;
    } else {
        opool = packet->pool->down;
    }

    objpool_release_chunks(opool, packet->index, packet->meta->buf_len);
}


struct vnfc_pktpool *pktpool_init(const char *name)
{
    struct vnfc_pktpool *pool;
    char path[PATH_MAX];
    size_t hdr_len;

    pool = (struct vnfc_pktpool*)malloc(sizeof(struct vnfc_pktpool));
    if (! pool) {
        VNFC_ERR_PRINT("Can't allocate memory for pool\n");
        return NULL;
    }

    hdr_len = sizeof(struct vnfc_packet_meta);

    snprintf(path, sizeof(path), "%s%s", name, POSTFIX_UP_KEY);
    pool->up = objpool_init(path, DEFAULT_PACKET_SIZE + hdr_len,
                            DEFAULT_NR_CHUNKS);
    if (! pool->up) {
        goto free_pool;
    }

    snprintf(path, sizeof(path), "%s%s", name, POSTFIX_DOWN_KEY);
    pool->down = objpool_init(path, DEFAULT_PACKET_SIZE + hdr_len,
                              DEFAULT_NR_CHUNKS);
    if (! pool->down) {
        goto free_up;
    }

    return pool;

free_up:
    objpool_exit(pool->up, false);

free_pool:
    free(pool);

    return NULL;
}


void pktpool_exit(struct vnfc_pktpool *pool, bool remove)
{
    if (pool) {
        if (pool->up) {
            objpool_exit(pool->up, remove);
            pool->up = NULL;
        }
        if (pool->down) {
            objpool_exit(pool->down, remove);
            pool->down = NULL;
        }
        free(pool);
    }
}
