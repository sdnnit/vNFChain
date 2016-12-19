/*
 * objpool.c : Object pool
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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <errno.h>
#include <endian.h>

#include "utils/print.h"
#include "utils/shm.h"
#include "utils/objpool.h"

VNFC_DEFINE_PRINT_MODULE("utils");


struct poolstat
{
    volatile uint64_t rw_indexes;
    uint8_t dummy[8];
};


struct chunk_hdr
{
    uint8_t  status;
    uint8_t  unused[3];
    uint32_t nr_chunks;
};

#define OBJPOOL_CHUNK_FREE         ((uint8_t)0x00)
#define OBJPOOL_CHUNK_USED         ((uint8_t)0xFF)

#define OBJPOOL_OFFSET             sizeof(struct poolstat)
#define CHUNK_OFFSET               sizeof(struct chunk_hdr)
#define MAX_POOL_SIZE              (1024 * 1024 * 1024)


#define READ_INDEX(rw_indexes)     (uint32_t)((rw_indexes) >> 32 & 0xFFFFFFFF)
#define WRITE_INDEX(rw_indexes)    (uint32_t)((rw_indexes) & 0xFFFFFFFF)
#define IS_EMPTY(rw_indexes)       (WRITE_INDEX(rw_indexes) == READ_INDEX(rw_indexes))
#define DEFAULT_INDEXES            0



inline uint8_t *get_chunk_from_index(const struct objpool *pool, uint32_t index)
{
    return &pool->data[index * pool->chunk_size + CHUNK_OFFSET];
}


inline uint32_t get_index_from_chunk(const struct objpool *pool,
                                     const uint8_t *chunk)
{
    ptrdiff_t diff = (void*)chunk - (void*)pool->data;
    return (uint32_t)(diff / pool->chunk_size);
}


static inline size_t calc_nr_chunks(const struct objpool *pool, size_t len)
{
    size_t nr_chunks;

    nr_chunks = len / pool->chunk_size;
    if (len != nr_chunks * pool->chunk_size) {
        nr_chunks++;
    }

    return nr_chunks;
}


static inline uint32_t *get_pointer_to_write_idx(struct objpool *pool)
{
    uint32_t *pwidx;

    pwidx = (uint32_t*)&pool->stat->rw_indexes;
#if __BYTE_ORDER == __BIG_ENDIAN
    pwidx++;
#endif
    return pwidx;
}


static inline uint32_t *get_pointer_to_read_idx(struct objpool *pool)
{
    uint32_t *pridx;

    pridx = (uint32_t*)&pool->stat->rw_indexes;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    pridx++;
#endif
    return pridx;
}


static inline bool can_reset_indexes(uint64_t indexes)
{
    return (indexes != DEFAULT_INDEXES && IS_EMPTY(indexes));
}


static inline uint64_t reset_indexes(struct objpool *pool, uint64_t indexes)
{
    uint64_t old_indexes;

    VNFC_DBG_PRINT("Reset the indexes: R) %u, W) %u\n",
                    READ_INDEX(indexes), WRITE_INDEX(indexes));

    old_indexes = __sync_val_compare_and_swap(&pool->stat->rw_indexes,
                                              indexes, DEFAULT_INDEXES);

    if (old_indexes != indexes) {
        VNFC_DBG_PRINT("Another process has update the index values: R) %u, W) %u\n",
                       READ_INDEX(old_indexes), WRITE_INDEX(old_indexes));
        return old_indexes;
    }

    return DEFAULT_INDEXES;
}


static inline bool can_alloc_chunks(struct objpool *pool, uint64_t indexes,
                                    size_t nr_req_chunks)
{
    uint32_t read_idx  = READ_INDEX(indexes);
    uint32_t write_idx = WRITE_INDEX(indexes);

    /* Has the write index been circulated ? */
    if (write_idx < read_idx) {
        return (write_idx + nr_req_chunks < read_idx);
    }

    return ((write_idx + nr_req_chunks <= pool->nr_chunks) ||
            (WRITE_INDEX(DEFAULT_INDEXES) + nr_req_chunks < read_idx));
}


static inline bool need_reset_write_idx(const struct objpool *pool, uint32_t new_write_idx)
{
    return (new_write_idx > pool->nr_chunks);
}


static inline uint32_t reset_write_idx(struct objpool *pool, uint32_t widx)
{
    uint32_t  old_widx;

    VNFC_DBG_PRINT("Reset the write index of pool: W) %u\n", widx);

    old_widx = __sync_val_compare_and_swap(get_pointer_to_write_idx(pool), widx,
                                           WRITE_INDEX(DEFAULT_INDEXES));
    if (widx != old_widx) {
        VNFC_DBG_PRINT("Another process has updated the write index: %u\n",
                       old_widx);
        return old_widx;
    }

    return WRITE_INDEX(DEFAULT_INDEXES);
}


static uint8_t *get_avail_chunks(struct objpool *pool, size_t nr_chunks,
                                 uint32_t *pidx)
{
    uint64_t indexes;
    uint32_t widx;
    uint32_t old_widx;
    uint32_t new_widx;

    indexes = __sync_fetch_and_add(&pool->stat->rw_indexes, 0);
    if (can_reset_indexes(indexes)) {
        indexes = reset_indexes(pool, indexes);
    }

    if (! can_alloc_chunks(pool, indexes, nr_chunks)) {
        /* There is no free chunks */
        VNFC_DBG_PRINT("The pool is full: R) %u, W) %u\n",
                        READ_INDEX(indexes), WRITE_INDEX(indexes));
        return NULL;
    }

    widx = WRITE_INDEX(indexes);
    if (need_reset_write_idx(pool, widx + nr_chunks)) {
        widx = reset_write_idx(pool, widx);
        if (widx != WRITE_INDEX(DEFAULT_INDEXES)) {
            return NULL;
        }
    }

    new_widx = widx + nr_chunks;
    old_widx = __sync_val_compare_and_swap(get_pointer_to_write_idx(pool),
                                           widx, new_widx);
    if (old_widx != widx) {
        return NULL;
    }

    if (pidx) {
        *pidx = widx;
    }

    return &pool->data[widx * pool->chunk_size];
}


uint8_t *objpool_alloc_chunks(struct objpool *pool, size_t len, uint32_t *pidx)
{
    uint8_t *chunk;
    size_t nr_chunks;

    if (! pool) {
        VNFC_ERR_PRINT("The pool is NULL\n");
        return NULL;
    }

    nr_chunks = calc_nr_chunks(pool, len + CHUNK_OFFSET);
    if (! nr_chunks || pool->nr_chunks < nr_chunks) {
        VNFC_ERR_PRINT("Invalid the number of req chunks: %lu\n", nr_chunks);
        return NULL;
    }

    chunk = get_avail_chunks(pool, nr_chunks, pidx);
    if (! chunk) {
        return NULL;
    }

    assert(((struct chunk_hdr*)chunk)->status == OBJPOOL_CHUNK_FREE);
    ((struct chunk_hdr*)chunk)->status = OBJPOOL_CHUNK_USED;

    return &chunk[CHUNK_OFFSET];
}


bool objpool_trim_chunks(struct objpool *pool, uint32_t index, size_t oldlen,
                         size_t newlen)
{
    size_t nr_old_chunks;
    size_t nr_new_chunks;
    uint32_t widx;
    uint32_t old_widx;
    uint32_t new_widx;
    int32_t diff;
    uint32_t i;

    nr_old_chunks = calc_nr_chunks(pool, oldlen);
    nr_new_chunks = calc_nr_chunks(pool, newlen);

    diff = nr_old_chunks - nr_new_chunks;
    if (! diff) {
        return false;
    } else if (diff < 0) {
        return false;
    }

    widx     = index + nr_old_chunks;
    new_widx = index + nr_new_chunks;

    for (i = new_widx; i < widx; i++) {
        struct chunk_hdr *hdr =
                           (struct chunk_hdr*)&pool->data[i * pool->chunk_size];
        hdr->status = OBJPOOL_CHUNK_FREE;
    }

    old_widx = __sync_val_compare_and_swap(get_pointer_to_write_idx(pool),
                                           widx, new_widx);
    if (old_widx != widx) {
        VNFC_DBG_PRINT("Another process has updated the write index\n");
        return false;
    }

    return true;
}


static uint32_t get_last_freeing_chunk(struct objpool *pool, uint32_t index,
                                       uint32_t ridx, uint32_t widx,
                                       size_t nr_chunks)
{
    uint32_t new_ridx;
    bool is_circulated;

    new_ridx = ridx + nr_chunks;

    if (! nr_chunks) {
        return 0;
    } else if (ridx < widx) {
        if (widx < new_ridx) {
            return 0;
        }
        is_circulated = false;
    } else {
        assert(widx < ridx);
        if (pool->nr_chunks < new_ridx) {
            return 0;
        }
        is_circulated = true;
    }

    if (index == ridx) {
        while ((is_circulated && new_ridx < pool->nr_chunks) ||
               (! is_circulated && new_ridx < widx)) {
            struct chunk_hdr* hdr;

            hdr = (struct chunk_hdr*)&pool->data[new_ridx * pool->chunk_size];
            if (hdr->status != OBJPOOL_CHUNK_FREE) {
                break;
            }
            new_ridx++;
        }
    }

    return new_ridx;
}


static bool need_reset_read_idx(const struct objpool *pool, uint32_t ridx)
{
    return (pool->nr_chunks == ridx);
}


static inline uint32_t reset_read_idx(struct objpool *pool, uint32_t ridx)
{
    uint32_t  old_ridx;

    VNFC_DBG_PRINT("Reset the read index of pool: R) %u\n", ridx);

    old_ridx = __sync_val_compare_and_swap(get_pointer_to_read_idx(pool), ridx,
                                           READ_INDEX(DEFAULT_INDEXES));
    if (ridx != old_ridx) {
        VNFC_DBG_PRINT("Another process has updated the read index: %u\n",
                       old_ridx);
        return old_ridx;
    }

    return READ_INDEX(DEFAULT_INDEXES);
}


void objpool_release_chunks(struct objpool *pool, uint32_t index, size_t len)
{
    uint64_t indexes;
    uint32_t ridx;
    uint32_t new_ridx;
    uint32_t widx;
    int i;

    indexes = __sync_fetch_and_add(&pool->stat->rw_indexes, 0);
    assert (! can_reset_indexes(indexes));

    ridx = READ_INDEX(indexes);
    widx = WRITE_INDEX(indexes);

    if (IS_EMPTY(indexes) || index < ridx) {
        VNFC_ERR_PRINT("Can't release already released chunks: %u\n", index);
        return ;
    }

    new_ridx = get_last_freeing_chunk(pool, index, ridx, widx,
                                      calc_nr_chunks(pool, len));
    if (! new_ridx) {
        VNFC_ERR_PRINT("Invalid release size: %lu\n", len);
        return ;
    }

    for (i = ridx; i < new_ridx; i++) {
        struct chunk_hdr *hdr;

        hdr = (struct chunk_hdr*)&pool->data[i * pool->chunk_size];
        hdr->status = OBJPOOL_CHUNK_FREE;
    }

    if (index == ridx) {
        uint32_t old_ridx;
        old_ridx = __sync_val_compare_and_swap(get_pointer_to_read_idx(pool),
                                               ridx, new_ridx);
        assert(old_ridx == ridx);

        indexes = __sync_fetch_and_add(&pool->stat->rw_indexes, 0);
        if (can_reset_indexes(indexes)) {
            reset_indexes(pool, indexes);
        } else if (need_reset_read_idx(pool, READ_INDEX(indexes))) {
            reset_read_idx(pool, READ_INDEX(indexes));
        }
    }
}


struct objpool *objpool_init(const char *path, size_t chunk_size,
                             size_t nr_chunks)
{
    struct objpool *pool;
    size_t pool_size;
    bool need_init;

    if (! path || ! chunk_size || ! nr_chunks) {
        VNFC_ERR_PRINT("Invalid params\n");
        return false;
    }

    chunk_size += CHUNK_OFFSET;

    pool_size = chunk_size * nr_chunks + OBJPOOL_OFFSET;
    if (MAX_POOL_SIZE < pool_size) {
        VNFC_ERR_PRINT("Too large pool size: %lu\n", pool_size);
        return false;
    }

    pool = (struct objpool*)malloc(sizeof(struct objpool));
    if (! pool) {
        VNFC_ERR_PRINT("Can't allocate memory for the pool struct\n");
        return NULL;
    }
    memset(pool, 0, sizeof(*pool));

    strncpy(pool->path, path, PATH_MAX);
    pool->chunk_size = chunk_size;
    pool->nr_chunks  = nr_chunks;
    pool->pool_size  = pool_size;

    pool->memory = shm_init(pool->path, pool->pool_size, &pool->fd);
    if (pool->memory) {
        need_init = true;
    } else {
        pool->memory = shm_map(pool->path, pool->pool_size, &pool->fd);
        if (! pool->memory) {
            VNFC_ERR_PRINT("Can't map the shared memory: %s\n", pool->path);
            goto free_pool;
        }
        need_init = false;
    }

    pool->stat = (struct poolstat*)pool->memory;
    pool->data = (uint8_t*)(pool->stat + 1);

    if (need_init) {
        int i;

        for (i = 0; i < pool->nr_chunks; i++) {
            struct chunk_hdr *hdr;

            hdr = (struct chunk_hdr*)&pool->data[pool->chunk_size * i];
            hdr->status = OBJPOOL_CHUNK_FREE;
        }

        pool->stat->rw_indexes = DEFAULT_INDEXES;
        VNFC_PRINT("Created a new objpool: %s, chunk size = %lu, " \
                   "chunk nums = %lu\n", pool->path, chunk_size, nr_chunks);
    }

    return pool;

free_pool:
    free(pool);
    return NULL;
}


void objpool_exit(struct objpool *pool, bool remove)
{
    if (pool) {
        if (pool->memory) {
            shm_exit((remove) ? pool->path : NULL,
                     pool->memory, pool->pool_size, pool->fd);
            pool->memory = NULL;
        }
        pool->data = NULL;
        pool->stat = NULL;

        free(pool);
    }
}
