/*
 * objpool.h
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

#ifndef __VNFC_LIB_UTILS_OBJPOOL_H__
#define __VNFC_LIB_UTILS_OBJPOOL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <linux/limits.h>

struct poolstat;

struct objpool
{
    int              fd;
    char             path[PATH_MAX];
    size_t           chunk_size;
    size_t           nr_chunks;
    size_t           pool_size;
    void            *memory;
    struct poolstat *stat;
    uint8_t         *data;
};


struct objpool *objpool_init(const char *path, size_t chunk_size,
                             size_t nr_chunks);
void            objpool_exit(struct objpool *pool, bool remove);
uint8_t        *objpool_alloc_chunks(struct objpool *pool, size_t len,
                                     uint32_t *pidx);
bool            objpool_trim_chunks(struct objpool *pool, uint32_t index,
                                    size_t oldlen, size_t newlen);
void            objpool_release_chunks(struct objpool *pool, uint32_t index,
                                       size_t len);
uint8_t        *get_chunk_from_index(const struct objpool *pool,
                                     uint32_t index);
uint32_t        get_index_from_chunk(const struct objpool *pool,
                                     const uint8_t *chunk);

#ifdef __cplusplus
}
#endif

#endif /* __VNFC_LIB_UTILS_OBJPOOL_H__ */
