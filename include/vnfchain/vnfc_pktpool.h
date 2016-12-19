/*
 * vnfc_pktpool.h
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

#ifndef __VNFC_LIB_PKTPOOL_H__
#define __VNFC_LIB_PKTPOOL_H__


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

struct objpool;

struct vnfc_pktpool
{
    struct objpool *up;
    struct objpool *down;
};

struct vnfc_packet;

struct vnfc_pktpool *pktpool_init(const char *name);
void                 pktpool_exit(struct vnfc_pktpool *pool, bool remove);
bool                 pktpool_set_packet(struct vnfc_pktpool *pool,
                                        struct vnfc_packet *packet, size_t len,
                                        bool upstream);
bool                 pktpool_get_packet(struct vnfc_pktpool *pool,
                                        struct vnfc_packet *packet,
                                        uint32_t index, bool upstream);
void                 pktpool_trim_packet(const struct vnfc_pktpool *pool,
                                     struct vnfc_packet *packet, size_t newlen);
void                 pktpool_release_packet(struct vnfc_packet *packet);

#ifdef __cplusplus
}
#endif

#endif /* __VFNC_LIB_PKTPOOL_H__ */
