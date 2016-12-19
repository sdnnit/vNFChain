/*
 * vring.h
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

#ifndef __VNFC_LIB_VHU_VRING_H__
#define __VNFC_LIB_VHU_VRING_H__

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <linux/virtio_ring.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    VRING_IDX_NONE = (uint16_t)-1,
};


enum {
    VHOST_USER_VRING_IDX_TX = 0,
    VHOST_USER_VRING_IDX_RX = 1,
    VHOST_USER_VRING_NUM    = 2,
};


struct vhu_vring {
    struct vring vring;
    int kickfd;
    int callfd;
    volatile uint16_t last_avail_idx;
    volatile uint16_t last_used_idx;
};


typedef uintptr_t (*map_handler_t)(void* context, uint64_t addr);

struct vring_table {
    map_handler_t map_handler;
    void *context;
    struct vhu_vring vrings[VHOST_USER_VRING_NUM];
};


#define VRING_TX(vtable) (&(vtable)->vrings[VHOST_USER_VRING_IDX_TX])
#define VRING_RX(vtable) (&(vtable)->vrings[VHOST_USER_VRING_IDX_RX])
#define VRING_NUM(vring) ((vring)->vring.num)


struct vring_table *vring_table_init(map_handler_t handler, void *context);
void                vring_table_exit(struct vring_table *vtable);
ssize_t             vring_read(struct vring_table *vtable, uint32_t *pidx, uint8_t **pbuf);
ssize_t             vring_write(struct vring_table *vtable, const uint8_t *buf, size_t buf_len);
uint16_t            vring_get_avail_num(const struct vring_table *vtable);
ssize_t             vring_get_packet_by_index(const struct vring_table *vtable, uint32_t index, uint8_t **pbuf);
void                vring_update_used(struct vring_table *vtable);
void                vring_update_avail(struct vring_table *vtable);
bool                vring_get_kick(int sock);
bool                vring_kick(int sock);

#ifdef __cplusplus
}
#endif

#endif /* __VNFC_LIB_VHU_VRING_H__ */
