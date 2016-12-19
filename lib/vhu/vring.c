/*
 * vring.c
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
#include <assert.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <linux/virtio_net.h>

#include "utils/print.h"
#include "utils/shm.h"
#include "vhu/vring.h"
#include "vhu/atomic.h"

VNFC_DEFINE_PRINT_MODULE("vhu")


struct vring_table *vring_table_init(map_handler_t handler, void *context)
{
    struct vring_table *vtable;
    int i;

    vtable = (struct vring_table*)malloc(sizeof(struct vring_table));
    if (! vtable) {
        VNFC_ERR_PRINT("Can't allocate memory\n");
        return NULL;
    }

    vtable->map_handler = handler;
    vtable->context     = context;

    for (i = 0; i < VHOST_USER_VRING_NUM; i++) {
        struct vhu_vring *vring = &vtable->vrings[i];
        memset(&vring->vring, 0, sizeof(struct vring));
        vring->kickfd         = -1;
        vring->callfd         = -1;
        vring->last_avail_idx = 0;
        vring->last_used_idx  = 0;
    }

    return vtable;
}


void vring_table_exit(struct vring_table *vtable)
{
    int i;

    if (! vtable) {
        return ;
    }

    for (i = 0; i < VHOST_USER_VRING_NUM; i++) {
        struct vhu_vring *vring = &vtable->vrings[i];
        if (vring->kickfd != -1) {
            close(vring->kickfd);
        }
        if (vring->callfd != -1) {
            close(vring->callfd);
        }
    }

    free(vtable);
}


static ssize_t _vring_read_impl(struct vring_table *vtable, uint16_t desc_idx,
                                uint32_t *pidx, uint8_t **pbuf)
{
    struct vhu_vring *vring;
    struct vring_desc *desc;
    struct vring_used *used;
    struct virtio_net_hdr *vnet;
    uint32_t i;
    uint16_t used_idx;
    ssize_t read_len;

    vring = VRING_RX(vtable);

    used = vring->vring.used;
    used_idx = vring->last_used_idx & (VRING_NUM(vring) - 1);

    vnet = NULL;
    read_len = 0;
    i = desc_idx;
    do {
        uint8_t *current;
        uint32_t cur_len;

        assert(i < VRING_NUM(vring));

        desc = &vring->vring.desc[i];

        assert(!(desc->flags & VRING_DESC_F_WRITE));
        assert(!(desc->flags & VRING_DESC_F_INDIRECT));

        current = (uint8_t*)vtable->map_handler(vtable->context, desc->addr);
        cur_len = desc->len;
        VNFC_DBG_PRINT("Rx) Chunk %d: len=%d, flags=0x%X, next=%d\n",
                        i, desc->len, desc->flags, desc->next);

        if (vnet) {
            assert(!(desc->flags & VRING_DESC_F_NEXT));
            assert(cur_len > 0);

            *pidx     = desc_idx;
            *pbuf     = current;
        } else { /* Read out the vnet header */
            vnet = (struct virtio_net_hdr*)current;
            assert(cur_len >= sizeof(*vnet));

            // check the header
            if ((vnet->flags != 0) || (vnet->gso_type != 0) ||
                (vnet->hdr_len != 0) || (vnet->gso_size != 0) ||
                (vnet->csum_start != 0) || (vnet->csum_offset != 0)) {
                VNFC_DBG_PRINT("Wrong vnet flags\n");
            }
        }

        read_len += cur_len;
        i = desc->next;
    } while (desc->flags & VRING_DESC_F_NEXT);

    used->ring[used_idx].id  = desc_idx;
    used->ring[used_idx].len = read_len;

    return read_len - sizeof(*vnet);
}


ssize_t vring_read(struct vring_table *vtable, uint32_t *pidx, uint8_t **pbuf)
{
    struct vhu_vring   *vring;
    struct vring_avail *avail;
    uint16_t read_idx;
    ssize_t n;

    vring = VRING_RX(vtable);
    avail = vring->vring.avail;

    VNFC_DBG_PRINT("last_avail=%d, last_used=%d, avail=%d, used=%d\n",
                    vring->last_avail_idx, vring->last_used_idx,
                    avail->idx, vring->vring.used->idx);

    read_idx = vring->last_avail_idx & (VRING_NUM(vring) - 1);

    n = _vring_read_impl(vtable, avail->ring[read_idx], pidx, pbuf);
    if (n > 0) {
        vring->last_avail_idx++;
        vring->last_used_idx++;
    }

    return n;
}


inline uint16_t vring_get_avail_num(const struct vring_table *vtable)
{
    const struct vhu_vring *vring = VRING_RX(vtable);
    return (uint16_t)(atomic_mb_read(&vring->vring.avail->idx) -
                      vring->last_avail_idx);
}


ssize_t vring_get_packet_by_index(const struct vring_table *vtable,
                                  uint32_t index, uint8_t **pbuf)
{
    const struct vhu_vring *vring = VRING_RX(vtable);
    struct vring_desc *desc;

    desc = &vring->vring.desc[index];
    assert(desc->len == sizeof(struct virtio_net_hdr));
    assert(desc->flags & VRING_DESC_F_NEXT);

    desc = &vring->vring.desc[desc->next];
    assert(desc->len > 0);
    assert(!(desc->flags & VRING_DESC_F_NEXT));

    *pbuf = (uint8_t*)vtable->map_handler(vtable->context, desc->addr);

    return desc->len;
}


void vring_update_used(struct vring_table *vtable)
{
    struct vhu_vring *vring;
    struct vring_avail *avail;
    struct vring_used  *used;

    vring = VRING_RX(vtable);
    avail = vring->vring.avail;
    used  = vring->vring.used;

    atomic_mb_set(&used->idx, vring->last_used_idx);

    if (!(avail->flags & VRING_AVAIL_F_NO_INTERRUPT)) {
        VNFC_DBG_PRINT("Do callback\n");
        if (! vring_kick(vring->callfd)) {
            VNFC_ERR_PRINT("Can't callback to the client\n");
        }
    }
}


static ssize_t _vring_write_impl(struct vring_table *vtable, uint16_t desc_idx,
                                 const uint8_t *buf, size_t buf_len)
{
    struct vhu_vring *vring;
    struct vring_desc *desc;
    struct vring_used *used;
    struct virtio_net_hdr vnet;
    void *guest_addr;
    size_t write_len;
    uint16_t used_idx;
    uint16_t i;

    vring = VRING_TX(vtable);

    write_len = 0;
    i = desc_idx;
    do {
        void *current = NULL;
        size_t cur_len = 0;

        assert(i < VRING_NUM(vring));
        desc = &vring->vring.desc[i];

        VNFC_DBG_PRINT("Tx) Chunk %d: len=%d, flags=0x%X, next=%d\n",
                        i, desc->len, desc->flags, desc->next);
        assert(desc->flags & VRING_DESC_F_WRITE);

        guest_addr = (uint8_t*)vtable->map_handler(vtable->context, desc->addr);

        if (desc->len == sizeof(struct virtio_net_hdr)) {
            memset(&vnet, 0, sizeof(vnet));
            current = &vnet;
            cur_len = sizeof(vnet);
        } else {
            assert(!(desc->flags & VRING_DESC_F_NEXT));
            if (buf_len > desc->len) {
                /* Too large data */
                return -1;
            }
            current = (void*)buf;
            cur_len = buf_len;
        }

        memcpy(guest_addr, current, cur_len);
        write_len += cur_len;
        i = desc->next;
    } while (desc->flags & VRING_DESC_F_NEXT);

    used = vring->vring.used;
    used_idx = vring->last_used_idx & (VRING_NUM(vring) - 1);

    used->ring[used_idx].id  = desc_idx;
    used->ring[used_idx].len = write_len;

    return write_len - sizeof(vnet);
}


ssize_t vring_write(struct vring_table *vtable, const uint8_t *buf, size_t buf_len)
{
    struct vhu_vring *vring;
    struct vring_avail *avail;
    uint16_t write_idx;
    ssize_t n;

    vring = VRING_TX(vtable);
    avail = vring->vring.avail;

    VNFC_DBG_PRINT("last_avail=%d, last_used=%d, avail=%d, used=%d\n",
                    vring->last_avail_idx, vring->last_used_idx,
                    avail->idx, vring->vring.used->idx);

    assert(vring->last_avail_idx != atomic_mb_read(&avail->idx));

    write_idx = vring->last_avail_idx & (VRING_NUM(vring) - 1);

    n = _vring_write_impl(vtable, avail->ring[write_idx], buf, buf_len);
    if (n > 0) {
        vring->last_avail_idx++;
        vring->last_used_idx++;
    }

    return n;
}


inline void vring_update_avail(struct vring_table *vtable)
{
    struct vhu_vring *vring;
    struct vring_used *used;

    vring = VRING_TX(vtable);
    used  = vring->vring.used;

    atomic_mb_set(&used->idx, vring->last_used_idx);
}


bool vring_get_kick(int sock)
{
    eventfd_t kick_it;
    ssize_t n;

    n = eventfd_read(sock, &kick_it);
    if (n < 0) {
        VNFC_PERROR("eventfd_read: ");
        return false;
    }

    return true;
}


bool vring_kick(int sock)
{
    ssize_t n;

    n = eventfd_write(sock, (eventfd_t)1);
    if (n < 0) {
        VNFC_PERROR("eventfd_write: ");
        return false;
    }

    return true;
}
