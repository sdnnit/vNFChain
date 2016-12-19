/*
 * memory.h
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

#ifndef __VNFC_LIB_VHU_MEM_H__
#define __VNFC_LIB_VHU_MEM_H__

#include <stdint.h>
#include "proto.h"

#ifdef __cplusplus
extern "C" {
#endif


struct vhu_server_memory_region
{
    uint64_t guest_phys_addr;
    uint64_t memory_size;
    uint64_t userspace_addr;
    uint64_t shm_addr;
    uint64_t shm_offset;
};


struct vhu_server_memory
{
    uint32_t nr_regions;
    struct vhu_server_memory_region regions[VHOST_MEMORY_MAX_NREGIONS];
};


struct vhu_server_memory *vhu_server_memory_init(void);
void      vhu_server_memory_exit(struct vhu_server_memory *memory);
uintptr_t vhu_map_guest_addr(const struct vhu_server_memory *memory, uint64_t addr);
uintptr_t vhu_map_user_addr(const struct vhu_server_memory *memory, uint64_t addr);


#ifdef __cplusplus
}
#endif

#endif /* __VNFC_LIB_VHU_MEM_H__ */
