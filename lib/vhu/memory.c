/*
 * memory.c
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
#include <hugetlbfs.h>

#include "utils/shm.h"
#include "vhu/memory.h"


struct vhu_server_memory *vhu_server_memory_init(void)
{
    struct vhu_server_memory *memory;

    memory = (struct vhu_server_memory*)malloc(sizeof(struct vhu_server_memory));
    if (! memory) {
        return NULL;
    }

    memset(memory, 0, sizeof(*memory));

    return memory;
}


void vhu_server_memory_exit(struct vhu_server_memory *memory)
{
    int i;

    if (! memory) {
        return ;
    }

    for (i = 0; i < memory->nr_regions; i++) {
        struct vhu_server_memory_region *region = &memory->regions[i];
        if (region->shm_addr) {
            size_t shm_size = region->memory_size + region->shm_offset;
            if (shm_size < gethugepagesize()) {
                shm_size = gethugepagesize();
            }
            shm_exit(NULL, (void*)region->shm_addr, shm_size, -1);
        }
    }

    free(memory);
}


uintptr_t vhu_map_guest_addr(const struct vhu_server_memory* memory,
                             uint64_t addr)
{
    int i;

    for (i = 0; i < memory->nr_regions; i++) {
        const struct vhu_server_memory_region *r = &memory->regions[i];

        if ((r->guest_phys_addr <= addr) &&
            (addr < (r->guest_phys_addr + r->memory_size))) {
            return addr - r->guest_phys_addr + r->shm_addr + r->shm_offset;
        }
    }

    return 0;
}


uintptr_t vhu_map_user_addr(const struct vhu_server_memory* memory,
                            uint64_t addr)
{
    int i;

    for (i = 0; i < memory->nr_regions; i++) {
        const struct vhu_server_memory_region *r = &memory->regions[i];

        if ((r->userspace_addr <= addr) &&
            (addr < (r->userspace_addr + r->memory_size))) {
            return addr - r->userspace_addr + r->shm_addr + r->shm_offset;
        }
    }

    return 0;
}
