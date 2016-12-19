/*
 * shm.h
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

 #ifndef __VNFC_LIB_UTILS_SHM_H__
 #define __VNFC_LIB_UTILS_SHM_H__

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void *shm_init(const char *path, size_t size, int *fd);
void *shm_map(const char *path, size_t size, int *fd);
void *shm_init_by_fd(int fd, size_t size);
void  shm_exit(const char *path, void *addr, size_t size, int fd);
int   shm_sync(void *addr, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* __VNFC_LIB_UTILS_SHM_H__ */
