/*
 * vnfc_utils.h
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

#ifndef __VNFC_LIB_UTILS_H__
#define __VNFC_LIB_UTILS_H__

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct vnfc;
struct vnfc_packet;

/*******************************************************************************
* Predicate functions
*******************************************************************************/
bool need_to_connect(const struct vnfc *vnfc);
bool is_singular(const struct vnfc *vnfc);
bool is_last_up(const struct vnfc *vnfc);
bool is_last_down(const struct vnfc *vnfc);
bool is_vhu_server(const struct vnfc *vnfc);

#ifdef USE_DPDK
bool is_ring_client(const struct vnfc *vnfc);
#endif

/*******************************************************************************
* Utility functions
*******************************************************************************/
void vnfc_memcpy(uint8_t *to, const uint8_t *from, size_t len);
void vnfc_make_sock_path(char *path, pid_t pid, bool upstream);
bool alloc_packet_wait(struct vnfc *vnfc, struct vnfc_packet *packet, size_t len,
                       bool upstream, size_t times);
bool reset_sock_server_polling(struct vnfc *vnfc, bool upstream);

#ifdef __cplusplus
}
#endif

#endif /* __VNFC_LIB_UTILS_H__ */
