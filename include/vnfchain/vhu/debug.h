/*
 * debug.h
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

#ifndef __VNFC_LIB_VHU_DBG_H__
#define __VNFC_LIB_VHU_DBG_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct vhu_message;
struct vhu_vring;

const char *get_vhostmsg_name(const struct vhu_message *msg);
void        dump_vhostmsg(const struct vhu_message *msg);
void        dump_buffer(const uint8_t *buf, size_t len);
void        dump_vring(const struct vhu_vring *vring);

#ifdef __cplusplus
}
#endif

#endif /* __VNFC_LIB_VHU_DBG_H__ */
