/*
 * vnfc_io.h : Definitions of I/O related functions
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

#ifndef __VNFC_LIB_IO_H__
#define __VNFC_LIB_IO_H__

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct vnfc;
struct vnfc_packet;
struct vnfc_packet_vec;

bool vnfc_send_packet_burst(struct vnfc *vnfc, struct vnfc_packet_vec *vector);
bool vnfc_recv_packet_burst(int event_fd, struct vnfc *vnfc,
                            struct vnfc_packet_vec *vector);
int  vnfc_wait_for_recv(struct vnfc *vnfc, int timeout);
void vnfc_drop_packet(struct vnfc *vnfc, struct vnfc_packet_vec *vector,
                      int index);
void vnfc_drop_packet_burst(struct vnfc *vnfc, struct vnfc_packet_vec *vector);

#ifdef __cplusplus
}
#endif


#endif /* __VNFC_LIB_IO_H__ */
