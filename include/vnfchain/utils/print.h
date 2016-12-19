/*
 * print.h
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

#ifndef __VNFC_LIB_UTILS_PRINT_H__
#define __VNFC_LIB_UTILS_PRINT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

#define VNFC_DEFINE_PRINT_MODULE(MODULE) \
    static const char *this_module = MODULE;


#ifdef VNFC_DEBUG

#define VNFC_DBG_PRINT(fmt, ...)  fprintf(stderr, "[%s] DEBUG: " fmt, this_module, ##  __VA_ARGS__)

#else

#define VNFC_DBG_PRINT(fmt, ...)

#endif


#define VNFC_PRINT(fmt, ...) printf("[%s] " fmt, this_module, ## __VA_ARGS__)

#define VNFC_ERR_PRINT(fmt, ...) fprintf(stderr, "[%s] ERROR: " fmt,  this_module, ## __VA_ARGS__)

#define VNFC_PERROR(msg) VNFC_ERR_PRINT(""); perror(msg)

#ifdef __cplusplus
}
#endif

#endif /* __VNFC_LIB_UTILS_PRINT_H__ */
