/*
 * poll.h
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

#ifndef __VNFC_LIB_UTILS_POLL_H__
#define __VNFC_LIB_UTILS_POLL_H__

#include <stdbool.h>
#include <sys/epoll.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_EPOLL_EVENTS    8

struct poll_struct
{
    int fd;
    struct epoll_event events[MAX_EPOLL_EVENTS];
};


struct poll_struct *poll_init(void);
void                poll_exit(struct poll_struct *poll);
bool                poll_add_fd(struct poll_struct *poll, int fd);
bool                poll_delete_fd(struct poll_struct *poll, int fd);
int                 poll_wait(struct poll_struct *poll, int timeout);
int                 poll_get_event_fd(const struct poll_struct *poll, int event_fd);

#ifdef __cplusplus
}
#endif

#endif /* __VNFC_LIB_UTILS_POLL_H__ */
