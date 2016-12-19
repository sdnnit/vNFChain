/*
 * poll.c : epoll wrapper
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
#include <unistd.h>

#include "utils/print.h"
#include "utils/poll.h"

VNFC_DEFINE_PRINT_MODULE("utils");


struct poll_struct *poll_init(void)
{
    struct poll_struct *poll;

    poll = (struct poll_struct*)malloc(sizeof(struct poll_struct));
    if (! poll) {
        return NULL;
    }

    poll->fd = epoll_create1(0);
    if (poll->fd == -1) {
        VNFC_PERROR("epoll_create1");
        poll_exit(poll);
        return NULL;
    }

    return poll;
}


void poll_exit(struct poll_struct *poll)
{
    if (poll) {
        if (poll->fd > 0) {
            close(poll->fd);
        }
        free(poll);
    }
}


bool poll_add_fd(struct poll_struct *poll, int fd)
{
    struct epoll_event ev;
    int err;

    ev.events  = EPOLLIN;
    ev.data.fd = fd;

    err = epoll_ctl(poll->fd, EPOLL_CTL_ADD, ev.data.fd, &ev);
    if (err < 0) {
        VNFC_PERROR("epoll_ctl");
        return false;
    }
    return true;
}


bool poll_delete_fd(struct poll_struct *poll, int fd)
{
    struct epoll_event ev;
    int err;

    ev.events  = EPOLLIN;
    ev.data.fd = fd;

    err = epoll_ctl(poll->fd, EPOLL_CTL_DEL, ev.data.fd, NULL);
    if (err < 0) {
        VNFC_PERROR("epoll_ctl");
        return false;
    }
    return true;
}


int poll_wait(struct poll_struct *poll, int timeout)
{
    int nfds;

    if (! poll || poll->fd == -1) {
        VNFC_DBG_PRINT("Invalid argument");
        return -1;
    }

    nfds = epoll_wait(poll->fd, poll->events, MAX_EPOLL_EVENTS, timeout);
    if (nfds < 0) {
        VNFC_PERROR("epoll_wait");
        return -1;
    }

    return nfds;
}


inline int poll_get_event_fd(const struct poll_struct *poll, int event_fd)
{
    return poll->events[event_fd].data.fd;
}
