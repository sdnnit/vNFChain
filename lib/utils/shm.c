/*
 * shm.c : mmap wrapper
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

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "utils/print.h"
#include "utils/shm.h"

VNFC_DEFINE_PRINT_MODULE("utils");


void *shm_init_by_fd(int fd, size_t size) {
    void *addr;

    addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        VNFC_PERROR("mmap");
        addr = NULL;
    }
    return addr;
}


void *shm_init(const char *path, size_t size, int *fd)
{
    void *addr;

    *fd = shm_open(path, O_RDWR | O_CREAT | O_EXCL, 0666);
    if (*fd < 0) {
        return NULL;
    }

    if (ftruncate(*fd, size) != 0) {
        VNFC_PERROR("ftruncate");
        goto err;
    }

    addr = shm_init_by_fd(*fd, size);
    if (! addr) {
        goto err;
    }

    return addr;

err:
    close(*fd);
    return NULL;
}


void *shm_map(const char *path, size_t size, int *fd)
{
    void *addr;

    *fd = shm_open(path, O_RDWR, 0666);
    if (*fd < 0) {
        VNFC_PERROR("shm_open");
        return NULL;
    }

    addr = shm_init_by_fd(*fd, size);
    if (! addr) {
        goto err;
    }

    return addr;

err:
    close(*fd);
    return NULL;
}


void shm_exit(const char *path, void *addr, size_t size, int fd)
{
    if (fd != -1) {
        close(fd);
    }

    if (munmap(addr, size) != 0) {
        VNFC_PERROR("munmap");
    }

    if (path) {
        if (shm_unlink(path) != 0) {
            VNFC_PERROR("shm_unlink");
        }
    }
}


int shm_sync(void *addr, size_t size)
{
    return msync(addr, size, MS_SYNC | MS_INVALIDATE);
}
