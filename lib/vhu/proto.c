/*
 * proto.c
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
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>

#include "utils/print.h"
#include "utils/shm.h"
#include "utils/poll.h"
#include "vhu/memory.h"
#include "vhu/vring.h"
#include "vhu/server.h"
#include "vhu/proto.h"

VNFC_DEFINE_PRINT_MODULE("vhu");


#define VHOST_USER_HDR_SIZE  offsetof(struct vhu_message, payload.u64)


ssize_t vhu_send_reply(int sock, struct vhu_message *msg)
{
    ssize_t n;

    do {
        n = send(sock, msg, VHOST_USER_HDR_SIZE + msg->payload_len, 0);
    } while (n < 0 && errno == EINTR);

    if (n < 0) {
        VNFC_PERROR("sendmsg");
    }

    return n;
}


ssize_t vhu_recv_message(int sock, struct vhu_message *msg)
{
    struct msghdr msgh;
    struct iovec iov[1];
    uint8_t control[CMSG_SPACE(sizeof(msg->fds))];
    struct cmsghdr *cmsg;
    ssize_t n;

    memset(&msgh, 0, sizeof(msgh));
    memset(control, 0, sizeof(control));

    iov[0].iov_base = (void*)msg;
    iov[0].iov_len  = VHOST_USER_HDR_SIZE;

    msgh.msg_iov        = iov;
    msgh.msg_iovlen     = sizeof(iov) / sizeof(iov[0]);
    msgh.msg_control    = control;
    msgh.msg_controllen = sizeof(control);

    n = recvmsg(sock, &msgh, 0);
    if (n < 0) {
        VNFC_PERROR("recvmsg");
        return -1;
    } else if (n == 0) {
        return 0;
    } else if (msg->flags & (MSG_TRUNC | MSG_CTRUNC)) {
        VNFC_ERR_PRINT("Message is truncated\n");
        return -1;
    }

    cmsg = CMSG_FIRSTHDR(&msgh);
    if (cmsg && cmsg->cmsg_len > 0 &&
        cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
        size_t cbuf_len = cmsg->cmsg_len - CMSG_LEN(0);
        memcpy(msg->fds, CMSG_DATA(cmsg), cbuf_len);
        msg->nr_fds = cbuf_len / sizeof(int);
    } else {
        msg->nr_fds = 0;
    }
    if (msg->payload_len > 0) {
        recv(sock, ((char*)msg) + n, msg->payload_len, 0);
    }

    return n;
}


static bool vhu_get_features(struct vhu_server *server, struct vhu_message *msg)
{
    msg->payload.u64 = 0; /* no features */
    msg->payload_len = sizeof(msg->payload.u64);

    return true; /* should reply back */
}


static bool vhu_set_features(struct vhu_server *server, struct vhu_message *msg)
{
    VNFC_DBG_PRINT("Not implemented\n");

    return false;
}


static bool vhu_set_owner(struct vhu_server *server, struct vhu_message *msg)
{
    VNFC_DBG_PRINT("Not implemented\n");

    return false;
}


static bool vhu_reset_owner(struct vhu_server *server, struct vhu_message *msg)
{
    VNFC_DBG_PRINT("Not implemented\n");

    return false;
}


static bool vhu_set_mem_table(struct vhu_server *server, struct vhu_message *msg)
{
    struct vhu_memory *memory = &msg->payload.memory;
    int i;

    server->memory->nr_regions = 0;

    if (msg->nr_fds != memory->nr_regions) {
        VNFC_ERR_PRINT("Invalid FD data\n");
        return false;
    }

    for (i = 0; i < memory->nr_regions; i++) {
        struct vhu_server_memory_region *region = &server->memory->regions[i];

        assert(msg->fds[i] > 0);

        region->guest_phys_addr = memory->regions[i].guest_phys_addr;
        region->memory_size     = memory->regions[i].memory_size;
        region->userspace_addr  = memory->regions[i].userspace_addr;
        region->shm_offset      = memory->regions[i].shm_offset;

        region->shm_addr  = (uintptr_t)shm_init_by_fd(msg->fds[i],
                                                      region->memory_size +
                                                      region->shm_offset);
        if (region->shm_addr) {
            server->memory->nr_regions++;
        }
        close(msg->fds[i]);
    }

    VNFC_DBG_PRINT("Got %d memory regions\n", server->memory->nr_regions);

    return false;
}


static bool vhu_set_log_base(struct vhu_server *server, struct vhu_message *msg)
{

    return false;
}


static bool vhu_set_log_fd(struct vhu_server *server, struct vhu_message *msg)
{
    return false;
}


static bool vhu_set_vring_num(struct vhu_server *server, struct vhu_message *msg)
{
    const struct vhost_vring_state *state = &msg->payload.state;
    int index;

    index = state->index;
    assert(index < VHOST_USER_VRING_NUM);

    server->vtable->vrings[index].vring.num = state->num;

    return 0;
}


static bool vhu_set_vring_addr(struct vhu_server *server, struct vhu_message *msg)
{
    const struct vhost_vring_addr *addr = &msg->payload.addr;
    struct vhu_vring *vring;
    int index;

    index = addr->index;
    assert(index < VHOST_USER_VRING_NUM);

    vring = &server->vtable->vrings[index];

    vring->vring.desc = (struct vring_desc*)vhu_map_user_addr(server->memory,
                                                               addr->desc_user_addr);
    vring->vring.avail = (struct vring_avail*)vhu_map_user_addr(server->memory,
                                                                 addr->avail_user_addr);
    vring->vring.used = (struct vring_used*)vhu_map_user_addr(server->memory,
                                                               addr->used_user_addr);
    vring->last_used_idx = vring->vring.used->idx;

    return false;
}


static bool vhu_set_vring_base(struct vhu_server *server, struct vhu_message *msg)
{
    const struct vhost_vring_state *state = &msg->payload.state;
    int index;

    index = state->index;
    assert(index < VHOST_USER_VRING_NUM);

    server->vtable->vrings[index].last_avail_idx = state->num;

    return false;
}


static bool vhu_get_vring_base(struct vhu_server *server, struct vhu_message *msg)
{
    struct vhost_vring_state *state = &msg->payload.state;
    struct vhu_vring *vring;
    int index;

    index = state->index;
    assert(index < VHOST_USER_VRING_NUM);

    vring = &server->vtable->vrings[index];

    state->num       = vring->last_avail_idx;
    msg->payload_len = sizeof(*state);

    if (vring->callfd != -1) {
        close(vring->callfd);
        vring->callfd = -1;
    }
    if (vring->kickfd != -1) {
        close(vring->kickfd);
        vring->kickfd = -1;
    }

    return true; /* should reply back */
}


static bool vhu_set_vring_kick(struct vhu_server *server, struct vhu_message *msg)
{
    struct vhu_vring *vring;
    int index;

    index = msg->payload.u64 & VHOST_USER_VRING_IDX_MASK;
    assert(index < VHOST_USER_VRING_NUM);

    vring = &server->vtable->vrings[index];
    if ((msg->payload.u64 & VHOST_USER_VRING_NOFD_MASK) == 0) {
        assert(msg->nr_fds == 1);

        if (vring->kickfd != -1) {
            VNFC_DBG_PRINT("Close the old kickfd: %d\n", vring->kickfd);
            close(vring->kickfd);
            /* TODO: Remove the fd from the event poll */
        }
        vring->kickfd = msg->fds[0];

        VNFC_DBG_PRINT("Got a kickfd: 0x%x\n", vring->kickfd);
    }

    return false;
}


static bool vhu_set_vring_call(struct vhu_server *server, struct vhu_message *msg)
{
    int index;

    index = msg->payload.u64 & VHOST_USER_VRING_IDX_MASK;
    assert(index < VHOST_USER_VRING_NUM);

    if ((msg->payload.u64 & VHOST_USER_VRING_NOFD_MASK) == 0) {
        struct vhu_vring *vring = &server->vtable->vrings[index];

        if (vring->callfd != -1) {
            VNFC_DBG_PRINT("Close the old callfd: %d\n", vring->callfd);
            close(vring->callfd);
        }

        assert(msg->nr_fds == 1);
        vring->callfd = msg->fds[0];

        VNFC_DBG_PRINT("Got a callfd %d\n", vring->callfd);
    }

    return false;
}


static bool vhu_set_vring_err(struct vhu_server *server, struct vhu_message *msg)
{
    VNFC_ERR_PRINT("Not implemented\n");

    return false;
}


static bool vhu_get_proto_features(struct vhu_server *server,
                                   struct vhu_message *msg)
{
    msg->payload.u64 = 0; /* No features */
    msg->payload_len = sizeof(msg->payload.u64);

    return true;
}


static bool vhu_set_proto_features(struct vhu_server *server,
                                   struct vhu_message *msg)
{
    VNFC_DBG_PRINT("Not implemented\n");

    return false;
}


static bool vhu_get_queue_num(struct vhu_server *server,
                              struct vhu_message *msg)
{
    VNFC_DBG_PRINT("Not implemented\n");

    return false;
}


static bool vhu_set_vring_enable(struct vhu_server *server,
                                 struct vhu_message *msg)
{
    VNFC_DBG_PRINT("Not implemented\n");

    return false;
}


vhu_msg_handler_t vhu_msg_handlers[VHOST_USER_MAX] = {
    NULL,                      // VHOST_USER_NONE
    vhu_get_features,          // VHOST_USER_GET_FEATURES
    vhu_set_features,          // VHOST_USER_SET_FEATURES
    vhu_set_owner,             // VHOST_USER_SET_OWNER
    vhu_reset_owner,           // VHOST_USER_RESET_OWNER
    vhu_set_mem_table,         // VHOST_USER_SET_MEM_TABLE
    vhu_set_log_base,          // VHOST_USER_SET_LOG_BASE
    vhu_set_log_fd,            // VHOST_USER_SET_LOG_FD
    vhu_set_vring_num,         // VHOST_USER_SET_VRING_NUM
    vhu_set_vring_addr,        // VHOST_USER_SET_VRING_ADDR
    vhu_set_vring_base,        // VHOST_USER_SET_VRING_BASE
    vhu_get_vring_base,        // VHOST_USER_GET_VRING_BASE
    vhu_set_vring_kick,        // VHOST_USER_SET_VRING_KICK
    vhu_set_vring_call,        // VHOST_USER_SET_VRING_CALL
    vhu_set_vring_err,         // VHOST_USER_SET_VRING_ERR
    vhu_get_proto_features,    // VHOST_USER_GET_PROTOCOL_FEATURES
    vhu_set_proto_features,    // VHOST_USER_SET_PROTOCOL_FEATURES
    vhu_get_queue_num,         // VHOST_USER_GET_QUEUE_NUM
    vhu_set_vring_enable,      // VHOST_USER_SET_VRING_ENABLE
};
