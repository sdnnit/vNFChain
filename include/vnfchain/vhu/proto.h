/*
 * proto.h
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

#ifndef __VNFC_LIB_VHU_PROTO_H__
#define __VNFC_LIB_VHU_PROTO_H__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The version of the protocol we support */
#define VHOST_USER_VERSION             (0x1)
#define VHOST_USER_VERSION_MASK        (0x3)
#define VHOST_USER_REPLY_MASK          (0x1 << 2)
#define VHOST_USER_VRING_IDX_MASK      (0xFF)
#define VHOST_USER_VRING_NOFD_MASK     (0x1 << 8)

typedef enum vhu_request_type {
    VHOST_USER_NONE                  = 0,
    VHOST_USER_GET_FEATURES          = 1,
    VHOST_USER_SET_FEATURES          = 2,
    VHOST_USER_SET_OWNER             = 3,
    VHOST_USER_RESET_OWNER           = 4,
    VHOST_USER_SET_MEM_TABLE         = 5,
    VHOST_USER_SET_LOG_BASE          = 6,
    VHOST_USER_SET_LOG_FD            = 7,
    VHOST_USER_SET_VRING_NUM         = 8,
    VHOST_USER_SET_VRING_ADDR        = 9,
    VHOST_USER_SET_VRING_BASE        = 10,
    VHOST_USER_GET_VRING_BASE        = 11,
    VHOST_USER_SET_VRING_KICK        = 12,
    VHOST_USER_SET_VRING_CALL        = 13,
    VHOST_USER_SET_VRING_ERR         = 14,
    VHOST_USER_GET_PROTOCOL_FEATURES = 15,
    VHOST_USER_SET_PROTOCOL_FEATURES = 16,
    VHOST_USER_GET_QUEUE_NUM         = 17,
    VHOST_USER_SET_VRING_ENABLE      = 18,
    VHOST_USER_SEND_RARP             = 19,
    VHOST_USER_MAX
} vhu_request_type;


typedef enum vhu_protocol_feature {
    VHOST_USER_PROTOCOL_F_MQ        = 0,
    VHOST_USER_PROTOCOL_F_LOG_SHMFD = 1,
    VHOST_USER_PROTOCOL_F_RARP      = 2,
    VHOST_USER_PROTOCOL_F_MAX
} vhu_protocol_feature;


#define VHOST_USER_F_PROTOCOL_FEATUERS   (30)
#define VHOST_USER_PROTOCOL_FEATURE_MASK ((1 << VOHST_USER_PROTOCOL_F_MAX) - 1)


enum {
    VHOST_MEMORY_MAX_NREGIONS = 8
};


// Structures imported from the Linux headers.
struct vhost_vring_state
{
    uint32_t index;
    uint32_t num;
};


struct vhost_vring_addr {
    uint32_t index;
    uint32_t flags;
    uint64_t desc_user_addr;
    uint64_t used_user_addr;
    uint64_t avail_user_addr;
    uint64_t log_guest_addr;
};


struct vhu_memory_region {
    uint64_t guest_phys_addr;
    uint64_t memory_size;
    uint64_t userspace_addr;
    uint64_t shm_offset;
};


struct vhu_memory
{
    uint32_t nr_regions;
    uint32_t padding;
    struct vhu_memory_region regions[VHOST_MEMORY_MAX_NREGIONS];
};


struct vhu_message {
    /* Header */
    vhu_request_type             type;
    uint32_t                     flags;
    uint32_t                     payload_len;

    /* Payload */
    union {
        uint64_t                 u64;
        struct vhost_vring_state state;
        struct vhost_vring_addr  addr;
        struct vhu_memory        memory;
    } payload;

    int fds[VHOST_MEMORY_MAX_NREGIONS];
    uint32_t nr_fds;
}  __attribute__((packed));


#define MEMB_SIZE(t,m)      (sizeof(((t*)0)->m))


struct vhu_server;
typedef bool (*vhu_msg_handler_t)(struct vhu_server *server,
                                  struct vhu_message *msg);

extern vhu_msg_handler_t vhu_msg_handlers[VHOST_USER_MAX];

ssize_t vhu_send_reply(int sock, struct vhu_message *msg);
ssize_t vhu_recv_message(int sock, struct vhu_message *msg);

#ifdef __cplusplus
}
#endif

#endif /* __VNFC_LIB_VHU_PROTO_H__ */
