/*
 * debug.c
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

#include <stdio.h>
#include <inttypes.h>
#include "vhu/vring.h"
#include "vhu/proto.h"
#include "vhu/debug.h"

const char *get_vhostmsg_name(const struct vhu_message *msg)
{
    switch (msg->type) {
    case VHOST_USER_NONE:
        return "VHOST_USER_NONE";
    case VHOST_USER_GET_FEATURES:
        return "VHOST_USER_GET_FEATURES";
    case VHOST_USER_SET_FEATURES:
        return "VHOST_USER_SET_FEATURES";
    case VHOST_USER_SET_OWNER:
        return "VHOST_USER_SET_OWNER";
    case VHOST_USER_RESET_OWNER:
        return "VHOST_USER_RESET_OWNER";
    case VHOST_USER_SET_MEM_TABLE:
        return "VHOST_USER_SET_MEM_TABLE";
    case VHOST_USER_SET_LOG_BASE:
        return "VHOST_USER_SET_LOG_BASE";
    case VHOST_USER_SET_LOG_FD:
        return "VHOST_USER_SET_LOG_FD";
    case VHOST_USER_SET_VRING_NUM:
        return "VHOST_USER_SET_VRING_NUM";
    case VHOST_USER_SET_VRING_ADDR:
        return "VHOST_USER_SET_VRING_ADDR";
    case VHOST_USER_SET_VRING_BASE:
        return "VHOST_USER_SET_VRING_BASE";
    case VHOST_USER_GET_VRING_BASE:
        return "VHOST_USER_GET_VRING_BASE";
    case VHOST_USER_SET_VRING_KICK:
        return "VHOST_USER_SET_VRING_KICK";
    case VHOST_USER_SET_VRING_CALL:
        return "VHOST_USER_SET_VRING_CALL";
    case VHOST_USER_SET_VRING_ERR:
        return "VHOST_USER_SET_VRING_ERR";
    case VHOST_USER_GET_PROTOCOL_FEATURES:
        return "VHOST_USER_GET_PROTOCOL_FEATURES";
    case VHOST_USER_SET_PROTOCOL_FEATURES:
        return "VHOST_USER_SET_PROTOCOL_FEATURES";
    case VHOST_USER_GET_QUEUE_NUM:
        return "VHOST_USER_GET_QUEUE_NUM";
    case VHOST_USER_SET_VRING_ENABLE:
        return "VHOST_USER_SET_VRING_ENABLE";
    case VHOST_USER_SEND_RARP:
        return "VHOST_USER_SEND_RARP";
    case VHOST_USER_MAX:
        return "VHOST_USER_MAX";
    }

    return "UNDEFINED";
}


void dump_vhostmsg(const struct vhu_message *msg)
{
    int i;

    printf("................................................................................\n");
    printf("Type: %s (0x%x)\n", get_vhostmsg_name(msg), msg->type);
    printf("Flags: 0x%x\n", msg->flags);

    switch (msg->type) {
    case VHOST_USER_GET_FEATURES:
    case VHOST_USER_SET_FEATURES:
    case VHOST_USER_SET_LOG_BASE:
    case VHOST_USER_SET_VRING_KICK:
    case VHOST_USER_SET_VRING_CALL:
    case VHOST_USER_SET_VRING_ERR:
        printf("u64: 0x%"PRIx64"\n", msg->payload.u64);
        break;
    case VHOST_USER_SET_MEM_TABLE:
        printf("nr_regions: %d\n", msg->payload.memory.nr_regions);
        for (i = 0; i < msg->payload.memory.nr_regions; i++) {
            printf("region: \n"
                   "\tguest phys addr = 0x%"PRIX64"\n"
                   "\tmemory size     = %"PRId64"\n"
                   "\tuserspace addr  = 0x%"PRIx64"\n"
                   "\tshm offset      = 0x%"PRIx64"\n",
                   msg->payload.memory.regions[i].guest_phys_addr,
                   msg->payload.memory.regions[i].memory_size,
                   msg->payload.memory.regions[i].userspace_addr,
                   msg->payload.memory.regions[i].shm_offset);
        }
        break;
    case VHOST_USER_SET_VRING_NUM:
    case VHOST_USER_SET_VRING_BASE:
    case VHOST_USER_GET_VRING_BASE:
        printf("state: %d %d\n", msg->payload.state.index,
                                 msg->payload.state.num);
        break;
    case VHOST_USER_SET_VRING_ADDR:
        printf("addr:\n\tidx = %d\n\tflags = 0x%x\n"
               "\tdesc user addr  = 0x%"PRIx64"\n"
               "\tused user addr  = 0x%"PRIx64"\n"
               "\tavail user addr = 0x%"PRIx64"\n"
               "\tlog guest addr  = 0x%"PRIx64"\n",
               msg->payload.addr.index, msg->payload.addr.flags,
               msg->payload.addr.desc_user_addr, msg->payload.addr.used_user_addr,
               msg->payload.addr.avail_user_addr, msg->payload.addr.log_guest_addr);
        break;
    default:
        break;
    }
}


void dump_buffer(const uint8_t *buf, size_t len)
{
    int i;

    printf("................................................................................");

    for (i = 0; i < len; i++) {
        if (i % 16 == 0) {
            printf("\n");
        }
        printf("%.2x ", buf[i]);
    }

    printf("\n");
}


void dump_vring(const struct vhu_vring *vring)
{
    int i;

    printf("desc: [addr] [len] [flags] [next]\n");

    for (i = 0; i < VRING_NUM(vring); i++) {
        printf("%d: 0x%"PRIx64" %d 0x%x %d\n",
                i,
                (uint64_t)vring->vring.desc[i].addr, vring->vring.desc[i].len,
                vring->vring.desc[i].flags, vring->vring.desc[i].next);
    }
#if 0
    printf("avail:\n");
    for (i = 0; i < VRING_NUM(vring); i++) {
       int desc_idx = vring->vring.avail->ring[i];
       printf("%d: %d\n", i, desc_idx);

       dump_buffer((uint8_t*)vring->vring.desc[desc_idx].addr,
                   vring->vring.desc[desc_idx].len);
    }
#endif
}
