/*
 * vnfc_utils.c
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

#include <string.h>
#include <time.h>

#include "vnfc.h"
#include "vnfc_pktpool.h"
#include "vnfc_packet.h"
#include "vnfc_utils.h"
#include "utils/print.h"
#include "utils/socket.h"
#include "utils/poll.h"

VNFC_DEFINE_PRINT_MODULE("vnfc");


/*******************************************************************************
* Predicate functions
*******************************************************************************/

inline bool need_to_connect(const struct vnfc *vnfc)
{
    return (vnfc->need_to_connect_up || vnfc->need_to_connect_down);
}


inline bool is_singular(const struct vnfc *vnfc)
{
    return (!vnfc->clt_up && !vnfc->clt_down && !need_to_connect(vnfc));
}


inline bool is_last_up(const struct vnfc *vnfc)
{
    return (!vnfc->clt_up && !vnfc->need_to_connect_up);
}


inline bool is_last_down(const struct vnfc *vnfc)
{
    return (!vnfc->clt_down && !vnfc->need_to_connect_down);
}


inline bool is_vhu_server(const struct vnfc *vnfc)
{
    return (vnfc->vhu);
}

#ifdef USE_DPDK
inline bool is_ring_client(const struct vnfc *vnfc)
{
    return (vnfc->ring);
}
#endif


/*******************************************************************************
* Utility functions
*******************************************************************************/

inline void vnfc_memcpy(uint8_t *to, const uint8_t *from, size_t len)
{
#if USE_DPDK
    rte_memcpy(to, from, len);
#else
    memcpy(to, from, len);
#endif
}


static const char *SOCKET_PATH = "/tmp/vnfclib";

inline void vnfc_make_sock_path(char *path, pid_t pid, bool upstream)
{
    sprintf(path, "%s_%d_%s.sock", SOCKET_PATH, pid, (upstream ? "up" : "down"));
}


bool alloc_packet_wait(struct vnfc *vnfc, struct vnfc_packet *packet, size_t len,
                       bool upstream, size_t times)
{
    struct timespec t = { 0, 10 * 1000 }; /* 10 us */
    uint32_t counter = 0;

    while (! pktpool_set_packet(vnfc->pool, packet, len, upstream)) {
        counter++;
        if (counter >= times) {
            return false;
        }
        nanosleep(&t, NULL);
    }

    return true;
}


bool reset_sock_server_polling(struct vnfc *vnfc, bool upstream)
{
    struct sock_server *server;

    if (upstream) {
        server = vnfc->svr_up;
    } else {
        server = vnfc->svr_down;
    }

    if (server->is_stream) {
        poll_delete_fd(vnfc->poll, server->sock);
        poll_add_fd(vnfc->poll, server->svr_sock);
    } else {
        /* TODO: Reset the UDP socket */
        VNFC_ERR_PRINT("Resetting the UDP socket hasn't been implemented\n");
    }

    return true;
}
