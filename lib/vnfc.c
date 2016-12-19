/*
 * vnfc.c : Main body of vNFCLib
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/un.h>

#include "if_vnfc.h"
#include "vnfc.h"
#include "vnfc_utils.h"
#include "vnfc_pktpool.h"
#include "vnfc_packet.h"
#include "utils/print.h"
#include "utils/socket.h"
#include "utils/poll.h"
#include "utils/objpool.h"
#include "vhu/server.h"

#ifdef USE_DPDK
#include "dpdk/dpdk.h"
#include "dpdk/ring_client.h"
#endif

VNFC_DEFINE_PRINT_MODULE("vnfc");

#ifdef FAKE_TUN
static const char *VNFC_DEVICE = "/dev/net/tun";
#else
static const char *VNFC_DEVICE = "/dev/net/vnfc";
#endif

static struct vnfc *g_vnfc;


/*******************************************************************************
* Signal settings
*******************************************************************************/

static void sig_handler(int sig, siginfo_t *info, void *unused)
{
    pid_t pid;
    int flags;

    pid   = info->si_int & 0xFFFF;
    flags = (info->si_int >> 16) & 0xFFFF;

    if (pid == 0xFFFF) {
        pid = -1;
    }

    VNFC_DBG_PRINT("Got a signal: pid = %d, flags = %X\n", pid, flags);

    if ((!(flags & SERVICE_UPSTREAM) && !(flags & SERVICE_DOWNSTREAM)) ||
        ((flags & SERVICE_UPSTREAM) && (flags & SERVICE_DOWNSTREAM))) {
        VNFC_ERR_PRINT("Direction is not given\n");
        return ;
    }

    if (! g_vnfc) {
        VNFC_ERR_PRINT("The global svc has not been set\n");
        return ;
    }

    if (flags & SERVICE_UPSTREAM) {
        if (g_vnfc->clt_up) {
            sock_client_exit(g_vnfc->clt_up);
            g_vnfc->clt_up = NULL;
        }
        if (pid > 0) {
            g_vnfc->need_to_connect_up = true;
            g_vnfc->pid_to_up = pid;
        } else {
            g_vnfc->need_to_connect_up = false;
            g_vnfc->pid_to_up = -1;
        }
    } else {
        if (g_vnfc->clt_down) {
            sock_client_exit(g_vnfc->clt_down);
            g_vnfc->clt_down = NULL;
        }
        if (pid > 0) {
            g_vnfc->need_to_connect_down = true;
            g_vnfc->pid_to_down = pid;
        } else {
            g_vnfc->need_to_connect_down = false;
            g_vnfc->pid_to_down = -1;
        }
    }

    /* TODO: VHU and DPDK Ring handling */
}


static bool init_signal(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = sig_handler;
    sa.sa_flags     = SA_SIGINFO;

    if (sigaction(SIG_VNFCHAIN, &sa, NULL) < 0) {
        VNFC_PERROR("sigaction (init_signal)");
        return false;
    }

    return true;
}


/*******************************************************************************
* Init/Exit functions
*******************************************************************************/

static void vnfc_pktpool_exit(struct vnfc *vnfc)
{
    if (vnfc->pool) {
        pktpool_exit(vnfc->pool, is_singular(vnfc));
        vnfc->pool = NULL;
    }
}


static bool vnfc_pktpool_init(struct vnfc *vnfc, const char *dev_name)
{
    struct vnfc_pktpool *pool;

    pool = pktpool_init(dev_name);
    if (! pool) {
        VNFC_ERR_PRINT("Can't init the packet pool\n");
        return NULL;
    }

    vnfc->pool = pool;

    return true;
}


static void close_server_socket(struct vnfc *vnfc, struct sock_server *svr)
{
    if (vnfc->poll) {
        if (svr->is_stream && svr->svr_sock != -1) {
            poll_delete_fd(vnfc->poll, svr->svr_sock);
        }
        if (svr->sock != -1) {
            poll_delete_fd(vnfc->poll, svr->sock);
        }
    }
    sock_server_exit(svr);
}


static void vnfc_socket_exit(struct vnfc *vnfc)
{
    if (vnfc->svr_up) {
        close_server_socket(vnfc, vnfc->svr_up);
        vnfc->svr_up = NULL;
    }
    if (vnfc->svr_down) {
        close_server_socket(vnfc, vnfc->svr_down);
        vnfc->svr_down = NULL;
    }
    if (vnfc->clt_up) {
        sock_client_exit(vnfc->clt_up);
        vnfc->clt_up = NULL;
    }
    if (vnfc->clt_down) {
        sock_client_exit(vnfc->clt_down);
        vnfc->clt_down = NULL;
    }
}


static struct sock_server *open_server_socket(bool upstream, bool is_stream)
{
    struct sock_server *server;
    char path[UNIX_PATH_MAX];

    vnfc_make_sock_path(path, getpid(), upstream);
    server = sock_server_init(path, is_stream);
    if (! server) {
        VNFC_ERR_PRINT("Can't open the server socket (%s)\n",
                        (upstream) ? "upstream" : "downstream");
    }

    return server;
}


static bool vnfc_socket_init(struct vnfc *vnfc, bool is_stream)
{
    struct sock_server *svr_up;
    struct sock_server *svr_down;

    /* Open a server socket for upstream */
    svr_up = open_server_socket(true, is_stream);
    if (! svr_up) {
        return false;
    }

    /* Open a server socket for downstream */
    svr_down = open_server_socket(false, is_stream);
    if (! svr_down) {
        goto exit_up;
    }

    /* Setup polling events */

    if (! poll_add_fd(vnfc->poll,
                      (is_stream) ? svr_up->svr_sock : svr_up->sock)) {
        goto exit_down;
    }
    if (! poll_add_fd(vnfc->poll,
                      (is_stream) ? svr_down->svr_sock : svr_down->sock)) {
        goto delete_poll_fd;
    }

    vnfc->svr_up   = svr_up;
    vnfc->svr_down = svr_down;

    return true;

delete_poll_fd:
    poll_delete_fd(vnfc->poll, (is_stream) ? svr_up->svr_sock : svr_up->sock);

exit_down:
    sock_server_exit(svr_down);

exit_up:
    sock_server_exit(svr_up);

    return false;
}


static void vnfc_poll_exit(struct vnfc *vnfc)
{
    if (vnfc->poll) {
        poll_exit(vnfc->poll);
        vnfc->poll = NULL;
    }
}


static bool vnfc_poll_init(struct vnfc *vnfc)
{
    vnfc->poll = poll_init();
    if (! vnfc->poll) {
        return false;
    }

    return true;
}


static void vnfc_vhu_exit(struct vnfc *vnfc)
{
    if (! vnfc->vhu) {
        return ;
    }

    if (vnfc->poll) {
        int svr_sock = vhu_get_server_socket(vnfc->vhu);
        int msg_sock = vhu_get_message_socket(vnfc->vhu);

        if (msg_sock != -1) {
            int data_sock = vhu_get_data_socket(vnfc->vhu);

            poll_delete_fd(vnfc->poll, msg_sock);
            if (data_sock != -1) {
                poll_delete_fd(vnfc->poll, data_sock);
            }
        } else if (svr_sock != -1) {
            poll_delete_fd(vnfc->poll, svr_sock);
        }
    }

    vhu_server_exit(vnfc->vhu);
    vnfc->vhu = NULL;

    VNFC_PRINT("The VHU server stopped\n");
}


static bool vnfc_vhu_init(struct vnfc *vnfc, const char *dev_name)
{
    VNFC_PRINT("Launching the VHU server...\n");

    vnfc->vhu = vhu_server_init(dev_name);
    if (! vnfc->vhu) {
        return false;
    }

    if (! poll_add_fd(vnfc->poll, vhu_get_server_socket(vnfc->vhu))) {
        vnfc_vhu_exit(vnfc);
        return false;
    }

    return true;
}


void vnfc_vhu_restart(struct vnfc *vnfc)
{
    if (! is_vhu_server(vnfc)) {
        return ;
    }

    VNFC_PRINT("Restarting the VHU server...\n");

    vnfc_vhu_exit(vnfc);

    if (! vnfc_vhu_init(vnfc, vnfc->dev_name)) {
        VNFC_ERR_PRINT("Can't restart the VHU server\n");
        return ;
    }

    VNFC_PRINT("Done\n");
}

#ifdef USE_DPDK
static void vnfc_dpdk_exit(void)
{

}


static bool vnfc_dpdk_init(void)
{
    char *argv[] = { "vnfc", "--proc-type=secondary", NULL };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    if (! dpdk_init(argc, argv)) {
        return false;
    }

    return true;
}


static void vnfc_dpdk_ring_exit(struct vnfc *vnfc)
{
    if (vnfc->ring) {
        ring_client_exit(vnfc->ring);
    }
    vnfc->ring = NULL;
}


static bool vnfc_dpdk_ring_init(struct vnfc *vnfc, uint32_t client_id)
{
    vnfc->ring = ring_client_init(client_id);
    if (! vnfc->ring) {
        return false;
    }

    return true;
}
#endif


static bool vnfc_attach_impl(struct vnfc *vnfc, const char *svc_name,
                             const char *dev_name, uint64_t flags)
{
    struct vnfc_req req;
    int err;

    /* Open an fd of vNFCModule for Rx */
    vnfc->fd_vnfc_in = open(VNFC_DEVICE, O_RDONLY);
    if (vnfc->fd_vnfc_in < 0) {
        VNFC_PERROR("open (fd_vnfc_in)");
        return false;
    }

    /* Open an fd of vNFCModule for Tx */
    vnfc->fd_vnfc_out = open(VNFC_DEVICE, O_WRONLY);
    if (vnfc->fd_vnfc_out < 0) {
        VNFC_PERROR("open (fd_vnfc_out)");
        goto close_in;
    }

    memset(&req, 0, sizeof(req));

    strcpy(req.svc_name, svc_name);
    strcpy(req.dev_name, dev_name);
    req.pid = getpid();

    if (flags & VNFC_UPSTREAM) {
        req.flags |= SERVICE_UPSTREAM;
    }
    if (flags & VNFC_DOWNSTREAM) {
        req.flags |= SERVICE_DOWNSTREAM;
    }
    if (! req.flags) {
        VNFC_ERR_PRINT("Service direction is not specified\n");
        goto close_out;
    }

    /* Set the read fd to receive only */
    req.flags |= SERVICE_INPUT_FILE;
    err = ioctl(vnfc->fd_vnfc_in, VNFC_SET_SERVICE, (void*)&req);
    if (err < 0) {
        VNFC_PERROR("ioctl (fd_vnfc_in)");
        goto close_out;
    }

    /* Set the write fd to write only */
    req.flags ^= SERVICE_INPUT_FILE;
    req.flags |= SERVICE_OUTPUT_FILE;
    err = ioctl(vnfc->fd_vnfc_out, VNFC_SET_SERVICE, (void*)&req);
    if (err < 0) {
        VNFC_PERROR("ioctl (fd_vnfc_out)");
        goto close_out;
    }

    strcpy(vnfc->svc_name, svc_name);
    strcpy(vnfc->dev_name, dev_name);
    vnfc->flags = flags;

    /* Start the polling to the read fd */
    if (! poll_add_fd(vnfc->poll, vnfc->fd_vnfc_in)) {
        goto close_out;
    }

    return true;

close_out:
    close(vnfc->fd_vnfc_out);
    vnfc->fd_vnfc_out = -1;

close_in:
    close(vnfc->fd_vnfc_in);
    vnfc->fd_vnfc_in = -1;

    return false;
}


static void init_vnfc(struct vnfc *vnfc)
{
    memset(vnfc, 0, sizeof(*vnfc));
    vnfc->fd_vnfc_in    = -1;
    vnfc->fd_vnfc_out   = -1;
    vnfc->pid_to_up      = -1;
    vnfc->pid_to_down    = -1;
}


struct vnfc *vnfc_attach(const char *svc_name, const char *dev_name,
                         uint64_t flags)
{
    struct vnfc *vnfc;

    if (! svc_name || (strlen(svc_name) >= IF_NAMESIZE)) {
        VNFC_ERR_PRINT("Invalid service name: %s\n", svc_name);
        goto err;
    }
    if (! dev_name || (strlen(dev_name) >= IF_NAMESIZE)) {
        VNFC_ERR_PRINT("Invalid device name: %s\n", dev_name);
        goto err;
    }
    if (! (flags & VNFC_BIDIRECTION)) {
        VNFC_ERR_PRINT("Invalid service direction\n");
        goto err;
    }

#ifdef USE_DPDK
    if (flags & VNFC_DPDK_RING) {
        if (! vnfc_dpdk_init()) {
            goto err;
        }
    }
#endif

    vnfc = (struct vnfc*)malloc(sizeof(struct vnfc));
    if (! vnfc) {
        VNFC_ERR_PRINT("Can't allocate memory for struct vnfc\n");
        goto err;
    }

    init_vnfc(vnfc);

    g_vnfc = vnfc;

    if (! init_signal()) {
        goto free_svc;
    }

    if (! vnfc_pktpool_init(vnfc, dev_name)) {
        goto free_svc;
    }

    if (! vnfc_poll_init(vnfc)) {
        goto exit_pktpool;
    }

    if (! vnfc_attach_impl(vnfc, svc_name, dev_name, flags)) {
        goto exit_poll;
    }

    if (! vnfc_socket_init(vnfc, false)) {
        goto exit_poll;
    }

    sleep(1); /* Waiting for a signal interrupt from the device */

    if (is_last_down(vnfc)) {
        if ((flags & VNFC_BIDIRECTION) != VNFC_BIDIRECTION) {
            VNFC_ERR_PRINT("VNFC_BIDIRECTION must be specified for VHU\n");
            goto exit_socket;
        }
        if (! vnfc_vhu_init(vnfc, dev_name)) {
            goto exit_socket;
        }
    }

#ifdef USE_DPDK
    if (flags & VNFC_DPDK_RING) {
        if (! is_last_up(vnfc)) {
            VNFC_ERR_PRINT("VNFC_BIDIRECTION must be specified for DPDK Ring\n");
            goto exit_vhu;
        }
        if (! vnfc_dpdk_ring_init(vnfc, 0)) {
            goto exit_vhu;
        }
    }
#endif

    VNFC_PRINT("Attached a new service: %s (%s), %d\n",
                vnfc->svc_name, vnfc->dev_name, getpid());

    return vnfc;

#ifdef USE_DPDK
exit_vhu:
    vnfc_vhu_exit(vnfc);
#endif
exit_socket:
    vnfc_socket_exit(vnfc);
exit_poll:
    poll_exit(vnfc->poll);
exit_pktpool:
    vnfc_pktpool_exit(vnfc);
free_svc:
    free(vnfc);
err:
#ifdef USE_DPDK
    if (get_dpdk()) {
        vnfc_dpdk_exit();
    }
#endif
    return NULL;
}


static void vnfc_detach_impl(struct vnfc *vnfc)
{
    struct vnfc_req req;

    if (vnfc->poll) {
        poll_delete_fd(vnfc->poll, vnfc->fd_vnfc_in);
    }

    memset(&req, 0, sizeof(req));
    memcpy(req.svc_name, vnfc->svc_name, IF_NAMESIZE);
    memcpy(req.dev_name, vnfc->dev_name, IF_NAMESIZE);
    req.flags = SERVICE_DETACH;

    /* Close the input file */
    if (vnfc->fd_vnfc_in != -1) {
        if (ioctl(vnfc->fd_vnfc_in, VNFC_SET_SERVICE, (void*)&req) < 0) {
            VNFC_PERROR("ioctl (fd_vnfc_in)");
        }
        close(vnfc->fd_vnfc_in);
    }

    /* Close the output file */
    if (vnfc->fd_vnfc_out != -1) {
        if (ioctl(vnfc->fd_vnfc_out, VNFC_SET_SERVICE, (void*)&req) < 0) {
            VNFC_PERROR("ioctl (fd_vnfc_out)");
        }
        close(vnfc->fd_vnfc_out);
    }
}


void vnfc_detach(struct vnfc *vnfc)
{
    if (! vnfc) {
        return ;
    }

    VNFC_PRINT("Detach the service: %s (%s), %d\n",
                vnfc->svc_name, vnfc->dev_name, getpid());

    g_vnfc = NULL;

    vnfc_detach_impl(vnfc);

    if (is_vhu_server(vnfc)) {
        vnfc_vhu_exit(vnfc);
    }

    vnfc_socket_exit(vnfc);

    vnfc_poll_exit(vnfc);

    vnfc_pktpool_exit(vnfc);

#ifdef USE_DPDK
    if (vnfc->ring) {
        vnfc_dpdk_ring_exit(vnfc);
    }
    if (get_dpdk()) {
        vnfc_dpdk_exit();
    }
#endif

    init_vnfc(vnfc);

    free(vnfc);
}
