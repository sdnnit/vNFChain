/*
 * vnfc.h : Definitions of main structures for vNFCModule
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

#ifndef __VNFC_H__
#define __VNFC_H__

#include <linux/version.h>
#include <linux/list.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
#include <linux/skb_array.h>
#endif
#include <net/sock.h>
#include "if_vnfc.h"

#define DRV_NAME                       "vnfc"
#define DRV_VERSION                    "1.0"
#define DRV_DESCRIPTION                "vNFChain - A virtual network function chain"
#define DRV_AUTHOR                     "Copyright 2015-17 Ryota Kawashima <kawa1983@ieee.org>"

#define VNFC_MINOR                     201

#define MAX_VNFC_QUEUES                DEFAULT_MAX_NUM_RSS_QUEUES
#define MAX_VNFC_FLOWS                 4096

#define VNFC_FLOW_ENTRIES              1024


struct vnfc_struct;
struct vnfc_service;

/* A vnfc file that supports file I/O from the userspace */
struct vnfc_file
{
    struct sock                sk;           /* Must be first member */
    struct socket              socket;       /* Socket for the user process */
    struct socket_wq           wq;
    struct vnfc_struct __rcu  *vnfc;         /* vnfc device */
    struct net                *net;          /* Network namespace */

    /* For asynchronous I/O */
    struct fasync_struct      *fasync;
    unsigned int               flags;        /* VNFC_FASYNC */

    union {
        u16                    queue_index;
        unsigned int           ifindex;
    };
    struct list_head           next;
    struct vnfc_struct        *detached;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
    struct skb_array           tx_array;
#endif

    /* For vnfc service */
    struct vnfc_service       *service;      /* vnfc service */
};


/* vnfc service */
struct vnfc_service
{
    struct vnfc_file  *vfile_to_svc;    /* vnfc file (to the service) */
    struct vnfc_file  *vfile_from_svc;  /* vnfc file (from the service) */
    pid_t              pid;             /* Process ID of the service */
    char               name[IFNAMSIZ];  /* Service name */
    unsigned int       flags;           /* Service settings */
    struct list_head   list;
    struct list_head   list_up;
    struct list_head   list_down;
};


/* vnfc device */
struct vnfc_struct
{
    struct vnfc_file __rcu  *vfile_vms[MAX_VNFC_QUEUES];   /* vnfc file (VM) */
    unsigned int             nr_queues;
    unsigned int             flags;

    struct list_head         services;                     /* vnfc services (All) */
    struct list_head         services_up;                  /* vnfc services (Upstream) */
    struct list_head         services_down;                /* vnfc services (Downstream) */

    kuid_t                   owner;                        /* Current owner */
    kgid_t                   group;                        /* Current group */

    struct net_device       *dev;                          /* Network device */
    netdev_features_t        set_features;                 /* Supported features */

    int                      sndbuf;                       /* Send buffer size */
    int                      vnet_hdr_sz;                  /* virtio_net_hdr size */

    spinlock_t               lock;
    struct hlist_head        flows[VNFC_FLOW_ENTRIES];     /**/
    struct timer_list        flow_gc_timer;
    u32                      flow_count;
    unsigned long            ageing_time;

    struct list_head         disabled;
    unsigned int             nr_disabled;
};


struct vnfc_struct *vnfc_get(struct vnfc_file *cfile);
void                vnfc_put(struct vnfc_struct *vnfc);
int                 vnfc_attach(struct vnfc_struct *vnfc,
                                struct vnfc_file *cfile);
void                __vnfc_detach(struct vnfc_file *cfile, bool clean);
void                vnfc_detach(struct vnfc_file *cfile, bool clean);
void                vnfc_detach_all(struct net_device *dev);

#endif /* __IF_VNFC_H__ */
