/*
 * vnfc_net.h
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

#ifndef __VNFC_NET_H__
#define __VNFC_NET_H__

/* Tx queue length */
#define VNFC_QUEUE_LEN  250000

extern struct net_device_ops vnfc_netdev_ops;
extern struct rtnl_link_ops  vnfc_link_ops;

struct net;
struct file;
struct ifreq;
struct vnfc_file;
struct vnfc_struct;

int vnfc_set_iff(struct net *net, struct vnfc_file *vfile, struct ifreq *ifr);
int vnfc_get_iff(struct net *net, struct vnfc_struct *vnfc, struct ifreq *ifr);

#endif /* __VNFC_NET_H__ */
