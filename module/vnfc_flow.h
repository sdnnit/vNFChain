/*
 * vnfc_flow.h
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

#ifndef __VNFC_FLOW_H__
#define __VNFC_FLOW_H__

#include <linux/types.h>
#include "vnfc.h"

struct vnfc_flow_entry
{
    struct hlist_node   hash_link;
	struct vnfc_struct *vnfc;
	struct rcu_head     rcu;

	u32                 rxhash;
	int                 queue_index;
	unsigned long       updated;
};


int                     vnfc_flow_init(struct vnfc_struct *vnfc);
void                    vnfc_flow_uninit(struct vnfc_struct *vnfc);
struct vnfc_flow_entry *vnfc_flow_find(struct vnfc_struct *vnfc, u32 rxhash);
void                    vnfc_flow_update(struct vnfc_struct *vnfc, u32 rxhash,
                                         struct vnfc_file *cfile);
void                    vnfc_flow_delete_by_queue(struct vnfc_struct *vnfc,
                                                  u16 queue_index);

#endif /* __VNFC_FLOW_H__ */
