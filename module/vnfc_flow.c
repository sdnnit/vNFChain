/*
 * vnfc_flow.c : Flow handling of vNFCModule
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

#include <linux/rcupdate.h>
#include "vnfc.h"
#include "vnfc_flow.h"

#define VNFC_FLOW_EXPIRE		(3 * HZ)


static inline u32 vnfc_hashfn(u32 rxhash)
{
    return rxhash & 0x3ff;
}


static struct vnfc_flow_entry *vnfc_flow_create(struct vnfc_struct *vnfc,
                                                u32 rxhash, u16 queue_index)
{
    struct vnfc_flow_entry *entry = kmalloc(sizeof(*entry), GFP_ATOMIC);

    if (entry) {
        struct hlist_head *head = &vnfc->flows[vnfc_hashfn(rxhash)];

        pr_debug("[%s] create flow: hash %u index %u\n",
                 DRV_NAME, rxhash, queue_index);
        entry->updated     = jiffies;
        entry->rxhash      = rxhash;
        entry->queue_index = queue_index;
        entry->vnfc       = vnfc;
        hlist_add_head_rcu(&entry->hash_link, head);
        vnfc->flow_count++;
    }
    return entry;
}


static void vnfc_flow_delete(struct vnfc_struct *vnfc,
                             struct vnfc_flow_entry *entry)
{
    pr_debug("[%s] delete flow: hash %u index %u\n",
             DRV_NAME, entry->rxhash, entry->queue_index);
    hlist_del_rcu(&entry->hash_link);
    kfree_rcu(entry, rcu);
    vnfc->flow_count--;
}


static void vnfc_flow_flush(struct vnfc_struct *vnfc)
{
    int i;

    spin_lock_bh(&vnfc->lock);
    for (i = 0; i < VNFC_FLOW_ENTRIES; i++) {
        struct vnfc_flow_entry *entry;
        struct hlist_node *n;

        hlist_for_each_entry_safe(entry, n, &vnfc->flows[i], hash_link) {
            vnfc_flow_delete(vnfc, entry);
        }
    }
    spin_unlock_bh(&vnfc->lock);
}


static void vnfc_flow_cleanup(unsigned long data)
{
    struct vnfc_struct *vnfc = (struct vnfc_struct *)data;
    unsigned long delay = vnfc->ageing_time;
    unsigned long next_timer;
    unsigned long count;
    int i;

    pr_debug("[%s] vnfc_flow_cleanup\n", DRV_NAME);

    spin_lock_bh(&vnfc->lock);

    next_timer = jiffies  + delay;
    count = 0;
    for (i = 0; i < VNFC_FLOW_ENTRIES; i++) {
        struct vnfc_flow_entry *entry;
        struct hlist_node *n;

        hlist_for_each_entry_safe(entry, n, &vnfc->flows[i], hash_link) {
            unsigned long this_timer;
            this_timer = entry->updated + delay;
            if (time_before_eq(this_timer, jiffies)) {
                vnfc_flow_delete(vnfc, entry);
            } else if (time_before(this_timer, next_timer)) {
                next_timer = this_timer;
            }
            count++;
        }
    }

    if (count) {
        mod_timer(&vnfc->flow_gc_timer, round_jiffies_up(next_timer));
    }

    spin_unlock_bh(&vnfc->lock);
}


extern void vnfc_flow_delete_by_queue(struct vnfc_struct *vnfc,
                                      u16 queue_index)
{
    int i;

    spin_lock_bh(&vnfc->lock);
    for (i = 0; i < VNFC_FLOW_ENTRIES; i++) {
        struct vnfc_flow_entry *entry;
        struct hlist_node *n;

        hlist_for_each_entry_safe(entry, n, &vnfc->flows[i], hash_link) {
            if (entry->queue_index == queue_index) {
                vnfc_flow_delete(vnfc, entry);
            }
        }
    }
    spin_unlock_bh(&vnfc->lock);
}


extern void vnfc_flow_update(struct vnfc_struct *vnfc, u32 rxhash,
                             struct vnfc_file *cfile)
{
    struct vnfc_flow_entry *entry;
    unsigned long delay = vnfc->ageing_time;

    if (!rxhash) {
        return;
    }

    rcu_read_lock();

    /* We may get a very small possibility of OOO during switching, not
     * worth to optimize.*/
    if (vnfc->nr_queues == 1 || cfile->detached) {
        goto unlock;
    }

    entry = vnfc_flow_find(vnfc, rxhash);
    if (likely(entry)) {
        /* TODO: keep queueing to old queue until it's empty? */
        entry->queue_index = cfile->queue_index;
        entry->updated     = jiffies;
    } else {
        spin_lock_bh(&vnfc->lock);

        if (!vnfc_flow_find(vnfc, rxhash) &&
            vnfc->flow_count < MAX_VNFC_FLOWS) {
            vnfc_flow_create(vnfc, rxhash, cfile->queue_index);
        }
        if (!timer_pending(&vnfc->flow_gc_timer)) {
            mod_timer(&vnfc->flow_gc_timer,
                      round_jiffies_up(jiffies + delay));
        }
        spin_unlock_bh(&vnfc->lock);
    }

unlock:
    rcu_read_unlock();
}


extern struct vnfc_flow_entry *vnfc_flow_find(struct vnfc_struct *vnfc,
                                              u32 rxhash)
{
    struct vnfc_flow_entry *entry;
    struct hlist_head *head;

    head = &vnfc->flows[vnfc_hashfn(rxhash)];

    hlist_for_each_entry_rcu(entry, head, hash_link) {
        if (entry->rxhash == rxhash) {
            return entry;
        }
    }
    return NULL;
}


extern int vnfc_flow_init(struct vnfc_struct *vnfc)
{
    int i;

    for (i = 0; i < VNFC_FLOW_ENTRIES; i++) {
        INIT_HLIST_HEAD(&vnfc->flows[i]);
    }

    vnfc->ageing_time = VNFC_FLOW_EXPIRE;
    setup_timer(&vnfc->flow_gc_timer, vnfc_flow_cleanup, (unsigned long)vnfc);
    mod_timer(&vnfc->flow_gc_timer,
              round_jiffies_up(jiffies + vnfc->ageing_time));

    return 0;
}


extern void vnfc_flow_uninit(struct vnfc_struct *vnfc)
{
    del_timer_sync(&vnfc->flow_gc_timer);
    vnfc_flow_flush(vnfc);
}
