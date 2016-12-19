/*
 * vnfc_service.c : Management of μVNFs
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

#include <linux/sched.h>
#include "vnfc.h"
#include "vnfc_service.h"


static struct vnfc_struct *get_vnfc_by_name(struct net *net,
                                              const char *dev_name)
{
    struct net_device *dev;

    dev = __dev_get_by_name(net, dev_name);
    if (! dev) {
        return NULL;
    }
    return netdev_priv(dev);
}


static struct vnfc_service *get_service(struct vnfc_file *vfile,
                                        struct vnfc_req *req)
{
    struct vnfc_struct *vnfc;

    vnfc = get_vnfc_by_name(vfile->net, req->dev_name);
    if (vnfc) {
        struct vnfc_service *service;
        struct list_head *p;

        list_for_each(p, &vnfc->services) {
            service = list_entry(p, struct vnfc_service, list);
            if ((service->pid == req->pid) &&
                !strcmp(service->name, req->svc_name)) {
                return service;
            }
        }
    }
    return NULL;
}


static int service_send_signal(pid_t vnr, int value, int flag)
{
    struct pid *pid;
    struct siginfo sig;
    struct task_struct *task;

    memset(&sig, 0, sizeof(sig));
    sig.si_signo = SIG_VNFCHAIN;
    sig.si_code  = SI_QUEUE;
    sig.si_int   = value & 0xFFFF;

    if (flag == SERVICE_UPSTREAM) {
        sig.si_int |= (SERVICE_UPSTREAM << 16);
    } else if (flag == SERVICE_DOWNSTREAM) {
        sig.si_int |= (SERVICE_DOWNSTREAM << 16);
    }

    pid = find_get_pid(vnr);
    if (! pid) {
        return -ENODEV;
    }

    task = get_pid_task(pid, PIDTYPE_PID);
    if (! task) {
        return -ENODEV;
    }

    return send_sig_info(SIG_VNFCHAIN, &sig, task);
}


static int service_net_append(struct vnfc_file *vfile, const char *dev_name)
{
    struct vnfc_struct *vnfc;
    struct vnfc_service *service;
    struct vnfc_service *prev_up;
    struct vnfc_service *prev_down;

    vnfc = get_vnfc_by_name(vfile->net, dev_name);
    if (! vnfc) {
        return -EINVAL;
    }
    rcu_assign_pointer(vfile->vnfc, vnfc);

    service = vfile->service;
    prev_up = prev_down = NULL;

    if (! list_empty(&vnfc->services)) {
        if ((service->flags & SERVICE_UPSTREAM) &&
            !list_empty(&vnfc->services_up)) {
            prev_up = list_entry(vnfc->services_up.prev,
                                 struct vnfc_service, list_up);
        }
        if ((service->flags & SERVICE_DOWNSTREAM) &&
            !list_empty(&vnfc->services_down)) {
            prev_down = list_first_entry(&vnfc->services_down,
                                         struct vnfc_service, list_down);
        }
    }

    list_add_tail(&service->list, &vnfc->services);

    if (service->flags & SERVICE_UPSTREAM) {
        list_add_tail(&service->list_up, &vnfc->services_up);

        if (prev_up) {
            /* Notify to the previous service */
            service_send_signal(prev_up->pid, service->pid, SERVICE_UPSTREAM);
        }
    }
    if (service->flags & SERVICE_DOWNSTREAM) {
        list_add(&service->list_down, &vnfc->services_down);

        if (prev_down) {
            /* Notify to self */
            service_send_signal(service->pid, prev_down->pid,
                                SERVICE_DOWNSTREAM);
        }
    }

    return 0;
}


static void service_net_delete(struct vnfc_struct *vnfc,
                               struct vnfc_service *service)
{
    struct vnfc_service *prev_up;
    struct vnfc_service *prev_down;

    prev_up = prev_down = NULL;

    list_del(&service->list);

    if (service->flags & SERVICE_UPSTREAM) {
        if (! list_is_singular(&service->list_up) &&
            (vnfc->services_up.next != &service->list_up)) {
            prev_up = list_entry(service->list_up.prev,
                                 struct vnfc_service, list_up);
        }
        list_del(&service->list_up);
    }
    if (service->flags & SERVICE_DOWNSTREAM) {
        if (! list_is_singular(&service->list_down) &&
            (vnfc->services_down.next != &service->list_down)) {
            prev_down = list_entry(service->list_down.prev,
                                   struct vnfc_service, list_down);
        }
        list_del(&service->list_down);
    }

    if (list_empty(&vnfc->services)) {
        return ;
    }

    if (prev_up) {
        pid_t pid;
        if (list_is_singular(&prev_up->list_up)) {
            pid = -1;
        } else {
            pid = list_entry(prev_up->list_up.next,
                             struct vnfc_service, list_up)->pid;
        }
        service_send_signal(prev_up->pid, pid, SERVICE_UPSTREAM);
    }
    if (prev_down) {
        pid_t pid;
        if (list_is_singular(&prev_down->list_down)) {
            pid = -1;
        } else {
            pid = list_entry(prev_down->list_down.next,
                             struct vnfc_service, list_down)->pid;
        }
        service_send_signal(prev_down->pid, pid, SERVICE_DOWNSTREAM);
    }
}


extern int service_file_attach(struct vnfc_file *vfile, struct vnfc_req *req)
{
    struct vnfc_struct *vnfc;
    struct vnfc_service *service;
    int err;

    vnfc = vnfc_get(vfile);

    if (vnfc) {
        vnfc_put(vnfc);
        return -EBADFD;
    } else if (vfile->service) {
        return -EBADFD;
    } else if (vfile->detached) {
        return -EINVAL;
    }

    service = get_service(vfile, req);
    if (! service) {
        service = (struct vnfc_service*)kzalloc(sizeof(struct vnfc_service),
                                                GFP_KERNEL);
        if (unlikely(! service)) {
            return -ENOMEM;
        }
    }

    rcu_assign_pointer(vfile->service, service);

    if (req->flags & SERVICE_OUTPUT_FILE) {
        service->vfile_from_svc = vfile;
        req->flags ^= SERVICE_OUTPUT_FILE;
    } else if (req->flags & SERVICE_INPUT_FILE) {
        service->vfile_to_svc = vfile;
        req->flags ^= SERVICE_INPUT_FILE;
    } else {
        return -EINVAL;
    }

    if (service->vfile_from_svc && service->vfile_to_svc) {
        /* Second attach */

        struct vnfc_struct *vnfc;
        vnfc = get_vnfc_by_name(vfile->net, req->dev_name);
        rcu_assign_pointer(vfile->vnfc, vnfc);
        BUG_ON(!vfile->vnfc);
        pr_info("[%s] (%s) add new service: %s (%d)\n", DRV_NAME,
                vnfc->dev->name, service->name, service->pid);
        return 0;
    }

    /* First attach */
    service->pid   = req->pid;
    service->flags = req->flags;
    memcpy(service->name, req->svc_name, IFNAMSIZ);

    err = service_net_append(vfile, req->dev_name);
    if (err) {
        kfree(service);
        vfile->service = NULL;
        vfile->vnfc   = NULL;
    }

    return err;
}


extern int service_file_detach(struct vnfc_file *vfile)
{
    struct vnfc_service *service;

    service = vfile->service;
    if (service) {
        if (service->vfile_from_svc == vfile) {
            service->vfile_from_svc = NULL;
        } else if (service->vfile_to_svc == vfile) {
            service->vfile_to_svc = NULL;
        } else {
            return -EINVAL;
        }

        if (!service->vfile_from_svc && !service->vfile_to_svc) {
            pr_info("[%s] (%s) detach the service: %s\n", DRV_NAME,
                    vfile->vnfc->dev->name, service->name);
            service_net_delete(vfile->vnfc, service);
            kfree(service);
        }
    }

    return 0;
}


extern int service_file_close(struct vnfc_file *vfile)
{
    int err;

    pr_info("[%s] (%s) close the service file: %s\n",
            DRV_NAME, vfile->vnfc->dev->name, vfile->service->name);

    err = service_file_detach(vfile);

    vfile->service = NULL;
    vfile->vnfc    = NULL;

    return err;
}
