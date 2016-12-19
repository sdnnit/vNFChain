/*
 * vnfc_ethtool.c : Ethtool interface
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

#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/errno.h>
#include "vnfc.h"
#include "vnfc_ethtool.h"


static int vnfc_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
    cmd->supported   = 0;
    cmd->advertising = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
    cmd->speed       = SPEED_10000;
#else
    ethtool_cmd_speed_set(cmd, SPEED_10000);
#endif
    cmd->duplex      = DUPLEX_FULL;
    cmd->port        = PORT_OTHER;
    cmd->phy_address = 0;
    cmd->transceiver = XCVR_DUMMY1;
    cmd->autoneg     = AUTONEG_DISABLE;
    cmd->maxtxpkt    = 0;
    cmd->maxrxpkt    = 0;

    return 0;
}


static void vnfc_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
    strlcpy(info->driver, DRV_NAME, sizeof(info->driver));
    strlcpy(info->version, DRV_VERSION, sizeof(info->version));
    strlcpy(info->bus_info, DRV_NAME, sizeof(info->bus_info));

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
    strlcpy(info->fw_version, "N/A", sizeof(info->fw_version));
#endif
}


static __u32 vnfc_get_msglevel(struct net_device *dev)
{
    return -EOPNOTSUPP;
}


static void vnfc_set_msglevel(struct net_device *dev, __u32 value)
{

}


#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
static __u32 vnfc_get_rx_csum(struct net_device *dev)
{
    return 0;
}


static int vnfc_set_rx_csum(struct net_device *dev, u32 data)
{
    return 0;
}
#endif


const struct ethtool_ops vnfc_ethtool_ops = {
    .get_settings = vnfc_get_settings,
    .get_drvinfo  = vnfc_get_drvinfo,
    .get_msglevel = vnfc_get_msglevel,
    .set_msglevel = vnfc_set_msglevel,
    .get_link     = ethtool_op_get_link,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
    .get_rx_csum  = vnfc_get_rx_csum,
    .set_rx_csum  = vnfc_set_rx_csum,
#endif
};
