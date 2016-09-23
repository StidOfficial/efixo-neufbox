/*************************************************************************
* Cavium Octeon Ethernet Driver
*
* Author: Cavium Networks info@caviumnetworks.com
*
* Copyright (c) 2003-2007  Cavium Networks (support@cavium.com). All rights
* reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
*     * Redistributions of source code must retain the above copyright
*       notice, this list of conditions and the following disclaimer.
*
*     * Redistributions in binary form must reproduce the above
*       copyright notice, this list of conditions and the following
*       disclaimer in the documentation and/or other materials provided
*       with the distribution.
*
*     * Neither the name of Cavium Networks nor the names of
*       its contributors may be used to endorse or promote products
*       derived from this software without specific prior written
*       permission.
*
* This Software, including technical data, may be subject to U.S.  export
* control laws, including the U.S.  Export Administration Act and its
* associated regulations, and may be subject to export or import regulations
* in other countries.  You warrant that You will comply strictly in all
* respects with all such regulations and acknowledge that you have the
* responsibility to obtain licenses to export, re-export or import the
* Software.
*
* TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
* AND WITH ALL FAULTS AND CAVIUM NETWORKS MAKES NO PROMISES, REPRESENTATIONS
* OR WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH
* RESPECT TO THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY
* REPRESENTATION OR DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT
* DEFECTS, AND CAVIUM SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES
* OF TITLE, MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR
* PURPOSE, LACK OF VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET
* POSSESSION OR CORRESPONDENCE TO DESCRIPTION.  THE ENTIRE RISK ARISING OUT
* OF USE OR PERFORMANCE OF THE SOFTWARE LIES WITH YOU.
*************************************************************************/
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/mii.h>
#include <net/dst.h>

#include "wrapper-cvmx-includes.h"
#include "ethernet-headers.h"

extern int octeon_is_simulation(void);
extern struct net_device *cvm_oct_device[];
DEFINE_SPINLOCK(global_register_lock);


static void cvm_oct_rgmii_poll(struct net_device *dev)
{
    cvm_oct_private_t* priv = (cvm_oct_private_t*)netdev_priv(dev);
    unsigned long flags;
    cvmx_helper_link_info_t link_info;

    /* Take the global register lock since we are going to touch
        registers that affect more than one port */
    spin_lock_irqsave(&global_register_lock, flags);

    link_info = cvmx_helper_link_get(priv->port);
    if (link_info.u64 == priv->link_info)
    {
        /* If the 10Mbps preamble workaround is supported and we're at 10Mbps
            we may need to do some special checking */
        if (USE_10MBPS_PREAMBLE_WORKAROUND && (link_info.s.speed == 10))
        {
            /* Read the GMXX_RXX_INT_REG[PCTERR] bit and see if we are getting
                preamble errors */
            int interface = INTERFACE(priv->port);
            int index = INDEX(priv->port);
            cvmx_gmxx_rxx_int_reg_t gmxx_rxx_int_reg;
            gmxx_rxx_int_reg.u64 = cvmx_read_csr(CVMX_GMXX_RXX_INT_REG(index, interface));
            if (gmxx_rxx_int_reg.s.pcterr)
            {
                /* We are getting preamble errors at 10Mbps. Most likely the
                    PHY is giving us packets with mis aligned preambles. In
                    order to get these packets we need to disable preamble
                    checking and do it in software */
                cvmx_gmxx_rxx_frm_ctl_t gmxx_rxx_frm_ctl;
                cvmx_ipd_sub_port_fcs_t ipd_sub_port_fcs;

                /* Disable preamble checking */
                gmxx_rxx_frm_ctl.u64 = cvmx_read_csr(CVMX_GMXX_RXX_FRM_CTL(index, interface));
                gmxx_rxx_frm_ctl.s.pre_chk = 0;
                cvmx_write_csr(CVMX_GMXX_RXX_FRM_CTL(index, interface), gmxx_rxx_frm_ctl.u64);
                /* Disable FCS stripping */
                ipd_sub_port_fcs.u64 = cvmx_read_csr(CVMX_IPD_SUB_PORT_FCS);
                ipd_sub_port_fcs.s.port_bit &= 0xffffffffull ^ (1ull<<priv->port);
                cvmx_write_csr(CVMX_IPD_SUB_PORT_FCS, ipd_sub_port_fcs.u64);
                /* Clear any error bits */
                cvmx_write_csr(CVMX_GMXX_RXX_INT_REG(index, interface), gmxx_rxx_int_reg.u64);
                DEBUGPRINT("%s: Using 10Mbps with software preamble removal\n", dev->name);
            }
        }
        spin_unlock_irqrestore(&global_register_lock, flags);
        return;
    }

    /* If the 10Mbps preamble workaround is allowed we need to on preamble checking,
        FCS stripping, and clear error bits on every speed change. If errors occur
        during 10Mbps operation the above cod will change this stuff */
    if (USE_10MBPS_PREAMBLE_WORKAROUND)
    {
        cvmx_gmxx_rxx_frm_ctl_t gmxx_rxx_frm_ctl;
        cvmx_ipd_sub_port_fcs_t ipd_sub_port_fcs;
        cvmx_gmxx_rxx_int_reg_t gmxx_rxx_int_reg;
        int interface = INTERFACE(priv->port);
        int index = INDEX(priv->port);

        /* Enable preamble checking */
        gmxx_rxx_frm_ctl.u64 = cvmx_read_csr(CVMX_GMXX_RXX_FRM_CTL(index, interface));
        gmxx_rxx_frm_ctl.s.pre_chk = 1;
        cvmx_write_csr(CVMX_GMXX_RXX_FRM_CTL(index, interface), gmxx_rxx_frm_ctl.u64);
        /* Enable FCS stripping */
        ipd_sub_port_fcs.u64 = cvmx_read_csr(CVMX_IPD_SUB_PORT_FCS);
        ipd_sub_port_fcs.s.port_bit |= 1ull<<priv->port;
        cvmx_write_csr(CVMX_IPD_SUB_PORT_FCS, ipd_sub_port_fcs.u64);
        /* Clear any error bits */
        gmxx_rxx_int_reg.u64 = cvmx_read_csr(CVMX_GMXX_RXX_INT_REG(index, interface));
        cvmx_write_csr(CVMX_GMXX_RXX_INT_REG(index, interface), gmxx_rxx_int_reg.u64);
    }

    link_info = cvmx_helper_link_autoconf(priv->port);
    priv->link_info = link_info.u64;
    spin_unlock_irqrestore(&global_register_lock, flags);

    /* Tell Linux */
    if (link_info.s.link_up)
    {
        if (!netif_carrier_ok(dev))
            netif_carrier_on(dev);
        if (priv->queue != -1)
            DEBUGPRINT("%s: %u Mbps %s duplex, port %2d, queue %2d\n",
                       dev->name, link_info.s.speed,
                       (link_info.s.full_duplex) ? "Full" : "Half",
                       priv->port, priv->queue);
        else
            DEBUGPRINT("%s: %u Mbps %s duplex, port %2d, POW\n",
                       dev->name, link_info.s.speed,
                       (link_info.s.full_duplex) ? "Full" : "Half",
                       priv->port);
    }
    else
    {
        if (netif_carrier_ok(dev))
            netif_carrier_off(dev);
        DEBUGPRINT("%s: Link down\n", dev->name);
    }
}


static int cvm_oct_rgmii_open(struct net_device *dev)
{
    cvmx_gmxx_prtx_cfg_t gmx_cfg;
    cvm_oct_private_t* priv = (cvm_oct_private_t*)netdev_priv(dev);
    int interface = INTERFACE(priv->port);
    int index = INDEX(priv->port);

    gmx_cfg.u64 = cvmx_read_csr(CVMX_GMXX_PRTX_CFG(index, interface));
    gmx_cfg.s.en = 1;
    cvmx_write_csr(CVMX_GMXX_PRTX_CFG(index, interface), gmx_cfg.u64);
    return 0;
}

static int cvm_oct_rgmii_stop(struct net_device *dev)
{
    cvmx_gmxx_prtx_cfg_t gmx_cfg;
    cvm_oct_private_t* priv = (cvm_oct_private_t*)netdev_priv(dev);
    int interface = INTERFACE(priv->port);
    int index = INDEX(priv->port);

    gmx_cfg.u64 = cvmx_read_csr(CVMX_GMXX_PRTX_CFG(index, interface));
    gmx_cfg.s.en = 0;
    cvmx_write_csr(CVMX_GMXX_PRTX_CFG(index, interface), gmx_cfg.u64);
    return 0;
}

int cvm_oct_rgmii_init(struct net_device *dev)
{
    cvm_oct_private_t* priv = (cvm_oct_private_t*)netdev_priv(dev);

    cvm_oct_common_init(dev);
    dev->open = cvm_oct_rgmii_open;
    dev->stop = cvm_oct_rgmii_stop;
    dev->stop(dev);
    /* Only true RGMII ports need to be polled. In GMII mode, port 0 is really
        a RGMII port */
    if (((priv->imode == CVMX_HELPER_INTERFACE_MODE_GMII) && (priv->port == 0)) ||
        (priv->imode == CVMX_HELPER_INTERFACE_MODE_RGMII))
    {
        if (!octeon_is_simulation())
            priv->poll = cvm_oct_rgmii_poll;
    }
    return 0;
}

void cvm_oct_rgmii_uninit(struct net_device *dev)
{
    cvm_oct_common_uninit(dev);
}

