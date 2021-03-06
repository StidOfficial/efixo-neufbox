/*
 *   Octeon Management Port Ethernet Driver
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2007 Cavium Networks
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/string.h>
#include <linux/delay.h>

#undef OCTEON_MODEL
#define USE_RUNTIME_MODEL_CHECKS 1
#include "cvmx.h"
#include "cvmx-mgmt-port.h"

static struct net_device *global_dev[2] = { NULL, NULL };

#define DEBUGPRINT(format, ...) do{if (__printk_ratelimit(HZ, 10)) printk(format, ##__VA_ARGS__);} while (0)

/**
 * This is the definition of the Ethernet driver's private
 * driver state stored in dev->priv.
 */
typedef struct {
	int port;
	struct net_device_stats stats;	/* Device statistics */
} device_private_t;


/**
 * Packet transmit
 *
 * @param skb    Packet to send
 * @param dev    Device info structure
 * @return Always returns zero
 */
static int packet_transmit(struct sk_buff *skb, struct net_device *dev)
{
	uint64_t flags;
	device_private_t *priv = (device_private_t *) dev->priv;
	cvmx_mgmt_port_result_t result;
	local_irq_save(flags);
	result = cvmx_mgmt_port_send(priv->port, skb->len, skb->data);
	local_irq_restore(flags);
	if (result == CVMX_MGMT_PORT_SUCCESS) {
		priv->stats.tx_packets++;
		priv->stats.tx_bytes += skb->len;
	} else {
		// DEBUGPRINT("ERROR: cvmx_mgmt_port_send() failed with %d\n",
		// result);
		priv->stats.tx_dropped++;
	}
	dev_kfree_skb(skb);
	return 0;
}


/**
 * Interrupt handler. The interrupt occurs whenever the POW
 * transitions from 0->1 packets in our group.
 *
 * @param cpl
 * @param dev_id
 * @param regs
 * @return
 */
static irqreturn_t do_interrupt(int cpl, void *dev_id)
{
	uint64_t flags;
	struct sk_buff *skb;
	int result;
	char packet[2048];
	struct net_device *dev = (struct net_device *) dev_id;
	device_private_t *priv = (device_private_t *) dev->priv;

	do {
		local_irq_save(flags);
		result = cvmx_mgmt_port_receive(priv->port, sizeof(packet),
						packet);
		local_irq_restore(flags);

		/* Silently drop packets if we aren't up */
		if ((dev->flags & IFF_UP) == 0)
			continue;

		if (result > 0) {
			skb = dev_alloc_skb(result);
			if (skb) {
				memcpy(skb_put(skb, result), packet, result);
				skb->protocol = eth_type_trans(skb, dev);
				skb->dev = dev;
				skb->ip_summed = CHECKSUM_NONE;
				priv->stats.rx_bytes += skb->len;
				priv->stats.rx_packets++;
				netif_rx(skb);
			} else {
				DEBUGPRINT
					("%s: Failed to allocate skbuff, packet dropped\n",
					 dev->name);
				priv->stats.rx_dropped++;
			}
		} else if (result < 0) {
			DEBUGPRINT
				("%s: Receive error code %d, packet dropped\n",
				 dev->name, result);
			priv->stats.rx_errors++;
		}
	} while (result != 0);

	/* Clear any pending interrupts */
	cvmx_write_csr(CVMX_MIXX_ISR(priv->port),
		       cvmx_read_csr(CVMX_MIXX_ISR(priv->port)));
	cvmx_read_csr(CVMX_MIXX_ISR(priv->port));

	return IRQ_HANDLED;
}


#ifdef CONFIG_NET_POLL_CONTROLLER
/**
 * This is called when the kernel needs to manually poll the
 * device. For Octeon, this is simply calling the interrupt
 * handler. We actually poll all the devices, not just the
 * one supplied.
 *
 * @param dev    Device to poll. Unused
 */
static void device_poll_controller(struct net_device *dev)
{
	do_interrupt(0, dev, NULL);
}
#endif


/**
 * Open a device for use. Device should be able to send and
 * receive packets after this is called.
 *
 * @param dev    Device to bring up
 * @return Zero on success
 */
static int device_open(struct net_device *dev)
{
	/* Clear the statistics whenever the interface is brought up */
	device_private_t *priv = (device_private_t *) dev->priv;
	memset(&priv->stats, 0, sizeof(priv->stats));
	cvmx_mgmt_port_enable(priv->port);
	return 0;
}


/**
 * Stop an ethernet device. No more packets should be
 * received from this device.
 *
 * @param dev    Device to bring down
 * @return Zero on success
 */
static int device_close(struct net_device *dev)
{
	device_private_t *priv = (device_private_t *) dev->priv;
	cvmx_mgmt_port_disable(priv->port);
	return 0;
}


/**
 * Get the low level ethernet statistics
 *
 * @param dev    Device to get the statistics from
 * @return Pointer to the statistics
 */
static struct net_device_stats *device_get_stats(struct net_device *dev)
{
	device_private_t *priv = (device_private_t *) dev->priv;
	return &priv->stats;
}

/**
 * Set the multicast list. Currently unimplemented.
 *
 * @param dev    Device to work on
 */
static void ethernet_mgmt_port_set_multicast_list(struct net_device *dev)
{
	device_private_t* priv = (device_private_t *)dev->priv;
	int port = priv->port;
	int num_ports;
	if (OCTEON_IS_MODEL(OCTEON_CN52XX))
		num_ports = 2;
	else
		num_ports = 1;
	if (port < num_ports)
		cvmx_mgmt_port_set_multicast_list(port, dev->flags);
}

/**
 * Set the hardware MAC address for a management port device
 *
 * @param dev    Device to change the MAC address for
 * @param addr   Address structure to change it too. MAC address is addr + 2.
 * @return Zero on success
 */
static int ethernet_mgmt_port_set_mac_address(struct net_device *dev, void *addr)
{
	device_private_t *priv = (device_private_t *) dev->priv;
	cvmx_agl_gmx_prtx_cfg_t agl_gmx_cfg;
	int port = priv->port;
	int num_ports;

	if (OCTEON_IS_MODEL(OCTEON_CN52XX))
		num_ports = 2;
	else
		num_ports = 1;

	memcpy(dev->dev_addr, addr + 2, 6);

	if (port < num_ports) {
		int i;
		uint8_t *ptr = addr;
		uint64_t mac = 0;
		for (i=0; i<6; i++)
			mac = (mac<<8) | (uint64_t)(ptr[i+2]);

		agl_gmx_cfg.u64 = cvmx_read_csr(CVMX_AGL_GMX_PRTX_CFG(port));
		cvmx_mgmt_port_set_mac(port, mac);
		ethernet_mgmt_port_set_multicast_list(dev);
		cvmx_write_csr(CVMX_AGL_GMX_PRTX_CFG(port), agl_gmx_cfg.u64);
	}
	return 0;
}

/**
 * Per network device initialization
 *
 * @param dev    Device to initialize
 * @return Zero on success
 */
static int device_init(struct net_device *dev)
{
	device_private_t *priv = (device_private_t *) dev->priv;
	uint64_t mac = cvmx_mgmt_port_get_mac(priv->port);

	dev->hard_start_xmit = packet_transmit;
	dev->get_stats = device_get_stats;
	dev->open = device_open;
	dev->stop = device_close;
#ifdef CONFIG_NET_POLL_CONTROLLER
	dev->poll_controller = device_poll_controller;
#endif
	dev->weight = 16;
	dev->dev_addr[0] = (mac >> 40) & 0xff;
	dev->dev_addr[1] = (mac >> 32) & 0xff;
	dev->dev_addr[2] = (mac >> 24) & 0xff;
	dev->dev_addr[3] = (mac >> 16) & 0xff;
	dev->dev_addr[4] = (mac >> 8) & 0xff;
	dev->dev_addr[5] = (mac >> 0) & 0xff;
	return 0;
}


/**
 * Module/ driver initialization. Creates the linux network
 * devices.
 *
 * @return Zero on success
 */
static int __init ethernet_mgmt_port_init(void)
{
	struct net_device *dev;
	device_private_t *priv;
	cvmx_mixx_irhwm_t mix_irhwm;
	cvmx_mixx_intena_t mix_intena;
	int num_ports;
	int port;

	if (!OCTEON_IS_MODEL(OCTEON_CN56XX) && !OCTEON_IS_MODEL(OCTEON_CN52XX))
		return 0;

	if (OCTEON_IS_MODEL(OCTEON_CN52XX))
		num_ports = 2;
	else
		num_ports = 1;

	printk("Octeon management port ethernet driver\n");

	for (port = 0; port < num_ports; port++) {
		if (cvmx_mgmt_port_initialize(port) != CVMX_MGMT_PORT_SUCCESS) {
			printk("\n\nERROR: cvmx_mgmt_port_initialize(%d) failed\n", port);
			return -1;
		}

		/* Setup is complete, create the virtual ethernet devices */
		dev = alloc_etherdev(sizeof(device_private_t));
		if (dev == NULL) {
			printk("\n\nERROR: Failed to allocate ethernet device\n");
			return -1;
		}

		SET_MODULE_OWNER(dev);
		dev->init = device_init;
		strcpy(dev->name, "mgmt%d");

		/* Initialize the device private structure. */
		priv = (device_private_t *) dev->priv;
		memset(priv, 0, sizeof(device_private_t));
		priv->port = port;

		if (register_netdev(dev) < 0) {
			printk("\n\nERROR: Failed to register ethernet device\n");
			kfree(dev);
			return -1;
		}

		/* Clear any pending interrupts */
		cvmx_write_csr(CVMX_MIXX_ISR(priv->port),
			       cvmx_read_csr(CVMX_MIXX_ISR(priv->port)));

		/* Register an IRQ hander for to receive interrupts */
		dev->irq =
			(priv->port == 0) ? OCTEON_IRQ_MII0 : OCTEON_IRQ_MII1;
		request_irq(dev->irq, do_interrupt, SA_SHIRQ, dev->name,
			    dev);

		/* Interrupt every single RX packet */
		mix_irhwm.u64 = 0;
		mix_irhwm.s.irhwm = 0;
		cvmx_write_csr(CVMX_MIXX_IRHWM(priv->port), mix_irhwm.u64);

		/* Enable receive interrupts */
		mix_intena.u64 = 0;
		mix_intena.s.ithena = 1;
		cvmx_write_csr(CVMX_MIXX_INTENA(priv->port), mix_intena.u64);

		global_dev[priv->port] = dev;

		dev->set_mac_address = ethernet_mgmt_port_set_mac_address;
		dev->set_multicast_list = ethernet_mgmt_port_set_multicast_list;
	}
	return 0;
}


/**
 * Module / driver shutdown
 *
 * @return Zero on success
 */
static void __exit ethernet_mgmt_port_cleanup(void)
{
	int port;
	for (port = 0; port < 2; port++) {
		if (global_dev[port]) {
			device_private_t *priv =
				(device_private_t *) global_dev[port]->priv;
			/* Disable interrupt */
			cvmx_write_csr(CVMX_MIXX_IRHWM(priv->port), 0);
			cvmx_write_csr(CVMX_MIXX_INTENA(priv->port), 0);
			cvmx_mgmt_port_shutdown(priv->port);

			/* Free the interrupt handler */
			free_irq(global_dev[port]->irq, global_dev[port]);

			/* Free the ethernet devices */
			unregister_netdev(global_dev[port]);
			kfree(global_dev[port]);
			global_dev[port] = NULL;
		}
	}
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cavium Networks <support@caviumnetworks.com>");
MODULE_DESCRIPTION("Cavium Networks Octeon management port ethernet driver.");
module_init(ethernet_mgmt_port_init);
module_exit(ethernet_mgmt_port_cleanup);
