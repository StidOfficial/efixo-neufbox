/*
 * bcm5325.c: Broadcom 5325 switch driver
 *
 * Copyright (C) 2010 Miguel Gaio <miguel.gaio@efixo.com>
 * Copyright (C) 2005 Felix Fietkau <nbd@nbd.name>
 * Copyright (C) 2008 Michael Buesch <mb@bu3sch.de>
 * Based on 'robocfg' by Oleg I. Vdovikin
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/if.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/if_ether.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <linux/bitops.h>
#include <net/genetlink.h>
#include <linux/switch.h>
#include <linux/delay.h>
#include <linux/phy.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include "robo-switch.h"
#include "etc53xx.h"

#define BCM5325_DRIVER_DESC	"Broadcom BCM5325 ethernet switch driver"
#define BCM5325_DRIVER_VER	"0.0.2"
#define BCM5325_DRIVER_NAME	"bcm5325e"


/* switch */

static int bcm5325_sw_get_vlan_ports(struct switch_dev *dev,
		struct switch_val *val)
{
	struct robo *priv = sw_to_robo(dev);
	struct switch_port *port;
	int i;

	u32 v32;
	u16 v16;

	v16 = val->port_vlan | (0 << 12) /* read */ |(1 << 13) /* enable */ ;
	robo_w16(priv, ROBO_VLAN_PAGE, ROBO_VLAN_TABLE_ACCESS_5350, v16);

	/* actual read */
	v32 = robo_r32(priv, ROBO_VLAN_PAGE, ROBO_VLAN_READ);
	if (!(v32 & (1 << 20)) /* valid */ )
		return -EINVAL;

	port = &val->value.ports[0];
	val->len = 0;
	for (i = 0; i < dev->ports; i++) {
		if (!(v32 & BIT(i)))
			continue;

		port->id = i;
		if (v32 & BIT(i + 6))
			port->flags = 0;
		else
			port->flags = BIT(SWITCH_PORT_FLAG_TAGGED);

		val->len++;
		port++;
	}

	return 0;
}

static int bcm5325_sw_set_vlan_ports(struct switch_dev *dev,
		struct switch_val *val)
{
	struct robo *priv = sw_to_robo(dev);
	struct switch_port *port;
	u32 member = 0;
	u32 untag = 0;
	int i;
	u16 v16;

	port = &val->value.ports[0];
	for (i = 0; i < val->len; i++, port++) {
		member |= BIT(port->id);

		if (!(port->flags & BIT(SWITCH_PORT_FLAG_TAGGED))) {
			untag |= BIT(port->id);
			robo_w16(priv, ROBO_VLAN_PAGE,
					ROBO_VLAN_PORT0_DEF_TAG + (i << 1),
					val->port_vlan);
		}
	}

	robo_w32(priv, ROBO_VLAN_PAGE, ROBO_VLAN_WRITE_5350,
			(1 << 20) /* valid */ |(untag << 6) | member);
	v16 = val->port_vlan | (1 << 12) /* write */ |(1 << 13) /* enable */ ;
	robo_w16(priv, ROBO_VLAN_PAGE, ROBO_VLAN_TABLE_ACCESS_5350, v16);

	return 0;
}

static int bcm5325_sw_get_vlan_enable(struct switch_dev *dev,
		const struct switch_attr *attr,
		struct switch_val *val)
{
	struct robo *priv = sw_to_robo(dev);

	val->value.i =
		((robo_r16(priv, ROBO_VLAN_PAGE, ROBO_VLAN_CTRL0) & (1 << 7)) ==
		 (1 << 7));

	return 0;
}

static int bcm5325_sw_set_vlan_enable(struct switch_dev *dev,
		const struct switch_attr *attr,
		struct switch_val *val)
{
	struct robo *priv = sw_to_robo(dev);
	u16 v;

	v = (val->value.i) ? v =
		(1 << 7) /* 802.1Q VLAN */ |(3 << 5) /* mac check and hash */ : 0;
	robo_w16(priv, ROBO_VLAN_PAGE, ROBO_VLAN_CTRL0, v);
	v = (val->value.i) ? (1 << 1) : 0;
	robo_w16(priv, ROBO_VLAN_PAGE, ROBO_VLAN_CTRL1, v);

	return 0;
}

static int bcm5325_sw_get_port_link(struct switch_dev *dev,
		const struct switch_attr *attr,
		struct switch_val *val)
{
	struct robo *priv = sw_to_robo(dev);
	u32 len;
	u16 link, speed, duplex;

	link = robo_r16(priv, ROBO_STAT_PAGE, ROBO_LINK_STAT_SUMMARY);
	speed = robo_r16(priv, ROBO_STAT_PAGE, ROBO_SPEED_STAT_SUMMARY);
	duplex = robo_r16(priv, ROBO_STAT_PAGE, ROBO_DUPLEX_STAT_SUMMARY);

	if (link & (1 << val->port_vlan)) {
		len = snprintf(priv->buf, sizeof(priv->buf),
				"port:%d link:up speed:%s %s-duplex",
				val->port_vlan,
				(speed & (1 << val->port_vlan)) ?
				"100baseT" : "10baseT",
				(duplex & (1 << val->port_vlan)) ?
				"full" : "half");
	} else {
		len =
			snprintf(priv->buf, sizeof(priv->buf), "port:%d link: down",
					val->port_vlan);
	}

	val->value.s = priv->buf;
	val->len = len;

	return 0;
}

static int bcm5325_sw_reset_switch(struct switch_dev *dev)
{
	struct robo *priv = sw_to_robo(dev);
	int j;
	u16 v;

	/* disable switching */
	robo_w16(priv, ROBO_CTRL_PAGE, ROBO_SWITCH_MODE,
			robo_r16(priv, ROBO_CTRL_PAGE, ROBO_SWITCH_MODE) & ~2);

	/* reset vlans */
	for (j = 0; j <= dev->vlans; j++) {
		/* write config now */
		v = (j) /* vlan */ |(1 << 12) /* write */ |(1 << 13) /* enable */ ;
		robo_w16(priv, ROBO_VLAN_PAGE, ROBO_VLAN_WRITE_5350, 0);
		robo_w16(priv, ROBO_VLAN_PAGE, ROBO_VLAN_TABLE_ACCESS_5350, v);
	}

	/* reset ports to a known good state */
	for (j = 0; j < dev->ports; j++) {
		robo_w16(priv, ROBO_CTRL_PAGE, ROBO_PORT0_CTRL + j, 0x0000);
		robo_w16(priv, ROBO_VLAN_PAGE,
				ROBO_VLAN_PORT0_DEF_TAG + (j << 1), 0);
	}

	/* enable switching */
	robo_w16(priv, ROBO_CTRL_PAGE, ROBO_SWITCH_MODE,
			robo_r16(priv, ROBO_CTRL_PAGE, ROBO_SWITCH_MODE) | 2);

	return 0;
}

static struct switch_attr bcm5325_globals[] = {
	{
		.type = SWITCH_TYPE_INT,
		.name = "enable_vlan",
		.description = "Enable VLAN mode",
		.set = bcm5325_sw_set_vlan_enable,
		.get = bcm5325_sw_get_vlan_enable,
		.max = 1,
	},
};

static struct switch_attr bcm5325_port[] = {
	{
		.type = SWITCH_TYPE_STRING,
		.name = "link",
		.description = "Get port link information",
		.max = 1,
		.set = NULL,
		.get = bcm5325_sw_get_port_link,
	},
};

static struct switch_attr bcm5325_vlan[] = {
};

static const struct switch_dev_ops bcm5325_ops = {
	.attr_global = {
		.attr = bcm5325_globals,
		.n_attr = ARRAY_SIZE(bcm5325_globals),
	},
	.attr_port = {
		.attr = bcm5325_port,
		.n_attr = ARRAY_SIZE(bcm5325_port),
	},
	.attr_vlan = {
		.attr = bcm5325_vlan,
		.n_attr = ARRAY_SIZE(bcm5325_vlan),
	},

	.get_vlan_ports = bcm5325_sw_get_vlan_ports,
	.set_vlan_ports = bcm5325_sw_set_vlan_ports,
	.reset_switch = bcm5325_sw_reset_switch,
};

static int bcm5325_pseudo_phy_probe(struct phy_device *phydev)
{
	struct robo *priv;
	struct switch_dev *sw_dev;
	int err;
	u16 id;

	if (phydev->addr != 0x1e)
		return -EINVAL;

	/* FIXME: check for real devid */
	id = robo_phy_r16(phydev, ROBO_MGMT_PAGE, ROBO_DEVICE_ID);
	if ((id != 0x00) && (id != 0x01)) {
		err = -ENODEV;
		goto err_out;
	}

	dev_info(&phydev->dev, "found BCM5325%s switch\n", id ? "A1" : "A0");

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		dev_err(&phydev->dev, "no memory for private data\n");
		err = -ENOMEM;
		goto err_out;
	}

	sw_dev = &priv->sw_dev;
	sw_dev->name = "BCM5325E";
	sw_dev->cpu_port = 8;
	sw_dev->ports = 5;
	sw_dev->vlans = VLAN_ID_MAX5350;
	sw_dev->ops = &bcm5325_ops;
	sw_dev->devname = BCM5325_DRIVER_NAME;

	priv->parent = &phydev->dev;
	phydev->priv = priv;
	err = robo_init(priv);
	if (err) {
		dev_err(&phydev->dev, "robo init failed\n");
		goto err_free_robo;
	}

	err = register_switch(sw_dev, NULL);
	if (err) {
		dev_err(&phydev->dev, "switch registration failed\n");
		goto err_cleanup_robo;
	}

	return 0;

err_cleanup_robo:
	robo_cleanup(priv);
err_free_robo:
	kfree(priv);
err_out:
	return err;
}

static void bcm5325_pseudo_phy_remove(struct phy_device *phydev)
{
	struct robo *priv = phydev->priv;

	if (!priv)
		return;

	unregister_switch(&priv->sw_dev);
	robo_cleanup(priv);
	kfree(priv);
}

static struct phy_driver bcm5325_pseudo_phy_driver = {
	.phy_id = 0x00000000,
	.name = "Broadcom BCM5325 Pseudo PHY",
	.phy_id_mask = 0xffffffff,
	.features = PHY_BASIC_FEATURES,
	.probe = bcm5325_pseudo_phy_probe,
	.remove = bcm5325_pseudo_phy_remove,
	.driver = {
		.owner = THIS_MODULE,
	},
};

static int bcm5325_phy_config_init(struct phy_device *phydev)
{
	return 0;
}

static int bcm5325_phy_config_aneg(struct phy_device *phydev)
{
	return 0;
}

static struct phy_driver bcm5325_phy_driver = {
	.phy_id = 0x0143bc30,
	.name = "Broadcom BCM5325",
	.phy_id_mask = 0x1ffffff0,
	.features = PHY_BASIC_FEATURES,
	.config_aneg = bcm5325_phy_config_aneg,
	.config_init = bcm5325_phy_config_init,
	.read_status = genphy_read_status,
	.driver = {
		.owner = THIS_MODULE,
	},
};

static int __init bcm5325_module_init(void)
{
	int err;

	err = phy_driver_register(&bcm5325_pseudo_phy_driver);
	if (err)
		goto err_out;

	err = phy_driver_register(&bcm5325_phy_driver);
	if (err)
		goto err_unregister_pseudo_phy;

	return 0;

err_unregister_pseudo_phy:
	phy_driver_unregister(&bcm5325_pseudo_phy_driver);
err_out:
	return err;
}

module_init(bcm5325_module_init);

static void __exit bcm5325_module_exit(void)
{
	phy_driver_unregister(&bcm5325_phy_driver);
	phy_driver_unregister(&bcm5325_pseudo_phy_driver);
} module_exit(bcm5325_module_exit);

MODULE_DESCRIPTION(BCM5325_DRIVER_DESC);
MODULE_VERSION(BCM5325_DRIVER_VER);
MODULE_LICENSE("GPL v2");
