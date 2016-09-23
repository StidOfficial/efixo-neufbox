/*
 * Platform driver for the Realtek RTL8367R ethernet switch
 *
 * Copyright (C) 2009-2010 Gabor Juhos <juhosg@openwrt.org>
 * Copyright (C) 2010 Antti Seppälä <a.seppala@gmail.com>
 * Copyright (C) 2010 Miguel Gaio <miguel.gaio@efixo.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/skbuff.h>
#include <linux/switch.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/phy.h>
#include <linux/rtl8367r.h>

#include "rtl8367_smi.h"

#ifdef CONFIG_RTL8367R_PHY_DEBUG_FS
#include <linux/debugfs.h>
#endif

#define RTL8367R_DRIVER_DESC	"Realtek RTL8367R ethernet switch driver"
#define RTL8367R_DRIVER_VER	"0.2.1"

#define RTL8367R_PHY_NO_MAX                 4
#define RTL8367R_PHY_PAGE_MAX               7
#define RTL8367R_PHY_ADDR_MAX               31

#define RTL8370_REG_CHIP_BASE               0x1300

#define RTL8367_CHIP_GLOBAL_CTRL_REG        0x0000
#define RTL8367_CHIP_CTRL_VLAN              (1 << 13)

#define RTL8367_RESET_CTRL_REG              0x1322
#define RTL8367_CHIP_CTRL_RESET_HW          1
#define RTL8367_CHIP_CTRL_RESET_SW          (1 << 1)

#define RTL8367R_MAGIC_ID_REG               0x13c2
#define RTL8367R_CHIP_VERSION_CTRL_REG      0x1301
#define RTL8367R_CHIP_VERSION_MASK          0xf
#define RTL8367R_CHIP_ID_REG                0x1300
#define RTL8367R_CHIP_ID_8367               0x6088

/* PHY registers control */
#define RTL8367R_PHY_ACCESS_CTRL_REG        0x1f00
#define RTL8367R_PHY_ACCESS_STATUS_REG      0x1f01
#define RTL8367R_PHY_ACCESS_DATA_REG        0x1f02
#define RTL8367R_PHY_ACCESS_WR_DATA_REG     0x1f03
#define RTL8367R_PHY_ACCESS_RD_DATA_REG     0x1f04

#define RTL8367R_PHY_CTRL_READ              1
#define RTL8367R_PHY_CTRL_WRITE             3

#define RTL8367R_PHY_BASE                   0x2000
#define RTL8367R_PHY_REG_MASK               0x1f
#define RTL8367R_PHY_NO_OFFSET              5
#define RTL8367R_PHY_NO_MASK                (0x1f << RTL8367R_PHY_NO_OFFSET)

/* LED control registers */
#define RTL8367_LED_BLINKRATE_REG           0x0420
#define RTL8367_LED_BLINKRATE_BIT           0
#define RTL8367_LED_BLINKRATE_MASK          0x0007

#define RTL8367_LED_CTRL_REG                0x0421
#define RTL8367_LED_0_1_CTRL_REG            0x0422
#define RTL8367_LED_2_3_CTRL_REG            0x0423

#define RTL8367R_MIB_COUNT                  33
#define RTL8367R_GLOBAL_MIB_COUNT           1
#define RTL8367R_MIB_COUNTER_PORT_OFFSET    0x0050
#define RTL8367R_MIB_COUNTER_BASE           0x1000
#define RTL8367R_MIB_CTRL_REG               0x1005
#define RTL8367R_MIB_CTRL_USER_MASK         0x01FF
#define RTL8367R_MIB_CTRL_BUSY_MASK         0x0001
#define RTL8367R_MIB_CTRL_RESET_MASK        0x0002

#define RTL8367R_MIB_CTRL_GLOBAL_RESET_MASK 0x0800
#define RTL8367R_MIB_CTRL_PORT_RESET_BIT    0x0003
#define RTL8367R_MIB_CTRL_PORT_RESET_MASK   0x01FC

#define RTL8367R_PORT_VLAN_CTRL_BASE        0x0058
#define RTL8367R_PORT_VLAN_CTRL_REG(_p)  \
		(RTL8367R_PORT_VLAN_CTRL_BASE + (_p) / 4)
#define RTL8367R_PORT_VLAN_CTRL_MASK	    0xf
#define RTL8367R_PORT_VLAN_CTRL_SHIFT(_p)   (4 * ((_p) % 4))

#define RTL8367R_VLAN_TABLE_READ_BASE       0x018B
#define RTL8367R_VLAN_TABLE_WRITE_BASE      0x0185

#define RTL8367R_VLAN_TB_CTRL_REG           0x010F

#define RTL8367R_TABLE_ACCESS_CTRL_REG      0x0180
#define RTL8367R_TABLE_VLAN_READ_CTRL       0x0E01
#define RTL8367R_TABLE_VLAN_WRITE_CTRL      0x0F01

#define RTL8367R_VLAN_MEMCONF_BASE          0x0016

#define RTL8367R_PORT_LINK_STATUS_BASE      0x1352
#define RTL8367R_PORT_STATUS_SPEED_MASK     0x0003
#define RTL8367R_PORT_STATUS_DUPLEX_MASK    0x0004
#define RTL8367R_PORT_STATUS_LINK_MASK      0x0010
#define RTL8367R_PORT_STATUS_TXPAUSE_MASK   0x0020
#define RTL8367R_PORT_STATUS_RXPAUSE_MASK   0x0040
#define RTL8367R_PORT_STATUS_AN_MASK        0x0080

#define RTL8367_PORT_NUM_CPU                9
#define RTL8367_NUM_PORTS                   5
#define RTL8367_NUM_VLANS                   16
#define RTL8367_NUM_LEDGROUPS               4
#define RTL8367_NUM_VIDS                    4096
#define RTL8367R_PRIORITYMAX                7
#define RTL8367R_FIDMAX	                    7

#define RTL8367_PORT_1                      (1 << 0)	/* In userspace port 0 */
#define RTL8367_PORT_2                      (1 << 1)	/* In userspace port 1 */
#define RTL8367_PORT_3                      (1 << 2)	/* In userspace port 2 */
#define RTL8367_PORT_4                      (1 << 3)	/* In userspace port 3 */
#define RTL8367_PORT_5                      (1 << 4)	/* No known connection */
#define RTL8367_PORT_CPU                    (1 << 9)	/* CPU port */

#define RTL8367_PORT_ALL                    (RTL8367_PORT_1 |       \
					     RTL8367_PORT_2 |       \
					     RTL8367_PORT_3 |       \
					     RTL8367_PORT_4 |       \
					     RTL8367_PORT_5 |       \
					     RTL8367_PORT_CPU)

#define RTL8367_PORT_ALL_BUT_CPU            (RTL8367_PORT_1 |       \
					     RTL8367_PORT_2 |       \
					     RTL8367_PORT_3 |       \
					     RTL8367_PORT_4 |       \
					     RTL8367_PORT_5)

#define RTL8367_PORT_ALL_EXTERNAL           (RTL8367_PORT_1 |       \
					     RTL8367_PORT_2 |       \
					     RTL8367_PORT_3 |       \
					     RTL8367_PORT_4 |       \
					     RTL8367_PORT_5)

#define RTL8367_PORT_ALL_INTERNAL           (RTL8367_PORT_CPU)

#define RTL8367R_INTERRUPT_STATUS           0x1102

struct rtl8367r {
	struct device *parent;
	struct rtl8367_smi smi;
	struct work_struct work;
	struct mii_bus *mii_bus;
	int mii_irq[PHY_MAX_ADDR];
	struct switch_dev dev;
	char buf[4096];
#ifdef CONFIG_RTL8367R_PHY_DEBUG_FS
	struct dentry *debugfs_root;
#endif
};

static inline struct rtl8367r *sw_to_rtl8367r(struct switch_dev *sw)
{
	return container_of(sw, struct rtl8367r, dev);
}

static int rtl8367r_reset_chip(struct rtl8367r *rtl)
{
	return 0;
}

static int rtl8367r_read_phy_reg(struct rtl8367r *rtl,
				 u32 phy_no, u32 addr, u32 * data)
{
	struct rtl8367_smi *smi = &rtl->smi;
	u32 reg;
	int ret;
	int i;

	if (phy_no > RTL8367R_PHY_NO_MAX)
		return -EINVAL;

	if (addr > RTL8367R_PHY_ADDR_MAX)
		return -EINVAL;

	reg = RTL8367R_PHY_BASE | (phy_no << RTL8367R_PHY_NO_OFFSET) |
	    (addr & RTL8367R_PHY_REG_MASK);
	ret = rtl8367_smi_write_reg(smi, RTL8367R_PHY_ACCESS_DATA_REG, reg);
	if (ret)
		return ret;

	ret = rtl8367_smi_write_reg(smi, RTL8367R_PHY_ACCESS_CTRL_REG,
				    RTL8367R_PHY_CTRL_READ);
	if (ret)
		return ret;

	for (i = 0; i < 5; ++i) {
		rtl8367_smi_read_reg(smi, RTL8367R_PHY_ACCESS_STATUS_REG, &reg);
		if (!(reg & 0x2))
			break;
	}

	ret = rtl8367_smi_read_reg(smi, RTL8367R_PHY_ACCESS_RD_DATA_REG, data);
	if (ret)
		return ret;

	return 0;
}

static int rtl8367r_write_phy_reg(struct rtl8367r *rtl,
				  u32 phy_no, u32 addr, u32 data)
{
	struct rtl8367_smi *smi = &rtl->smi;
	u32 reg;
	int ret;
	int i;

	if (phy_no > RTL8367R_PHY_NO_MAX)
		return -EINVAL;

	if (addr > RTL8367R_PHY_ADDR_MAX)
		return -EINVAL;

	ret = rtl8367_smi_write_reg(smi, RTL8367R_PHY_ACCESS_WR_DATA_REG, data);
	if (ret)
		return ret;

	reg = RTL8367R_PHY_BASE | (phy_no << RTL8367R_PHY_NO_OFFSET) |
	    (addr & RTL8367R_PHY_REG_MASK);
	ret = rtl8367_smi_write_reg(smi, RTL8367R_PHY_ACCESS_DATA_REG, reg);
	if (ret)
		return ret;

	ret = rtl8367_smi_write_reg(smi, RTL8367R_PHY_ACCESS_CTRL_REG,
				    RTL8367R_PHY_CTRL_WRITE);
	if (ret)
		return ret;

	for (i = 0; i < 5; ++i) {
		rtl8367_smi_read_reg(smi, RTL8367R_PHY_ACCESS_STATUS_REG, &reg);
		if (!(reg & 0x2))
			break;
	}

	return 0;
}

#ifdef CONFIG_RTL8367R_PHY_DEBUG_FS
static int rtl8367r_debugfs_open(struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private;
	return 0;
}

static ssize_t rtl8367r_read_debugfs_reg(struct file *file,
					 char __user * user_buf,
					 size_t count, loff_t * ppos)
{
	struct rtl8367r *rtl = (struct rtl8367r *)file->private_data;
	struct rtl8367_smi *smi = &rtl->smi;
	u32 t, reg = g_dbg_reg;
	int err, len = 0;
	char *buf = rtl->buf;

	memset(buf, '\0', sizeof(rtl->buf));

	err = rtl8367_smi_read_reg(smi, reg, &t);
	if (err) {
		len += snprintf(buf, sizeof(rtl->buf),
				"Read failed (reg: 0x%04x)\n", reg);
		return simple_read_from_buffer(user_buf, count, ppos, buf, len);
	}

	len += snprintf(buf, sizeof(rtl->buf), "reg = 0x%04x, val = 0x%04x\n",
			reg, t);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t rtl8367r_write_debugfs_reg(struct file *file,
					  const char __user * user_buf,
					  size_t count, loff_t * ppos)
{
	struct rtl8367r *rtl = (struct rtl8367r *)file->private_data;
	struct rtl8367_smi *smi = &rtl->smi;
	unsigned long data;
	u32 reg = g_dbg_reg;
	int err;
	size_t len;
	char *buf = rtl->buf;

	len = min(count, sizeof(rtl->buf) - 1);
	if (copy_from_user(buf, user_buf, len)) {
		dev_err(rtl->parent, "copy from user failed\n");
		return -EFAULT;
	}

	buf[len] = '\0';
	if (len > 0 && buf[len - 1] == '\n')
		buf[len - 1] = '\0';

	if (strict_strtoul(buf, 16, &data)) {
		dev_err(rtl->parent, "Invalid reg value %s\n", buf);
	} else {
		err = rtl8367_smi_write_reg(smi, reg, data);
		if (err) {
			dev_err(rtl->parent,
				"writing reg 0x%04x val 0x%04lx failed\n",
				reg, data);
		}
	}

	return count;
}

static const struct file_operations fops_rtl8367r_regs = {
	.read = rtl8367r_read_debugfs_reg,
	.write = rtl8367r_write_debugfs_reg,
	.open = rtl8367r_debugfs_open,
	.owner = THIS_MODULE
};

static void rtl8367r_debugfs_init(struct rtl8367r *rtl)
{
	struct dentry *node;
	struct dentry *root;

	if (!rtl->debugfs_root)
		rtl->debugfs_root = debugfs_create_dir("rtl8367r", NULL);

	if (!rtl->debugfs_root) {
		dev_err(rtl->parent, "Unable to create debugfs dir\n");
		return;
	}
	root = rtl->debugfs_root;

	node = debugfs_create_x16("reg", S_IRUGO | S_IWUSR, root, &g_dbg_reg);
	if (!node) {
		dev_err(rtl->parent, "Creating debugfs file reg failed\n");
		return;
	}

	node = debugfs_create_file("val", S_IRUGO | S_IWUSR, root, rtl,
				   &fops_rtl8367r_regs);
	if (!node) {
		dev_err(rtl->parent, "Creating debugfs file val failed\n");
		return;
	}
}

static void rtl8367r_debugfs_remove(struct rtl8367r *rtl)
{
	if (rtl->debugfs_root) {
		debugfs_remove_recursive(rtl->debugfs_root);
		rtl->debugfs_root = NULL;
	}
}

#else
static inline void rtl8367r_debugfs_init(struct rtl8367r *rtl)
{
}

static inline void rtl8367r_debugfs_remove(struct rtl8367r *rtl)
{
}
#endif				/* CONFIG_RTL8367R_PHY_DEBUG_FS */

static const char *rtl8367r_speed_str(unsigned speed)
{
	switch (speed) {
	case 0:
		return "10baseT";
	case 1:
		return "100baseT";
	case 2:
		return "1000baseT";
	}

	return "unknown";
}

static int rtl8367r_sw_get_port_link(struct switch_dev *dev,
				     const struct switch_attr *attr,
				     struct switch_val *val)
{
	struct rtl8367r *rtl = sw_to_rtl8367r(dev);
	struct rtl8367_smi *smi = &rtl->smi;
	u32 len = 0, data = 0;

	if (val->port_vlan >= RTL8367_NUM_PORTS)
		return -EINVAL;

	memset(rtl->buf, '\0', sizeof(rtl->buf));
	rtl8367_smi_read_reg(smi, RTL8367R_PORT_LINK_STATUS_BASE +
			     val->port_vlan, &data);

	len = snprintf(rtl->buf, sizeof(rtl->buf),
		       "port:%d link:%s speed:%s %s-duplex %s%s%s",
		       val->port_vlan,
		       (data & RTL8367R_PORT_STATUS_LINK_MASK) ? "up" : "down",
		       rtl8367r_speed_str(data &
					  RTL8367R_PORT_STATUS_SPEED_MASK),
		       (data & RTL8367R_PORT_STATUS_DUPLEX_MASK) ?
		       "full" : "half",
		       (data & RTL8367R_PORT_STATUS_TXPAUSE_MASK) ?
		       "tx-pause " : "",
		       (data & RTL8367R_PORT_STATUS_RXPAUSE_MASK) ?
		       "rx-pause " : "",
		       (data & RTL8367R_PORT_STATUS_AN_MASK) ? "nway " : "");

	val->value.s = rtl->buf;
	val->len = len;

	return 0;
}

static int rtl8367r_sw_reset_switch(struct switch_dev *dev)
{
	struct rtl8367r *rtl = sw_to_rtl8367r(dev);
	int err;

	err = rtl8367r_reset_chip(rtl);
	if (err)
		return err;

	return 0;
}

static struct switch_attr rtl8367r_globals[] = {
};

static struct switch_attr rtl8367r_port[] = {
	{
	 .type = SWITCH_TYPE_STRING,
	 .name = "link",
	 .description = "Get port link information",
	 .max = 1,
	 .set = NULL,
	 .get = rtl8367r_sw_get_port_link,
	 },
};

/* template */
static struct switch_dev rtl8367_switch_dev = {
	.name = "RTL8367R",
	.cpu_port = RTL8367_PORT_NUM_CPU,
	.ports = RTL8367_NUM_PORTS,
	.vlans = RTL8367_NUM_VLANS,
	.attr_global = {
			.attr = rtl8367r_globals,
			.n_attr = ARRAY_SIZE(rtl8367r_globals),
			},
	.attr_port = {
		      .attr = rtl8367r_port,
		      .n_attr = ARRAY_SIZE(rtl8367r_port),
		      },

	.reset_switch = rtl8367r_sw_reset_switch,
};

static int rtl8367r_switch_init(struct rtl8367r *rtl)
{
	struct switch_dev *dev = &rtl->dev;
	int err;

	memcpy(dev, &rtl8367_switch_dev, sizeof(struct switch_dev));
	dev->priv = rtl;
	dev->devname = dev_name(rtl->parent);

	err = register_switch(dev, NULL);
	if (err)
		dev_err(rtl->parent, "switch registration failed\n");

	return err;
}

static void rtl8367r_switch_cleanup(struct rtl8367r *rtl)
{
	unregister_switch(&rtl->dev);
}

static int rtl8367r_mii_read(struct mii_bus *bus, int addr, int reg)
{
	struct rtl8367r *rtl = bus->priv;
	u32 val = 0;
	int err;

	err = rtl8367r_read_phy_reg(rtl, addr, reg, &val);
	if (err)
		return 0xffff;

	return val;
}

static int rtl8367r_mii_write(struct mii_bus *bus, int addr, int reg, u16 val)
{
	struct rtl8367r *rtl = bus->priv;
	u32 t;
	int err;

	err = rtl8367r_write_phy_reg(rtl, addr, reg, val);
	/* flush write */
	(void)rtl8367r_read_phy_reg(rtl, addr, reg, &t);

	return err;
}

static inline int phy_speed(u32 reg)
{
	if ((reg & 0xc000) == 0x8000)
		return 1000;
	else if ((reg & 0xc000) == 0x4000)
		return 100;
	else if ((reg & 0xc000) == 0x0000)
		return 10;
	else
		return 0;
}

static inline char const *phy_duplex(u32 reg)
{
	return (reg & (1 << 13)) ? "Full" : "Half";
}

static void rtl8367r_work(struct work_struct *work)
{
	static u32 last[5];
	struct rtl8367r *rtl =
	    (void *)container_of(work, struct rtl8367r, work);
	struct rtl8367_smi *smi = &rtl->smi;
	u32 reg;
	int i;
#if 0
	bool low_speed = true;
#endif

	rtl8367_smi_read_reg(smi, RTL8367R_INTERRUPT_STATUS, &reg);
	rtl8367_smi_write_reg(smi, RTL8367R_INTERRUPT_STATUS, 0xff);
	if (!(reg & ((1 << 0) | (1 << 3))))
		return;

	for (i = 0; i < 5; ++i) {
		rtl8367r_write_phy_reg(rtl, i, 0x1f, 0);
		rtl8367r_read_phy_reg(rtl, i, MII_BMSR, &reg);
		reg = !!(reg & (BMSR_LSTATUS | BMSR_ANEGCOMPLETE));
		if (reg) {
#if 0
			low_speed = false;
#endif
			rtl8367r_read_phy_reg(rtl, i, 0x11, &reg);
			if (reg != last[i])
				dev_info(rtl->parent, "port:%d link:%s "
					 "speed:%d %s-duplex\n",
					 i, "Up",
					 phy_speed(reg), phy_duplex(reg));
		} else {
			if (reg != last[i])
				dev_info(rtl->parent, "port:%d link:%s\n",
					 i, "Down");
		}

		last[i] = reg;
	}

#if 0
	if (smi->low_speed_clock != low_speed) {
		u16 reg = low_speed ? 0x1000 : 0x1076;

		rtl8367_smi_write_reg(smi, 0x1310, reg);
		smi->low_speed_clock = low_speed;
		dev_info(rtl->parent, "%s powersave mode\n",
			 low_speed ? "entering" : "leaving");
	}
#endif
}

static irqreturn_t rtl8367r_isr(int irq, void *arg)
{
	struct rtl8367r *rtl = arg;

	schedule_work(&rtl->work);

	return IRQ_HANDLED;
}

static int rtl8367r_mii_init(struct rtl8367r *rtl)
{
	int ret;
	int i;

	rtl->mii_bus = mdiobus_alloc();
	if (rtl->mii_bus == NULL) {
		ret = -ENOMEM;
		goto err;
	}

	rtl->mii_bus->priv = (void *)rtl;
	rtl->mii_bus->name = "rtl8367-rtl";
	rtl->mii_bus->read = rtl8367r_mii_read;
	rtl->mii_bus->write = rtl8367r_mii_write;
	snprintf(rtl->mii_bus->id, MII_BUS_ID_SIZE, "%s",
		 dev_name(rtl->parent));
	rtl->mii_bus->parent = rtl->parent;
	rtl->mii_bus->phy_mask = ~(0x1f);
	rtl->mii_bus->irq = rtl->mii_irq;
	for (i = 0; i < PHY_MAX_ADDR; i++)
		rtl->mii_irq[i] = PHY_POLL;

	ret = mdiobus_register(rtl->mii_bus);
	if (ret)
		goto err_free;

	return 0;

 err_free:
	mdiobus_free(rtl->mii_bus);
 err:
	return ret;
}

static void rtl8367r_mii_cleanup(struct rtl8367r *rtl)
{
	mdiobus_unregister(rtl->mii_bus);
	mdiobus_free(rtl->mii_bus);
}

static int rtl8367r_mii_bus_match(struct mii_bus *bus)
{
	return (bus->read == rtl8367r_mii_read &&
		bus->write == rtl8367r_mii_write);
}

static int rtl8367r_setup(struct rtl8367r *rtl)
{
	struct rtl8367_smi *smi = &rtl->smi;
	u32 chip_id = 0;
	u32 chip_ver = 0;
	int ret;

	ret = rtl8367_smi_write_reg(smi, RTL8367R_MAGIC_ID_REG, 0x0249);
	if (ret) {
		dev_err(rtl->parent, "unable to write magic id\n");
		return ret;
	}

	ret = rtl8367_smi_read_reg(smi, RTL8367R_CHIP_ID_REG, &chip_id);
	if (ret) {
		dev_err(rtl->parent, "unable to read chip id\n");
		return ret;
	}

	switch (chip_id) {
	case RTL8367R_CHIP_ID_8367:
		break;
	default:
		dev_err(rtl->parent, "unknown chip id (%04x)\n", chip_id);
		return -ENODEV;
	}

	ret = rtl8367_smi_read_reg(smi, RTL8367R_CHIP_VERSION_CTRL_REG,
				   &chip_ver);
	if (ret) {
		dev_err(rtl->parent, "unable to read chip version\n");
		return ret;
	}

	dev_info(rtl->parent, "RTL%04x ver. %u chip found\n",
		 chip_id, chip_ver & RTL8367R_CHIP_VERSION_MASK);

	ret = rtl8367r_reset_chip(rtl);
	if (ret)
		return ret;

	rtl8367r_debugfs_init(rtl);
	return 0;
}

static int __init rtl8367r_probe(struct platform_device *pdev)
{
	static int rtl8367_smi_version_printed;
	struct rtl8367r_platform_data *pdata;
	struct rtl8367r *rtl;
	struct rtl8367_smi *smi;
	int err;

	if (!rtl8367_smi_version_printed++)
		printk(KERN_NOTICE RTL8367R_DRIVER_DESC
		       " version " RTL8367R_DRIVER_VER "\n");

	pdata = pdev->dev.platform_data;
	if (!pdata) {
		dev_err(&pdev->dev, "no platform data specified\n");
		err = -EINVAL;
		goto err_out;
	}

	rtl = kzalloc(sizeof(*rtl), GFP_KERNEL);
	if (!rtl) {
		dev_err(&pdev->dev, "no memory for private data\n");
		err = -ENOMEM;
		goto err_out;
	}

	rtl->parent = &pdev->dev;

	smi = &rtl->smi;
	smi->parent = &pdev->dev;
	smi->gpio_sda = pdata->gpio_sda;
	smi->gpio_sck = pdata->gpio_sck;

	err = rtl8367_smi_init(smi);
	if (err)
		goto err_free_rtl;

	platform_set_drvdata(pdev, rtl);

	err = rtl8367r_setup(rtl);
	if (err)
		goto err_clear_drvdata;

	err = rtl8367r_mii_init(rtl);
	if (err)
		goto err_clear_drvdata;

	err = rtl8367r_switch_init(rtl);
	if (err)
		goto err_mii_cleanup;

	if (pdata->irq > 0) {
		INIT_WORK(&rtl->work, rtl8367r_work);
		if (request_irq(pdata->irq, rtl8367r_isr,
				IRQF_SHARED | IRQF_TRIGGER_RISING,
				RTL8367R_DRIVER_NAME, rtl) < 0) {
			flush_scheduled_work();
			goto err_mii_cleanup;
		}
	}

	return 0;

 err_mii_cleanup:
	rtl8367r_mii_cleanup(rtl);
 err_clear_drvdata:
	platform_set_drvdata(pdev, NULL);
	rtl8367_smi_cleanup(smi);
 err_free_rtl:
	kfree(rtl);
 err_out:
	return err;
}

static int rtl8367r_phy_config_init(struct phy_device *phydev)
{
	if (!rtl8367r_mii_bus_match(phydev->bus))
		return -EINVAL;

	return 0;
}

static int rtl8367r_phy_config_aneg(struct phy_device *phydev)
{
	return 0;
}

static struct phy_driver rtl8367r_phy_driver = {
	.phy_id = 0x001cc800,
	.name = "Realtek RTL8367R",
	.phy_id_mask = 0x1ffffff0,
	.features = PHY_GBIT_FEATURES,
	.config_aneg = rtl8367r_phy_config_aneg,
	.config_init = rtl8367r_phy_config_init,
	.read_status = genphy_read_status,
	.driver = {
		   .owner = THIS_MODULE,
		   },
};

static int __devexit rtl8367r_remove(struct platform_device *pdev)
{
	struct rtl8367r *rtl = platform_get_drvdata(pdev);

	if (rtl) {
		rtl8367r_switch_cleanup(rtl);
		rtl8367r_debugfs_remove(rtl);
		rtl8367r_mii_cleanup(rtl);
		platform_set_drvdata(pdev, NULL);
		rtl8367_smi_cleanup(&rtl->smi);
		kfree(rtl);
	}

	return 0;
}

static struct platform_driver rtl8367r_driver = {
	.driver = {
		   .name = RTL8367R_DRIVER_NAME,
		   .owner = THIS_MODULE,
		   },
	.probe = rtl8367r_probe,
	.remove = __devexit_p(rtl8367r_remove),
};

static int __init rtl8367r_module_init(void)
{
	int ret;
	ret = platform_driver_register(&rtl8367r_driver);
	if (ret)
		return ret;

	ret = phy_driver_register(&rtl8367r_phy_driver);
	if (ret)
		goto err_platform_unregister;

	return 0;

 err_platform_unregister:
	platform_driver_unregister(&rtl8367r_driver);
	return ret;
}

module_init(rtl8367r_module_init);

static void __exit rtl8367r_module_exit(void)
{
	phy_driver_unregister(&rtl8367r_phy_driver);
	platform_driver_unregister(&rtl8367r_driver);
}

module_exit(rtl8367r_module_exit);

MODULE_DESCRIPTION(RTL8367R_DRIVER_DESC);
MODULE_VERSION(RTL8367R_DRIVER_VER);
MODULE_AUTHOR("Gabor Juhos <juhosg@openwrt.org>");
MODULE_AUTHOR("Antti Seppälä <a.seppala@gmail.com>");
MODULE_AUTHOR("Miguel Gaio <miguel.gaio@efixo.com>");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:" RTL8367R_DRIVER_NAME);
