
#ifndef _LINUX_BCMPHY_H_
#define _LINUX_BCMPHY_H_
#ifdef __KERNEL__

#include <linux/spinlock.h>

struct bcmphy {
	char const *name;
	struct net_device *dev;
	spinlock_t lock;
	unsigned (*read) (struct bcmphy *, unsigned);
	unsigned (*write) (struct bcmphy *, unsigned, unsigned);
	unsigned dev_id;
	unsigned id;
	unsigned ports_count;
};

static inline unsigned bcmphy_read(struct bcmphy *phy, unsigned reg)
{
	return phy->read(phy, reg);
}

static inline unsigned bcmphy_write(struct bcmphy *phy, unsigned reg,
				    unsigned val)
{
	return phy->write(phy, reg, val);
}

static inline void bcmphy_print_status(char const *name, unsigned link,
				       unsigned speed, unsigned duplex)
{
	printk("%s - Link is %s", name, link ? "Up" : "Down");
	if (link)
		printk(" - %d/%s", speed, duplex ? "Full" : "Half");
	printk("\n");
}

#endif
#endif
