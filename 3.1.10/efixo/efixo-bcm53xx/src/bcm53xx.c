/*!
 * \file lib/robo_switch.c
 *
 * \author Copyright 2007 Gaio Miguel <miguel.gaio@efixo.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 * 
 * $Id: bcm53xx.c 20243 2011-04-14 09:00:24Z mgo $
 */

/* POSIX */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <etk/log.h>
#include <bcm53xx.h>

static char const *ifname;

int bcm53xx_open(char const *_ifname)
{
	int fd = 0;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		sys_err("%s( %d, %d, 0 )", "socket", AF_INET, SOCK_DGRAM);
		return -1;
	}

	ifname = _ifname;

	return fd;
}

void bcm53xx_close(int fd)
{
	close(fd);
}

static int bcm53xx_do_ioctl(int fd, int rq, void *priv)
{
	struct ifreq ifr;

	memset(&ifr, 0x00, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
	ifr.ifr_data = priv;

	if (ioctl(fd, rq, &ifr) < 0) {
		sys_err("%d", rq);
		return -1;
	}

	return 0;
}

uint8_t bcm53xx_r8(int fd, unsigned page, unsigned reg)
{
	struct bcm53xx_ioctl_data priv;

	priv.page = page;
	priv.reg = reg;
	priv.len = sizeof(uint8_t);
	bcm53xx_do_ioctl(fd, SIOCGROBOREGS, &priv);

	return priv.u.u16;
}

uint16_t bcm53xx_r16(int fd, unsigned page, unsigned reg)
{
	struct bcm53xx_ioctl_data priv;

	priv.page = page;
	priv.reg = reg;
	priv.len = sizeof(uint16_t);
	bcm53xx_do_ioctl(fd, SIOCGROBOREGS, &priv);

	return priv.u.u16;
}

uint32_t bcm53xx_r32(int fd, unsigned page, unsigned reg)
{
	struct bcm53xx_ioctl_data priv;

	priv.page = page;
	priv.page = page;
	priv.reg = reg;
	priv.len = sizeof(uint32_t);
	bcm53xx_do_ioctl(fd, SIOCGROBOREGS, &priv);

	return priv.u.u32;
}

void bcm53xx_r48(int fd, unsigned page, unsigned reg, void *v48)
{
	struct bcm53xx_ioctl_data priv;

	priv.page = page;
	priv.reg = reg;
	priv.len = 6;
	bcm53xx_do_ioctl(fd, SIOCGROBOREGS, &priv);

	memcpy(v48, &priv.u.raw, 6);
}

uint64_t bcm53xx_r64(int fd, unsigned page, unsigned reg)
{
	struct bcm53xx_ioctl_data priv;

	priv.page = page;
	priv.reg = reg;
	priv.len = sizeof(uint64_t);
	bcm53xx_do_ioctl(fd, SIOCGROBOREGS, &priv);

	return priv.u.u64;
}

void bcm53xx_w8(int fd, unsigned page, unsigned reg, uint8_t v)
{
	struct bcm53xx_ioctl_data priv;

	priv.page = page;
	priv.reg = reg;
	priv.len = sizeof(v);
	priv.u.u16 = v;
	bcm53xx_do_ioctl(fd, SIOCSROBOREGS, &priv);
}

void bcm53xx_w16(int fd, unsigned page, unsigned reg, uint16_t v)
{
	struct bcm53xx_ioctl_data priv;

	priv.page = page;
	priv.reg = reg;
	priv.len = sizeof(v);
	priv.u.u16 = v;

	bcm53xx_do_ioctl(fd, SIOCSROBOREGS, &priv);
}

void bcm53xx_w32(int fd, unsigned page, unsigned reg, uint32_t v)
{
	struct bcm53xx_ioctl_data priv;

	priv.page = page;
	priv.reg = reg;
	priv.len = sizeof(v);
	priv.u.u32 = v;
	bcm53xx_do_ioctl(fd, SIOCSROBOREGS, &priv);
}

void bcm53xx_w48(int fd, unsigned page, unsigned reg, void const *v)
{
	struct bcm53xx_ioctl_data priv;

	priv.page = page;
	priv.reg = reg;
	priv.len = 6;
	priv.u.u64 = 0UL;
	memcpy(priv.u.raw, v, 6);
	bcm53xx_do_ioctl(fd, SIOCSROBOREGS, &priv);
}

void bcm53xx_w64(int fd, unsigned page, unsigned reg, uint64_t v)
{
	struct bcm53xx_ioctl_data priv;

	priv.page = page;
	priv.reg = reg;
	priv.len = sizeof(v);
	priv.u.u64 = v;
	bcm53xx_do_ioctl(fd, SIOCSROBOREGS, &priv);
}

/* l2 lookup table */

static void bcm53xx_l2_lookup_start(int fd, struct ether_addr const *e)
{
	uint8_t v = (ROBO_ARL_CONTROL_READ | ROBO_ARL_CONTROL_START);

	/* mac address: index register */
	bcm53xx_w48(fd, PAGE_ARL, ROBO_ARL_ADDR_INDEX, e);
	/* read access */
	bcm53xx_w8(fd, PAGE_ARL, ROBO_ARL_CONTROL, v);
}

static void bcm53xx_l2_commit(int fd)
{
	uint8_t v = (ROBO_ARL_CONTROL_START);

	/* commit */
	bcm53xx_w8(fd, PAGE_ARL, ROBO_ARL_CONTROL, v);
}

static void bcm5325_l2_read(int fd, unsigned n, struct
			    bcm53xx_arl *entry)
{
	entry->u.bcm5325.raw = bcm53xx_r64(fd, PAGE_ARL, ROBO_ARL_ENTRY0 + n);
}

static void bcm5395_l2_read(int fd, unsigned n, struct
			    bcm53xx_arl *entry)
{
	entry->u.bcm5395.raw.u64 =
	    bcm53xx_r64(fd, PAGE_ARL, ROBO_ARL_ENTRY0 + n);
	entry->u.bcm5395.raw.u32 =
	    bcm53xx_r32(fd, PAGE_ARL, ROBO_ARL_ENTRY1 + n);
}

static void bcm53xx_l2_read(int fd, unsigned n, struct bcm53xx_arl *entry)
{
	if (has_bcm5325)
		bcm5325_l2_read(fd, n, entry);
	if (has_bcm5395)
		bcm5395_l2_read(fd, n, entry);
}

static void bcm5325_l2_write(int fd, unsigned n, struct
			     bcm53xx_arl *entry, struct ether_addr const *e)
{
	memcpy(entry->u.bcm5325.s.mac_address, e, sizeof(*e));
	bcm53xx_w64(fd, PAGE_ARL, ROBO_ARL_ENTRY0 + n, entry->u.bcm5325.raw);
}

static void bcm5395_l2_write(int fd, unsigned n, struct
			     bcm53xx_arl *entry, struct ether_addr const *e)
{
	entry->u.bcm5395.raw.u64 = 0UL;
	memcpy(entry->u.bcm5395.s.mac_address, e, sizeof(*e));
	bcm53xx_w64(fd, PAGE_ARL,
		    ROBO_ARL_ENTRY0 + n, entry->u.bcm5395.raw.u64);
	bcm53xx_w32(fd, PAGE_ARL, ROBO_ARL_ENTRY1 + n,
		    entry->u.bcm5395.raw.u32);
}

static void bcm53xx_l2_write(int fd, unsigned n, struct bcm53xx_arl
			     *entry, struct ether_addr const *e)
{
	if (has_bcm5325)
		bcm5325_l2_write(fd, n, entry, e);
	if (has_bcm5395)
		bcm5395_l2_write(fd, n, entry, e);
}

static int bcm53xx_l2_matches(struct bcm53xx_arl const
			      *entry, struct ether_addr const *e)
{
	if (has_bcm5325)
		return !memcmp(entry->u.bcm5325.s.mac_address, e, sizeof(*e));
	if (has_bcm5395)
		return !memcmp(entry->u.bcm5395.s.mac_address, e, sizeof(*e));
}

int bcm53xx_l2_entry(int fd, struct ether_addr const *e,
		     struct bcm53xx_arl *entry)
{
	unsigned n;
	unsigned count;
	off_t off;

	if (has_bcm5325) {
		off = sizeof(*entry);
		count = ROBO_5325_ARL_ENTRY_COUNT * off;
	}
	if (has_bcm5395) {
		off = sizeof(*entry);
		count = ROBO_5395_ARL_ENTRY_COUNT * off;
	}

	bcm53xx_l2_lookup_start(fd, e);
	for (n = 0U; n < count; n += off) {
		bcm53xx_l2_read(fd, n, entry);
		if (bcm53xx_l2_matches(entry, e))
			return 0;

	}

	return -1;
}

int bcm53xx_l2_setup(int fd, struct ether_addr const *e,
		     struct bcm53xx_arl const *entry)
{
	struct bcm53xx_arl cur;
	unsigned n;
	unsigned found = 0;
	unsigned count;
	off_t off;

	if (has_bcm5325) {
		off = sizeof(*entry);
		count = ROBO_5325_ARL_ENTRY_COUNT * off;
	}
	if (has_bcm5395) {
		off = sizeof(*entry);
		count = ROBO_5395_ARL_ENTRY_COUNT * off;
	}

	/* lookup for already allocated */
	bcm53xx_l2_lookup_start(fd, e);
	for (n = 0U; n < count; n += off) {
		bcm53xx_l2_read(fd, n, &cur);
		if (bcm53xx_l2_matches(&cur, e)) {
			cur = *entry;
			bcm53xx_l2_write(fd, n, &cur, e);
			bcm53xx_l2_commit(fd);
			found = 1;
		}
	}

	if (found) {
		return 0;
	}

	found = 0;
	/* lookup for free entry */
	for (n = 0U; n < count; n += off) {
		bcm53xx_l2_read(fd, n, &cur);
		if (!bcm53xx_l2_valid(&cur)) {
			cur = *entry;
			bcm53xx_l2_write(fd, n, &cur, e);
			bcm53xx_l2_commit(fd);
			found = 1;
		}
	}

	if (!found) {
		err("%s( %s )", __func__, ether_ntoa(e));
		return -1;
	}

	return 0;
}

int bcm53xx_l2_mcast_add(struct ether_addr const *e, uint32_t port)
{
	struct bcm53xx_arl entry;
	int fd;
	int ret;

	fd = bcm53xx_open("eth1");

	ret = bcm53xx_l2_entry(fd, e, &entry);
	if (ret < 0)		/* not defined */
		memset(&entry, 0x00, sizeof(entry));

	if (has_bcm5325) {
		entry.u.bcm5325.s.valid = 1;
		entry.u.bcm5325.s._static = 1;
		entry.u.bcm5325.s.portid |=
		    ROBO_5325_ARL_CPU_PORT | (1 << port);
	}
	if (has_bcm5395) {
		entry.u.bcm5395.s.valid = 1;
		entry.u.bcm5395.s._static = 1;
		entry.u.bcm5395.s.portid |=
		    ROBO_5395_ARL_CPU_PORT | (1 << port);
	}
	ret = bcm53xx_l2_setup(fd, e, &entry);
	if (ret < 0)
		warn("[IGMP] arl entry (%s) not found", ether_ntoa(e));
	bcm53xx_close(fd);

	return ret;
}

int bcm53xx_l2_mcast_del(struct ether_addr const *e, uint32_t port)
{
	struct bcm53xx_arl entry;
	int fd;
	int ret;

	fd = bcm53xx_open("eth1");

	ret = bcm53xx_l2_entry(fd, e, &entry);
	if (ret < 0) {		/* not defined */
		warn("[IGMP] arl entry (%s) not found", ether_ntoa(e));
		bcm53xx_close(fd);
		return -1;
	}

	if (has_bcm5325) {
		entry.u.bcm5325.s.portid &= ~(1 << port);
		if (entry.u.bcm5325.s.portid == ROBO_5325_ARL_CPU_PORT)	/* delete empty entry */
			entry.u.bcm5325.s._static = 0;
	}
	if (has_bcm5395) {
		entry.u.bcm5395.s.portid &= ~(1 << port);
		if (entry.u.bcm5395.s.portid == ROBO_5395_ARL_CPU_PORT)	/* delete empty entry */
			entry.u.bcm5395.s._static = 0;
	}

	ret = bcm53xx_l2_setup(fd, e, &entry);
	if (ret < 0)
		warn("[IGMP] arl entry (%s) not found", ether_ntoa(e));

	bcm53xx_close(fd);

	return ret;
}

/* diffserv */

unsigned bcm53xx_diffserv_get(int fd, unsigned dscp)
{
	unsigned reg;
	uint64_t v64;

	reg = QOS_PRIO_DSCP_REG(dscp);
	v64 = bcm53xx_qos_map_read(fd, reg);

	v64 >>= QOS_PRIO_DSCP_SHIFT(dscp);
	v64 &= QOS_PRIO_DSCP_MASK;

	return (unsigned)v64;
}

void bcm53xx_diffserv_set(int fd, unsigned dscp, unsigned queue)
{
	unsigned reg;
	uint64_t v64;

	reg = QOS_PRIO_DSCP_REG(dscp);
	v64 = bcm53xx_qos_map_read(fd, reg);
	v64 &= ~(QOS_PRIO_DSCP_MASK << QOS_PRIO_DSCP_SHIFT(dscp));
	v64 |= (CAST(queue) << QOS_PRIO_DSCP_SHIFT(dscp));
	bcm53xx_qos_map_write(fd, reg, v64);
}
