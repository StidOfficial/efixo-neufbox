/*
 * switch-robo.c
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
 * $Id: switch-robo.c 20243 2011-04-14 09:00:24Z mgo $
 */

/* POSIX */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>

#include <unistd.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bcm53xx.h>

#ifdef NB4
#define LAN_BASE 2U
#define LAN0 2
#define LAN1 3
#define LAN2 4
#define LAN3 5
#else /* NB5 */
#define LAN_BASE 1U
#define LAN0 1
#define LAN1 2
#define LAN2 3
#define LAN3 4
#endif /* NB4:NB5 */

/*! \def ARRAY_SIZE
 *  \brief Count elements in static array
 */
#define ARRAY_SIZE( x ) (sizeof ( x ) / sizeof ( ( x ) [0] ) )

/*! \def ALIGN
 *  \brief Align value
 */
#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))

#define __noret __attribute__ ((__noreturn__))
#define __unused __attribute__ ((__unused__))

/*! \def matches( s, c_str )
 *  \brief Compare strings.
 *  \param data Data strings
 *  \param cstr C-Strings
 */
#define matches( s, c_str ) \
({ \
	const char __dummy[] = c_str; \
	(void)(&__dummy); \
	( memcmp ( s, c_str, sizeof( c_str ) ) == 0 ); \
})

#define __stringify_1(x)        #x
#define __stringify(x) __stringify_1(x)

static void __noret usage(void);

/*! \fn strtol_default(char const * buf, int def)
 *  \brief strtol with default value 
 *  \param buf String you want to convert into long
 *  \def   default value returned if strtol fails
 */
unsigned long xstrtoul(char const *nptr, int base)
{
	char *endptr;
	unsigned long ret;

	errno = 0;
	ret = strtoul(nptr, &endptr, base);
	if ((errno != 0) || (endptr == nptr) || (*endptr != '\0'))
		usage();

	return ret;
}

static inline unsigned switch_active_mask(void)
{
#ifdef NB4
	/* lan2, lan3, lan4, cpu */
	return 0x003FU;
#endif
#ifdef NB5
	/* lan1, lan2, lan3, lan4, cpu */
	return 0x010FU;
#endif
}

static char const *const ports_list_names[] = {
#ifdef NB4
	"lan2",
	"lan3",
	"lan4",
	NULL,
	"cpu",
#endif
#ifdef NB5
	"lan1",
	"lan2",
	"lan3",
	"lan4",
	NULL,
	NULL,
	NULL,
	NULL,
	"cpu",
#endif
};

static char const *port_name(unsigned id)
{

	if (id >= ARRAY_SIZE(ports_list_names))
		usage();

	return ports_list_names[id];
}

static unsigned port_id(char const *name)
{
#ifdef NB4
	if (matches(name, "lan2"))
		return 0U;
	else if (matches(name, "lan3"))
		return 1U;
	else if (matches(name, "lan4"))
		return 2U;
	else if (matches(name, "cpu"))
		return 5U;
	else
		return (unsigned)-1;
#endif
#ifdef NB5
	if (matches(name, "lan1"))
		return 0U;
	else if (matches(name, "lan2"))
		return 1U;
	else if (matches(name, "lan3"))
		return 2U;
	else if (matches(name, "lan4"))
		return 3U;
	else if (matches(name, "cpu"))
		return 8U;
	else
		return (unsigned)-1;
#endif
}

static unsigned port_mask(char const *name)
{
	unsigned id;

	id = port_id(name);
	if (id == (unsigned)-1)
		return 0U;
	else
		return (1U << id);
}

static void print_info(struct bcm53xx_arl const *entry)
{
	unsigned mask;
	bool valid;
	bool dynamic;
	bool age;

	if (has_bcm5325) {
		valid = entry->u.bcm5325.s.valid;
		dynamic = !entry->u.bcm5325.s._static;
		age = entry->u.bcm5325.s.age;
		mask = entry->u.bcm5325.s.portid;
	} else if (has_bcm5395) {
		valid = entry->u.bcm5395.s.valid;
		dynamic = !entry->u.bcm5395.s._static;
		age = entry->u.bcm5395.s.age;
		mask = entry->u.bcm5395.s.portid;
	}

	if (!valid)
		printf("  port:   [ - ]\n");
	else if (bcm53xx_l2_mcast(entry))
		printf("  port:   [ %s%s%s%s%s]%s%s\n",
		       (mask & port_mask("cpu")) ? "cpu " : "",
		       (mask & port_mask("lan1")) ? "lan1 " : "",
		       (mask & port_mask("lan2")) ? "lan2 " : "",
		       (mask & port_mask("lan3")) ? "lan3 " : "",
		       (mask & port_mask("lan4")) ? "lan4 " : "",
		       dynamic ? "" : " static", age ? " age" : "");
	else
		printf("  port:   [ %s ]%s%s\n",
		       (mask <
			ARRAY_SIZE(ports_list_names)) ? port_name(mask) : "",
		       dynamic ? "" : " static", age ? " age" : "");

}

#ifdef NB5
static void robo_stats32(char const *name, int fd, unsigned reg, unsigned mask)
{
	printf("%-20s:", name);
	for (int i = 0; i <= 8; ++i)
		if (mask & (1 << i))
			printf(" %12u",
			       bcm53xx_r32(fd, PAGE_PORT0_MIB + i, reg));
	printf("\n");
}

static void robo_stats64(char const *name, int fd, unsigned reg, unsigned mask)
{
	printf("%-20s:", name);
	for (int i = 0; i <= 8; ++i)
		if (mask & (1 << i))
			printf(" %12" PRIi64 "u",
			       bcm53xx_r64(fd, PAGE_PORT0_MIB + i, reg));
	printf("\n");
}

static void robo_stats(int fd, unsigned mask)
{
	printf("%-20s:", "stats");
	for (int i = 0; i <= 8; ++i)
		if (mask & (1 << i))
			printf(" %12s", port_name(i));
	printf("\n");

	printf("\n===== %s =====\n", "TX packets");
	robo_stats64("bytes", fd, 0x00U, mask);
	robo_stats32("drop", fd, 0x08U, mask);
	/* robo_stats32( "qos 0", fd, 0x0CU, mask ); */
	robo_stats32("broadcast", fd, 0x10U, mask);
	robo_stats32("multicast", fd, 0x14U, mask);
	robo_stats32("unicast", fd, 0x18U, mask);
	robo_stats32("collisions", fd, 0x1CU, mask);
	robo_stats32("single collisions", fd, 0x20U, mask);
	robo_stats32("multiple collisions", fd, 0x24U, mask);
	robo_stats32("deferred transmit", fd, 0x28U, mask);
	robo_stats32("late collision", fd, 0x2CU, mask);
	robo_stats32("excessive collision", fd, 0x30U, mask);
	robo_stats32("frame in disc", fd, 0x34U, mask);
	robo_stats32("pause", fd, 0x38U, mask);
	printf("--\n");
	robo_stats32("qos 0", fd, 0x0CU, mask);
	robo_stats32("qos 1", fd, 0x3CU, mask);
	robo_stats32("qos 2", fd, 0x40U, mask);
	robo_stats32("qos 3", fd, 0x44U, mask);

	printf("\n===== %s =====\n", "RX packets");
	robo_stats64("bytes", fd, 0x50U, mask);
	robo_stats64("good bytes", fd, 0x88U, mask);
	robo_stats32("undersize", fd, 0x58U, mask);
	robo_stats32("pause", fd, 0x5CU, mask);
	/* robo_stats32( "0-64 bytes", fd, 0x60U, mask ); */
	/* robo_stats32( "65-127 bytes", fd, 0x64U, mask ); */
	/* robo_stats32( "128-255 bytes", fd, 0x68U, mask ); */
	/* robo_stats32( "256-511 bytes", fd, 0x6CU, mask ); */
	/* robo_stats32( "512-1023 bytes", fd, 0x70U, mask ); */
	/* robo_stats32( "1024-1522 bytes", fd, 0x74U, mask ); */
	robo_stats32("oversize", fd, 0x78U, mask);
	robo_stats32("jabbers", fd, 0x7CU, mask);
	robo_stats32("alignment errors", fd, 0x80U, mask);
	robo_stats32("fcs errors", fd, 0x84U, mask);
	robo_stats32("drop", fd, 0x90U, mask);
	robo_stats32("unicast", fd, 0x94U, mask);
	robo_stats32("multicast", fd, 0x98U, mask);
	robo_stats32("broadcast", fd, 0x9CU, mask);
	robo_stats32("sa changes", fd, 0xA0U, mask);
	robo_stats32("fragments", fd, 0xA4U, mask);
	robo_stats32("excess size disc", fd, 0xA8U, mask);
	robo_stats32("symbol errors", fd, 0xACU, mask);
	robo_stats32("discard:", fd, 0xC0U, mask);
	printf("--\n");
	robo_stats32("0-64 bytes", fd, 0x60U, mask);
	robo_stats32("65-127 bytes", fd, 0x64U, mask);
	robo_stats32("128-255 bytes", fd, 0x68U, mask);
	robo_stats32("256-511 bytes", fd, 0x6CU, mask);
	robo_stats32("512-1023 bytes", fd, 0x70U, mask);
	robo_stats32("1024-1522 bytes", fd, 0x74U, mask);
	robo_stats32("1523-2047 bytes", fd, 0xB0U, mask);
	robo_stats32("2048-4095 bytes", fd, 0xB4U, mask);
	robo_stats32("4096-8181 bytes", fd, 0xB8U, mask);
	robo_stats32("8192-9728 bytes", fd, 0xBCU, mask);
}
#endif

static void __noret cmd_reset(int argc __unused, char const *argv[]__unused)
{
	int fd;

	fd = bcm53xx_open("eth1");
#ifdef NB5
	bcm53xx_w8(fd, 0x00, 0x79, 0x90);
#endif /* NB5 */
	bcm53xx_close(fd);

	exit(EXIT_SUCCESS);
}

static void __noret cmd_stats(int argc, char const *argv[])
{
	int fd;
	unsigned mask = ~0U;

	if ((argc > 2) && (matches(argv[2], "ports"))) {
		mask = 0x00U;

		for (int i = 3; i < argc; ++i)
			mask |= port_mask(argv[i]);
	}

	mask &= switch_active_mask();

	fd = bcm53xx_open("eth1");
#ifdef NB5
	robo_stats(fd, mask);
#endif
	bcm53xx_close(fd);

	exit(EXIT_SUCCESS);
}

static void __noret cmd_arl(int argc, char const *argv[])
{
	int fd;
	struct bcm53xx_arl entry;
	struct ether_addr e;

	if ((argc < 3) || (!ether_aton_r(argv[2], &e)))
		usage();

	fd = bcm53xx_open("eth1");
	bcm53xx_l2_entry(fd, &e, &entry);
	if (argc == 5) {
		if (matches(argv[3], "add")) {
			if (has_bcm5325) {
				entry.u.bcm5325.s.valid = 1;
				entry.u.bcm5325.s._static = 1;
				entry.u.bcm5325.s.portid |= port_mask(argv[4]);
			}
			if (has_bcm5395) {
				entry.u.bcm5395.s.valid = 1;
				entry.u.bcm5395.s._static = 1;
				entry.u.bcm5395.s.portid |= port_mask(argv[4]);
			}
			bcm53xx_l2_setup(fd, &e, &entry);
			bcm53xx_l2_entry(fd, &e, &entry);
		} else if (matches(argv[3], "del")) {
			if (has_bcm5325) {
				entry.u.bcm5325.s.portid &= ~port_mask(argv[4]);
				/* delete empty entry */
				if (entry.u.bcm5325.s.portid ==
				    ROBO_5325_ARL_CPU_PORT
				    || !entry.u.bcm5325.s.portid) {
					memset(&entry, 0x00, sizeof(entry));
				}
			}
			if (has_bcm5395) {
				entry.u.bcm5395.s.portid &= ~port_mask(argv[4]);
				/* delete empty entry */
				if (entry.u.bcm5395.s.portid ==
				    ROBO_5395_ARL_CPU_PORT
				    || !entry.u.bcm5395.s.portid) {
					memset(&entry, 0x00, sizeof(entry));
				}
			}
			bcm53xx_l2_setup(fd, &e, &entry);
			bcm53xx_l2_entry(fd, &e, &entry);
		}
	}

	bcm53xx_close(fd);

	print_info(&entry);

	exit(EXIT_SUCCESS);
}

static void cmd_qos(int argc, char const *argv[])
{
	int fd;
	unsigned dscp;
	unsigned queue;

	if (argc == 2) {
		fd = bcm53xx_open("eth1");
		for (dscp = 0U; dscp < DSCP_COUNT; ++dscp) {
			queue = bcm53xx_diffserv_get(fd, dscp);
			if (queue)
				printf("QoS: DSCP:0x%X queue:%o\n",
				       dscp, queue);
		}
		bcm53xx_close(fd);
		exit(EXIT_SUCCESS);
	}

	dscp = xstrtoul(argv[2], 0);
	fd = bcm53xx_open("eth1");
	if (argc == 4) {
		queue = xstrtoul(argv[3], 8);
		bcm53xx_diffserv_set(fd, dscp, queue);
	}

	queue = bcm53xx_diffserv_get(fd, dscp);
	bcm53xx_close(fd);

	printf("QoS: DSCP:0x%X queue:%o\n", dscp, queue);

	exit(EXIT_SUCCESS);
}

static void __noret cmd_lowlevel(int argc, char const *argv[])
{
	int fd;
	uint16_t page, reg, len;
	uint16_t raw[4];

	/* low level  management */
	if (argc < 4) {
		usage();
	}

	page = xstrtoul(argv[1], 16);
	reg = xstrtoul(argv[2], 16);
	len = xstrtoul(argv[3], 16);

	fd = bcm53xx_open("eth1");

	if (argc == 4) {
		printf("  -> Page %02Xh: Address %02Xh = ", page, reg);

		switch (len) {
		case 1:
			printf("[%02Xh]\n", bcm53xx_r8(fd, page, reg));
			break;

		case 2:
			printf("[%04Xh]\n", bcm53xx_r16(fd, page, reg));
			break;

		case 4:
			printf("[%08Xh]\n", bcm53xx_r32(fd, page, reg));
			break;

		case 6:
			bcm53xx_r48(fd, page, reg, raw);
			printf("[%02X%02X%02Xh]\n", raw[0], raw[1], raw[2]);
			break;

		case 8:
			printf("[%016" PRIi64 "Xh]\n",
			       bcm53xx_r64(fd, page, reg));
			break;
		}
	} else {
		uint64_t val = xstrtoul(argv[4], 16);
		switch (len) {
		case 1:
			bcm53xx_w8(fd, page, reg, (uint8_t) val);
			break;

		case 2:
			bcm53xx_w16(fd, page, reg, (uint16_t) val);
			break;

		case 4:
			bcm53xx_w32(fd, page, reg, (uint32_t) val);
			break;

		case 6:
			bcm53xx_w48(fd, page, reg, &val);
			break;

		case 8:
			bcm53xx_w64(fd, page, reg, (uint64_t) val);
			break;
		}
	}

	bcm53xx_close(fd);

	exit(EXIT_SUCCESS);
}

static void __noret usage(void)
{
	fprintf(stderr, "usage: switch-robo <page> <reg> <len> [data]\n"
		"                   qos [<dscp> [queue]]\n"
		"                   arl <ether> [<add|del> <port>]\n"
		"                   stats [<ports> <port list...>]\n"
		"\n" "  ports: lan1, lan2, lan3, lan4, cpu\n");

	exit(EXIT_FAILURE);
}

int main(int argc, char const *argv[])
{
	if (argc < 2)
		usage();
	else if (matches(argv[1], "reset"))
		cmd_reset(argc, argv);
	else if (matches(argv[1], "stats"))
		cmd_stats(argc, argv);
	else if (matches(argv[1], "arl"))
		cmd_arl(argc, argv);
	else if (matches(argv[1], "qos"))
		cmd_qos(argc, argv);
	else
		cmd_lowlevel(argc, argv);

	return 0;
}
