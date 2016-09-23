/*
 * Broadcom BCM5325E/536x switch configuration utility
 *
 * Copyright (C) 2005 Oleg I. Vdovikin
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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

/* linux stuff */
#include <linux/mii.h>
#include <linux/ethtool.h>

#include <bcm53xx.h>

#define ROBO_PHY_ADDR	0x01	/* robo switch phy address */

#define __unused __attribute__ ( ( unused ) )

/*! \def ARRAY_SIZE
 *  \brief Count elements in static array
 */
#define ARRAY_SIZE( x ) (sizeof ( x ) / sizeof ( ( x ) [0] ) )

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

/*! \def err( fmt, ... )
 *  \brief Log message.
 *  \param fmt Log message
 *  \param ... Arguments list
 */
#define err( fmt, ... ) \
	fprintf( stderr, fmt,  ##__VA_ARGS__ )

typedef struct {
	struct ifreq ifr;
	int fd;
	int et;			/* use private ioctls */
} robo_t;

static uint16_t mdio_read(robo_t * robo, uint16_t phy_id, uint8_t reg)
{
	struct mii_ioctl_data *mii = (void *)&robo->ifr.ifr_data;
	mii->phy_id = phy_id;
	mii->reg_num = reg;
	if (ioctl(robo->fd, SIOCGMIIREG, &robo->ifr) < 0) {
		err("%s( %d, %s, %p ) %m\n", "ioctl", robo->fd, "SIOGSMIIREG",
		    &robo->ifr);
		exit(EXIT_FAILURE);
	}
	return mii->val_out;
}

static void mdio_write(robo_t * robo, uint16_t phy_id, uint8_t reg,
		       uint16_t val)
{
	struct mii_ioctl_data *mii = (void *)&robo->ifr.ifr_data;
	mii->phy_id = phy_id;
	mii->reg_num = reg;
	mii->val_in = val;
	if (ioctl(robo->fd, SIOCSMIIREG, &robo->ifr) < 0) {
		err("%s( %d, %s, %p ) %m\n", "ioctl", robo->fd, "SIOCSMIIREG",
		    &robo->ifr);
		exit(EXIT_FAILURE);
	}
}

uint8_t port[] = { 0, 1, 2, 3, 4, 8 };
char ports[] = { 'W', '4', '3', '2', '1', 'C' };
char *rxtx[] = { "enabled", "rx_disabled", "tx_disabled", "disabled" };
char *stp[] =
    { "none", "disable", "block", "listen", "learn", "forward", "6", "7" };

struct {
	char *name;
	uint16_t bmcr;
} media[] = {
	{
	"auto", BMCR_ANENABLE | BMCR_ANRESTART}, {
	"10HD", 0}, {
	"10FD", BMCR_FULLDPLX}, {
	"100HD", BMCR_SPEED100}, {
	"100FD", BMCR_SPEED100 | BMCR_FULLDPLX}, {
	"1000HD", BMCR_SPEED1000}, {
	"1000FD", BMCR_SPEED1000 | BMCR_FULLDPLX}
};

struct {
	char *name;
	uint16_t value;
} mdix[] = {
	{
	"auto", 0x0000}, {
	"on", 0x1800}, {
	"off", 0x0800}
};

static void __attribute__ ((noreturn)) usage(void)
{
	err("Broadcom BCM5325E/536x switch configuration utility\n"
	    "Copyright (C) 2005 Oleg I. Vdovikin\n\n"
	    "This program is distributed in the hope that it will be useful,\n"
	    "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
	    "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the\n"
	    "GNU General Public License for more details.\n\n");

	err("Usage: robocfg <op> ... <op>\n"
	    "Operations are as below:\n"
	    "\tshow\n"
	    "\tswitch <enable|disable>\n"
	    "\tport <port_number> [state <%s|%s|%s|%s>]\n\t\t[stp %s|%s|%s|%s|%s|%s] [tag <vlan_tag>]\n"
	    "\t\t[media %s|%s|%s|%s|%s|%s|%s] [mdi-x %s|%s|%s]\n"
	    "\tvlan <vlan_number> [ports <ports_list>]\n"
	    "\tvlans <enable|disable|reset>\n\n"
	    "\tports_list should be one argument, space separated, quoted if needed,\n"
	    "\tport number could be followed by 't' to leave packet vlan tagged (CPU \n"
	    "\tport default) or by 'u' to untag packet (other ports default) before \n"
	    "\tbringing it to the port, '*' is ignored\n"
	    "\nSamples:\n"
	    "1) ASUS WL-500g Deluxe stock config (eth0 is WAN, eth0.1 is LAN):\n"
	    "robocfg switch disable vlans enable reset vlan 0 ports \"0 5u\" vlan 1 ports \"1 2 3 4 5t\""
	    " port 0 state enabled stp none switch enable\n"
	    "2) WRT54g, WL-500g Deluxe OpenWRT config (vlan0 is LAN, vlan1 is WAN):\n"
	    "robocfg switch disable vlans enable reset vlan 0 ports \"1 2 3 4 5t\" vlan 1 ports \"0 5t\""
	    " port 0 state enabled stp none switch enable\n",
	    rxtx[0], rxtx[1], rxtx[2], rxtx[3], stp[0], stp[1], stp[2],
	    stp[3], stp[4], stp[5], media[0].name, media[1].name,
	    media[2].name, media[3].name, media[4].name, media[5].name,
	    media[6].name, mdix[0].name, mdix[1].name, mdix[2].name);

	exit(EXIT_FAILURE);
}

static int cmd_port_state(robo_t * robo, int argc __unused, char *argv[],
			  int i, int n)
{
	unsigned j;

	for (j = 0; j < ARRAY_SIZE(rxtx) && strcasecmp(argv[i], rxtx[j]); j++) ;

	if (j < ARRAY_SIZE(rxtx)) {
		uint16_t v16;

		v16 = bcm53xx_r16(robo->fd, PAGE_CONTROL, port[n]);
		/* change state */
		v16 &= ~(3 << 0);
		v16 |= (j << 0);
		bcm53xx_w16(robo->fd, PAGE_CONTROL, port[n], v16);
	} else {
		err("Invalid state '%s'.\n", argv[i]);
		exit(EXIT_FAILURE);
	}

	return i;
}

static int cmd_port_stp(robo_t * robo, int argc __unused, char *argv[], int i,
			int n)
{
	unsigned j;

	for (j = 0; j < ARRAY_SIZE(stp)
	     && strcasecmp(argv[i], stp[j]); j++) ;

	if (j < ARRAY_SIZE(stp)) {
		uint16_t v16;

		v16 = bcm53xx_r16(robo->fd, PAGE_CONTROL, port[n]);
		/* change stp */
		v16 &= ~(7 << 5);
		v16 |= (j << 5);
		bcm53xx_w16(robo->fd, PAGE_CONTROL, port[n], v16);
	} else {
		err("Invalid stp '%s'.\n", argv[i]);
		exit(EXIT_FAILURE);
	}

	return i;
}

static int cmd_port_media(robo_t * robo, int argc __unused, char *argv[],
			  int i, int n)
{
	unsigned j;

	for (j = 0; j < ARRAY_SIZE(media)
	     && strcasecmp(argv[i], media[j].name); j++) ;

	if (j < ARRAY_SIZE(media)) {
		mdio_write(robo, port[n], MII_BMCR, media[j].bmcr);
	} else {
		err("Invalid media '%s'.\n", argv[i]);
		exit(EXIT_FAILURE);
	}

	return i;
}

static int cmd_port_mdix(robo_t * robo, int argc __unused, char *argv[], int i,
			 int n)
{
	unsigned j;

	for (j = 0; j < ARRAY_SIZE(mdix)
	     && strcasecmp(argv[i], mdix[j].name); j++) ;

	if (j < ARRAY_SIZE(mdix)) {
		uint16_t v16;

		v16 = mdio_read(robo, port[n], 0x1c);
		v16 &= ~0x1800;
		v16 |= mdix[j].value, mdio_write(robo, port[n], 0x1c, v16);
	} else {
		err("Invalid mdi-x '%s'.\n", argv[i]);
		exit(EXIT_FAILURE);
	}

	return i;
}

static int cmd_port_tag(robo_t * robo, int argc __unused, char *argv[], int i,
			int n)
{
	unsigned j;

	j = atoi(argv[i]);
	/* change n tag */
	bcm53xx_w16(robo->fd, PAGE_VLAN, ROBO_VLAN_PTAG0 + (n << 1), j);

	return i;
}

static int cmd_port(robo_t * robo, int argc, char *argv[], int i)
{
	int n = atoi(argv[++i]);

	/* read port specs */
	while (++i < argc) {
		if (matches(argv[i], "state") && ++i < argc) {
			i = cmd_port_state(robo, argc, argv, i, n);
		} else if (matches(argv[i], "stp") && ++i < argc) {
			i = cmd_port_stp(robo, argc, argv, i, n);
		} else if (matches(argv[i], "media") && ++i < argc) {
			i = cmd_port_media(robo, argc, argv, i, n);
		} else if (matches(argv[i], "mdi-x") && ++i < argc) {
			i = cmd_port_mdix(robo, argc, argv, i, n);
		} else if (matches(argv[i], "tag") && ++i < argc) {
			i = cmd_port_tag(robo, argc, argv, i, n);
		} else {
			break;
		}
	}

	return i;
}

static int cmd_vlan_ports(robo_t * robo, int argc __unused, char *argv[],
			  int i, int vlan)
{
	char *pports = argv[i];
	int untag = 0;
	int member = 0;
	int j;
	uint32_t v32;
	uint16_t v16;

	while (*pports >= '0' && *pports <= '9') {
		j = *pports++ - '0';
		member |= 1 << j;

		/* untag if needed, CPU port requires special handling */
		if (*pports == 'u'
		    || (j != 5 && (*pports == ' ' || *pports == 0))) {
			untag |= 1 << j;
			if (*pports)
				pports++;
			/* change default vlan tag */
			bcm53xx_w16(robo->fd, PAGE_VLAN,
				    ROBO_VLAN_PTAG0 + (j << 1), vlan);
		} else if (*pports == '*' || *pports == 't' || *pports == ' ')
			pports++;
		else
			break;

		while (*pports == ' ')
			pports++;
	}

	if (*pports) {
		err("Invalid pports '%s'.\n", argv[i]);
		exit(EXIT_FAILURE);
	}

	/* write config now */
	v32 = ROBO_VLAN_WRITE_VALID | ((vlan & 0x0ff0) << 8) |
	    (untag << ROBO_VLAN_UNTAG_SHIFT) | member;
	v16 = vlan | ROBO_VLAN_ACCESS_START_DONE | ROBO_VLAN_ACCESS_WRITE_STATE;
	bcm53xx_w32(robo->fd, PAGE_VLAN, ROBO_VLAN_WRITE, v32);
	bcm53xx_w16(robo->fd, PAGE_VLAN, ROBO_VLAN_ACCESS, v16);

	return i;
}

static int cmd_vlan(robo_t * robo, int argc, char *argv[], int i)
{
	int vlan = atoi(argv[++i]);

	while (++i < argc) {
		if (matches(argv[i], "ports") && ++i < argc) {
			i = cmd_vlan_ports(robo, argc, argv, i, vlan);
		} else {
			break;
		}
	}

	return i;
}

static int cmd_switch(robo_t * robo, int argc __unused, char *argv[], int i)
{
	/* enable/disable switching */
	bcm53xx_w16(robo->fd, PAGE_CONTROL, ROBO_SWITCH_MODE,
		    (bcm53xx_r16(robo->fd, PAGE_CONTROL, ROBO_SWITCH_MODE)
		     & ~2) | (*argv[++i] == 'e' ? 2 : 0));

	return ++i;
}

static int cmd_vlans_reset(robo_t * robo)
{
	int vlan;

	/* reset vlan validity bit */
	for (vlan = 0; vlan <= VLAN_ID_MAX5350; ++vlan) {
		uint16_t v16;

		/* write config now */
		v16 =
		    vlan | ROBO_VLAN_ACCESS_START_DONE |
		    ROBO_VLAN_ACCESS_WRITE_STATE;
		bcm53xx_w32(robo->fd, PAGE_VLAN, ROBO_VLAN_WRITE, 0);
		bcm53xx_w16(robo->fd, PAGE_VLAN, ROBO_VLAN_ACCESS, v16);
	}

	return 0;
}

static int cmd_vlans_disable(robo_t * robo)
{
#ifdef NB4
	if (ioctl(robo->fd, SIOCDEVPRIVATE + 7, &robo->ifr) < 0) {
		err("%s( %d, %s, %p ) %m\n", "ioctl", robo->fd,
		    "SIOCGDISABLEVLAN", &robo->ifr);
		exit(EXIT_FAILURE);
	}
#endif				/* NB4 */

	/* disable vlans */
	bcm53xx_w16(robo->fd, PAGE_VLAN, ROBO_VLAN_CTRL0, 0);
	bcm53xx_w16(robo->fd, PAGE_VLAN, ROBO_VLAN_CTRL1, 0);
	bcm53xx_w16(robo->fd, PAGE_VLAN, ROBO_VLAN_CTRL4, 0);
	bcm53xx_w16(robo->fd, PAGE_VLAN, ROBO_VLAN_CTRL5, 0);

	return 0;
}

static int cmd_vlans_enable(robo_t * robo)
{
	uint16_t v16;

#ifdef NB4
	if (ioctl(robo->fd, SIOCDEVPRIVATE + 6, &robo->ifr) < 0) {
		err("%s( %d, %s, %p ) %m\n", "ioctl", robo->fd,
		    "SIOCGENABLEVLAN", &robo->ifr);
		exit(EXIT_FAILURE);
	}
#endif				/* NB4 */

	/* enable vlans */
	v16 = ROBO_VLAN_CTRL0_ENABLE_1Q | ROBO_VLAN_CTRL0_IVLM;
	bcm53xx_w16(robo->fd, PAGE_VLAN, ROBO_VLAN_CTRL0, v16);

	v16 = (1 << 1) | (1 << 2) | (1 << 3) /* RSV multicast */ ;
	bcm53xx_w16(robo->fd, PAGE_VLAN, ROBO_VLAN_CTRL1, v16);

	v16 = (1 << 6) /* drop invalid VID frames */ ;
	bcm53xx_w16(robo->fd, PAGE_VLAN, ROBO_VLAN_CTRL4, v16);

	v16 = (1 << 3) /* drop miss V table frames */ ;
	bcm53xx_w16(robo->fd, PAGE_VLAN, ROBO_VLAN_CTRL5, v16);

	return 0;
}

static int cmd_vlans(robo_t * robo, int argc, char *argv[], int i)
{
	while (++i < argc) {
		if (matches(argv[i], "reset")) {
			cmd_vlans_reset(robo);
		} else if (matches(argv[i], "disable")) {
			cmd_vlans_disable(robo);
		} else if (matches(argv[i], "enable")) {
			cmd_vlans_enable(robo);
		} else {
			break;
		}
	}

	return i;
}

static void cmd_show(robo_t * robo)
{
	unsigned int i, j;
	int vlan;
	uint8_t mac[6];
	uint16_t v16;
#ifdef BROADCOM_5325E_SWITCH
	uint16_t speed;
#else				/* BROADCOM_5395S_SWITCH */
	uint32_t speed;
#endif				/* BROADCOM_5395S_SWITCH */
	uint16_t duplex;

#ifdef BROADCOM_5325E_SWITCH
	speed = bcm53xx_r16(robo->fd, PAGE_STATUS, ROBO_PORT_SPEED_SUMMARY);
	duplex =
	    bcm53xx_r16(robo->fd, PAGE_STATUS, ROBO_5325_DUPLEX_STATUS_SUMMARY);
#else
	speed = bcm53xx_r32(robo->fd, PAGE_STATUS, ROBO_PORT_SPEED_SUMMARY);
	duplex =
	    bcm53xx_r16(robo->fd, PAGE_STATUS, ROBO_5395_DUPLEX_STATUS_SUMMARY);
#endif

	printf("Switch: %sabled\n",
	       bcm53xx_r8(robo->fd, PAGE_CONTROL,
			  ROBO_SWITCH_MODE) & 2 ? "en" : "dis");

	for (i = 0; i < ARRAY_SIZE(port); i++) {
		char const *port_speed[] = {
			"10", "100", "1000", "?"
		};
		char const *port_duplex[] = {
			"HD", "FD"
		};

		v16 = bcm53xx_r16(robo->fd, PAGE_STATUS, ROBO_LINK_STATUS);
		printf(v16 & (1 << port[i]) ? "Port %d(%c): %s%s " :
		       "Port %d(%c):  DOWN ", i, ports[i],
#ifdef BROADCOM_5325E_SWITCH
		       port_speed[(speed >> (1 * port[i])) & 0x01],
#else				/* BROADCOM_5395S_SWITCH */
		       port_speed[(speed >> (2 * port[i])) & 0x03],
#endif				/* BROADCOM_5395S_SWITCH */
		       port_duplex[(duplex >> port[i]) & 0x01]);

		v16 = bcm53xx_r16(robo->fd, PAGE_CONTROL, port[i]);
		printf("%s stp: %s vlan: %d ", rxtx[v16 & 3],
		       stp[(v16 >> 5) & 7],
		       bcm53xx_r16(robo->fd, PAGE_VLAN,
				   ROBO_VLAN_PTAG0 + (i << 1)));

		bcm53xx_r48(robo->fd, PAGE_STATUS,
			    ROBO_LAST_SOURCE_ADDRESS_PORT0 + port[i] * 6, mac);
		printf("mac: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1],
		       mac[2], mac[3], mac[4], mac[5]);
	}

	v16 = bcm53xx_r16(robo->fd, PAGE_VLAN, ROBO_VLAN_CTRL0);
	printf("VLANs: %s %sabled%s%s\n", "BCM53xx",
	       (v16 & (1 << 7)) ? "en" : "dis",
	       (v16 & (1 << 6)) ? " mac_check" : "",
	       (v16 & (1 << 5)) ? " mac_hash" : "");

	/* scan VLANs */
	for (vlan = 0; vlan <= VLAN_ID_MAX5350; ++vlan) {
		uint32_t v32;

		/* issue read */
		v16 =
		    vlan | (0 << ROBO_VLAN_HIGH_8BIT_VID_SHIFT) |
		    ROBO_VLAN_ACCESS_START_DONE;
		bcm53xx_w16(robo->fd, PAGE_VLAN, ROBO_VLAN_ACCESS, v16);
		/* actual read */
		v32 = bcm53xx_r32(robo->fd, PAGE_VLAN, ROBO_VLAN_READ);
		if (v32 & ROBO_VLAN_READ_VALID) {
			printf("vlan%d:", vlan);
			for (j = 0; j < ARRAY_SIZE(port); j++) {
				if (v32 & (1 << j)) {
					printf(" %d%s", j,
					       (v32 &
						(1 <<
						 (j + ROBO_VLAN_UNTAG_SHIFT)))
					       ? (j == 5 ? "u" : "") : "t");
				}
			}
			printf("\n");
		}
	}
}

int main(int argc, char *argv[])
{
	int i = 0;
	uint32_t phyid;
	robo_t robo;
	if ((robo.fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		err("%s( %d, %d, %d ) %m\n", "socket", AF_INET, SOCK_DGRAM, 0);
		exit(EXIT_FAILURE);
	}

	/* the only interface for now */
	strcpy(robo.ifr.ifr_name, "eth1");
	phyid = mdio_read(&robo, ROBO_PHY_ADDR, 0x2) |
	    (mdio_read(&robo, ROBO_PHY_ADDR, 0x3) << 16);
	if (phyid == 0xffffffff || phyid == 0x55210022) {
		err("No Robo switch in managed mode found\n");
		exit(EXIT_FAILURE);
	}

	robo.fd = bcm53xx_open("eth1");
	for (i = 1; i < argc;) {
		if (matches(argv[i], "port")
		    && (i + 1) < argc) {
			i = cmd_port(&robo, argc, argv, i);
		} else if (matches(argv[i], "vlan")
			   && (i + 1) < argc) {
			i = cmd_vlan(&robo, argc, argv, i);
		} else if (matches(argv[i], "switch")
			   && (i + 1) < argc) {
			i = cmd_switch(&robo, argc, argv, i);
		} else if (matches(argv[i], "vlans")
			   && (i + 1) < argc) {
			i = cmd_vlans(&robo, argc, argv, i);
		} else if (matches(argv[i], "show")) {
			break;
		} else {
			err("Invalid option %s\n", argv[i]);
			usage();
		}
	}

	if (i == argc) {
		if (argc == 1)
			usage();
	}

	/* show config */
	cmd_show(&robo);
	bcm53xx_close(robo.fd);

	return (EXIT_SUCCESS);
}
