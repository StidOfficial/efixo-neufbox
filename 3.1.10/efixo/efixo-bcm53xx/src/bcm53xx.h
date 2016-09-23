/*!
 * \file lib/switch-robo.h
 *
 * \brief  
 *
 * \author Copyright 2007 Miguel GAIO <miguel.gaio@efixo.com>
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
 * $Id: bcm53xx.h 20243 2011-04-14 09:00:24Z mgo $
 */

#ifndef _BCM53XX_H_
#define _BCM53XX_H_

#include <stdint.h>
#include <sys/types.h>

/* LINUX */
#include <linux/types.h>
#include <linux/bcm53xx.h>
#include <net/if.h>
#include <netinet/ether.h>

#ifdef BROADCOM_5325E_SWITCH
#define has_bcm5325 1
#define has_bcm5395 0
#endif
#ifdef BROADCOM_5395S_SWITCH
#define has_bcm5325 0
#define has_bcm5395 1
#endif

/*! \fn void bcm53xx_open( char const *ifname )
 *  \brief Always use this fonction before using read or write
 *  \param ifname Robo Switch netdevice name
 */
int bcm53xx_open(char const *ifname);

/*! \fn void bcm53xx_close( void )
 *  \brief Use this function when you finish using read and write.
 */
void bcm53xx_close(int fd);

/*! \fn uint16_t bcm53xx_r16( unsigned page, unsigned reg )
 *  \brief Read a 16 bits register in  memory
 *  \param page Page adress
 *  \param reg  Register adress
 */
uint8_t bcm53xx_r8(int fd, unsigned page, unsigned reg);

/*! \fn uint16_t bcm53xx_r16( unsigned page, unsigned reg )
 *  \brief Read a 16 bits register in  memory
 *  \param page Page adress
 *  \param reg  Register adress
 */
uint16_t bcm53xx_r16(int fd, unsigned page, unsigned reg);

/*! \fn uint32_t bcm53xx_r32( unsigned page, unsigned reg )
 *  \brief Read a 32 bits register in  memory
 *  \param page Page adress
 *  \param reg  Register adress
 */
uint32_t bcm53xx_r32(int fd, unsigned page, unsigned reg);

/*! \fn void bcm53xx_r48( unsigned page, unsigned reg, void *v )
 *  \brief Read a 48 bits register in  memory
 *  \param page Page adress
 *  \param reg  Register adress
 */
void bcm53xx_r48(int fd, unsigned page, unsigned reg, void *);

/*! \fn uint32_t bcm53xx_r64( unsigned page, unsigned reg )
 *  \brief Read a 32 bits register in  memory
 *  \param page Page adress
 *  \param reg  Register adress
 */
uint64_t bcm53xx_r64(int fd, unsigned page, unsigned reg);

/*! \fn void bcm53xx_w8( unsigned page, unsigned reg, uint8_t val8 )
 *  \brief Write a 16 bits register in memory
 *  \param page  Page adress
 *  \param reg   Register adress
 *  \param val8 Value to write
 */
void bcm53xx_w8(int fd, unsigned page, unsigned reg, uint8_t val8);

/*! \fn void bcm53xx_w16( unsigned page, unsigned reg, uint16_t val16 )
 *  \brief Write a 16 bits register in memory
 *  \param page  Page adress
 *  \param reg   Register adress
 *  \param val16 Value to write
 */
void bcm53xx_w16(int fd, unsigned page, unsigned reg, uint16_t val16);

/*! \fn void bcm53xx_w32( unsigned page, unsigned reg, uint32_t val32 )
 *  \brief Write a 32 bits register in memory
 *  \param page  Page adress
 *  \param reg   Register adress
 *  \param val32 Value to write
 */
void bcm53xx_w32(int fd, unsigned page, unsigned reg, uint32_t val32);

/*! \fn void bcm53xx_w48( unsigned page, unsigned reg, void const *val48 )
 *  \brief Write a 32 bits register in memory
 *  \param page  Page adress
 *  \param reg   Register adress
 *  \param val32 Value to write
 */
void bcm53xx_w48(int fd, unsigned page, unsigned reg, void const *val48);

/*! \fn void bcm53xx_w64( unsigned page, unsigned reg, void const *val48 )
 *  \brief Write a 32 bits register in memory
 *  \param page  Page adress
 *  \param reg   Register adress
 *  \param val32 Value to write
 */
void bcm53xx_w64(int fd, unsigned page, unsigned reg, uint64_t val64);

/* l2 lookup table */

static inline int bcm53xx_l2_valid(struct bcm53xx_arl const
				   *entry)
{
	if (has_bcm5325)
		return (entry->u.bcm5325.s.valid);
	if (has_bcm5395)
		return (entry->u.bcm5395.s.valid);
}

static inline int bcm53xx_l2_mcast(struct bcm53xx_arl const
				   *entry)
{
	if (has_bcm5325)
		return (entry->u.bcm5325.s.mac_address[0] == 0x01);
	if (has_bcm5395)
		return (entry->u.bcm5395.s.mac_address[0] == 0x01);
}

/*! \fn int bcm53xx_l2_entry( int fd, struct ether_addr const *e,
 *                                  struct bcm53xx_arl *entry )
 */
int bcm53xx_l2_entry(int fd, struct ether_addr const *e,
		     struct bcm53xx_arl *entry);

/*! \fn bcm53xx_l2_setup( int fd, struct ether_addr const *e,
 *                             struct bcm53xx_arl const *entry )
 */
int bcm53xx_l2_setup(int fd, struct ether_addr const *e,
		     struct bcm53xx_arl const *entry);

/*! \fn bcm53xx_l2_mcast_add( int fd, struct ether_addr const *e,
 *                    uint32_t port )
 *  \brief Add port into multi cast rule
 *  \param e	Ethernet Address
 *  \param port	Port
 */
int bcm53xx_l2_mcast_add(struct ether_addr const *e, uint32_t port);

/*! \fn bcm53xx_l2_mcast_del( struct ether_addr const *e, uint32_t port )
 *  \brief Delete port into multi cast rule
 *  \param e	Ethernet Address
 *  \param port	Port
 */
int bcm53xx_l2_mcast_del(struct ether_addr const *e, uint32_t port);

/* diffserv */

#define for_each_qos_map_reg(reg) \
	for ( reg = ROBO_QOS_DSCP_PRIO00; reg < \
	      QOS_DSCP_PRIO_REG_SIZE * QOS_DSCP_PRIO_REG_COUNT + \
	      ROBO_QOS_DSCP_PRIO00; reg += QOS_DSCP_PRIO_REG_SIZE )

static inline uint64_t bcm53xx_qos_map_read(int fd, unsigned reg)
{
	uint64_t v64;

	if (has_bcm5325)
		v64 = bcm53xx_r64(fd, PAGE_PORT_QOS, reg);
	if (has_bcm5395) {
		bcm53xx_r48(fd, PAGE_PORT_QOS, reg, &v64);
		/* big endian cast 48bits -> 64bits */
		v64 >>= 16;
	}

	return v64;
}

static inline void bcm53xx_qos_map_write(int fd, unsigned reg, uint64_t v64)
{
	if (has_bcm5325)
		bcm53xx_w64(fd, PAGE_PORT_QOS, reg, v64);
	if (has_bcm5395) {
		/* big endian cast 64bits -> 48bits */
		v64 <<= 16;
		bcm53xx_w48(fd, PAGE_PORT_QOS, reg, &v64);
	}
}

/*! \fn bcm53xx_diffserv_get(int fd, unsigned dscp)
 *  \brief Delete port into multi cast rule
 *  \param fd File Descriptor
 *  \param dscp DSCP field
 */
unsigned bcm53xx_diffserv_get(int fd, unsigned dscp);

/*! \fn bcm53xx_diffserv_set(int fd, unsigned dscp, unsigned queue)
 *  \brief Delete port into multi cast rule
 *  \param fd File Descriptor
 *  \param dscp DSCP field
 *  \param queue Queue
 */
void bcm53xx_diffserv_set(int fd, unsigned dscp, unsigned queue);

#endif /* _BCM53XX_H_ */
