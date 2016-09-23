/*!
 *      \file sfp.h
 *
 *      \author Copyright 2007 Miguel GAIO <miguel.gaio@efixo.com>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef _SFP_H_
#define _SFP_H_

#include <cvmx.h>
#include <cvmx-twsi.h>

#include <linux/types.h>
#include <linux/sff-8472.h>

static inline u8 sfp_eeprom_base_read8(unsigned addr)
{
	return cvmx_twsi_read8(SFP_EEPROM_BASE, addr);
}

static inline u8 sfp_eeprom_extended_read8(unsigned addr)
{
	return cvmx_twsi_read8(SFP_EEPROM_BASE,
			       sizeof(struct sfp_eeprom_base) + addr);
}

static inline u8 sfp_ddm_monitor_read8(unsigned addr)
{
	return cvmx_twsi_read8(SFP_DDM_BASE,
			       sizeof(struct sfp_ddm_tresholds) +
			       sizeof(struct sfp_ddm_constants) + addr);
}

static inline void sfp_ddm_monitor_write8(unsigned addr, unsigned data)
{
	cvmx_twsi_write8(SFP_DDM_BASE,
			 sizeof(struct sfp_ddm_tresholds) +
			 sizeof(struct sfp_ddm_constants) + addr, data);
}

/* -- */

static inline u16 sfp_Rx_ok(void)
{
	unsigned addr;
	u8 flags;
	u8 ddm;

	addr = offsetof(struct sfp_eeprom_extended, diagnostic_monitor_type);
	ddm = sfp_eeprom_extended_read8(addr);
	if (!ddm) {		/* If device has no ddm force link OK */
		return 1;
	}

	addr = offsetof(struct sfp_ddm_monitors, alarm_warnings_flags)+1;
	flags = sfp_ddm_monitor_read8(addr);

	return (flags == 0xFF) ? 0u : !(flags & 0xC0);
}

static inline u8 sfp_eeprom_bitrate(void)
{
	unsigned addr;
	u8 speed;

	addr = offsetof(struct sfp_eeprom_base, br_nominal);
	speed = sfp_eeprom_base_read8(addr);

	return (speed == 0xFF) ? 0u : speed;
}

static inline u16 sfp_Rx_LOS(void)
{
	unsigned addr;
	u8 flags;
	u8 ddm;

	addr = offsetof(struct sfp_eeprom_extended, diagnostic_monitor_type);
	ddm = sfp_eeprom_extended_read8(addr);
	if (!ddm) {		/* If device has no ddm force Link up */
		return 0;
	}

	addr = offsetof(struct sfp_ddm_monitors, logic_status);
	flags = sfp_ddm_monitor_read8(addr);

	return !!(flags & 0x02);
}

static inline void sfp_Tx_disable(void)
{
	unsigned addr;
	u8 control;

	addr = offsetof(struct sfp_ddm_monitors, logic_status);
	control = sfp_ddm_monitor_read8(addr);
	control |= (1 << 6);	/* Tx Disable Control */
	sfp_ddm_monitor_write8(addr, control);
}

static inline void sfp_Tx_enable(void)
{
	unsigned addr;
	u8 control;

	addr = offsetof(struct sfp_ddm_monitors, logic_status);
	control = sfp_ddm_monitor_read8(addr);
	control &= ~(1 << 6);	/* Tx Disable Control */
	sfp_ddm_monitor_write8(addr, control);
}

#endif				/* _SFP_H_ */
