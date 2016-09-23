/*
 *      sff-8472.h
 *
 *      Copyright 2007 Miguel GAIO <miguel.gaio@efixo.com>
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

#ifndef _SFF_8472_H_
#define _SFF_8472_H_

#define SFP_EEPROM_BASE	0x50
#define SFP_DDM_BASE	0x51

/**
 * Serial ID: Data Fields
 */

struct sfp_eeprom_base {
	__u8 identifier; /** Type of serial transceiver */
	__u8 ext_identifier;	/** Extended identifier of type of serial transceiver */
	__u8 connector; /** Code for connector type */
	__u8 transceiver[8];	/** Code for electronic compatibility or optical compatibility */
	__u8 encoding; /** Code for serial encoding algorithm */
	__u8 br_nominal; /** Nominal bit rate, units of 100 MBits/sec. */
	__u8 reserved0;
	__u8 length_9um_km; /** Link length supported for 9/125 mm fiber, units of km */
	__u8 length_9um_100m; /** Link length supported for 9/125 mm fiber, units of 100m */
	__u8 length_50um_10m; /** Link length supported for 50/125 mm fiber, units of 10m */
	__u8 length_62um_10m; /** Link length supported for 62.5/125 mm fiber, units of 10m */
	__u8 length_copper_m; /** Link length supported for copper, units of meters */
	__u8 reserved1;
	char vendor_name[16];	 /** SFP transceiver vendor name (ASCII) */
	__u8 reserved2;
	__u8 vendor_oui[3];	/** SFP transceiver vendor IEEE company ID */
	char vendor_pn[16];    /** Part number provided by SFP transceiver vendor (ASCII) */
	char vendor_rev[4];    /** Revision level for part number provided by vendor (ASCII) */
	__u16 wavelength; /** Transceiver wavelength */
	__u8 reserved3;
	__u8 cc_base; /** Check code for Base ID Fields (addresses 0 to 62) */
};

struct sfp_eeprom_extended {
	__u8 options[2]; /** Indicates which optional SFP signals are implemented */
	__u8 br_max;	/** Upper bite rate margin, units of % */
	__u8 br_min;	/** Lower bite rate margin, units of % */
	__u8 vendor_sn[16]; /** Serial number provided by vendor (ASCII) */
	__u8 date_code[8]; /** Vendor's manufacturing date code */
	__u8 diagnostic_monitor_type; /** Digital diagnostic monitoring implemented, "externally calibrated" is implemented, RX measurement type is "Average Power".*/
	__u8 enhanced_options; /** Optional Alarm/Warning flags implemented for all monitored quantities, Optional Soft TX_FAULT monitoring implemented, Optional Soft RX_LOS monitoring implemented */
	__u8 sff_8472; /** Includes fonctionality described in Rev9.3 SFF-8472 */
	__u8 cc_ext;	/** Check code for the Extended ID Fields */
};

struct ddm_limits {
	__s16 high_alarm;	/* 00-01 */
	__s16 low_alarm;	/* 02-03 */
	__s16 high_warning;	/* 04-05 */
	__s16 low_warning;	/* 06-07 */
};

struct sfp_ddm_tresholds {
	struct ddm_limits temperature;	/* 00-07 */
	struct ddm_limits vcc;	/* 08-15 */
	struct ddm_limits bias;	/* 16-23 */
	struct ddm_limits tx_power;	/* 24-31 */
	struct ddm_limits rx_power;	/* 32-39 */
	__u8 reserved[16];	/* 40-55 */
};

struct ddm_calibration {
	__u16 slope;		/* 00-01 */
	__s16 offset;		/* 02-03 */
};

struct ddm_calibration_rx_power {
	float a4;		/* 00-03 */
	float a3;		/* 04-07 */
	float a2;		/* 08-11 */
	float a1;		/* 12-15 */
	float a0;		/* 16-19 */
};

struct sfp_ddm_constants {
	struct ddm_calibration_rx_power rx_power;	/* 56-75 */
	struct ddm_calibration bias;	/* 77-79 */
	struct ddm_calibration tx_power;	/* 80-83 */
	struct ddm_calibration temperature;	/* 84-87 */
	struct ddm_calibration vcc;	/* 88-91 */
	__u8 reserved[3];	/* 92-94 */
	__u8 cc;		/* 95 */
};

struct sfp_ddm_monitors {
	__s16 temperature;	/* 96-97 */
	__u16 vcc;		/* 98-99 */
	__u16 bias;		/* 100-101 */
	__s16 tx_power;	/* 102-103 */
	__s16 rx_power;	/* 104-105 */
	__u8 reserved[4];	/* 106-109 */
	__u8 logic_status;	/* 110 */
	__u8 ad_conversion_updates;	/* 111 */
	__u32 alarm_warnings_flags[2];	/* 112-119 */
};

union sfp_eeprom {
	__u8 raw[256];
	struct eeprom_s {
		struct sfp_eeprom_base base;
		struct sfp_eeprom_extended extended;
	} s;
};

union sfp_ddm {
	__u8 raw[256];
	struct ddm_s {
		struct sfp_ddm_tresholds tresholds;
		struct sfp_ddm_constants constants;
		struct sfp_ddm_monitors monitors;
	} s;
};

static inline float fixed_point(__s16 x)
{
	return (((float)x) / 256.f);
}

static inline float temperature(union sfp_ddm const *ddm, __s16 t)
{
	return (fixed_point(ddm->s.constants.temperature.slope) * t
		+ ddm->s.constants.temperature.offset) / 256.;
}

static inline float voltage(union sfp_ddm const *ddm, __u16 vcc)
{
	return (fixed_point(ddm->s.constants.vcc.slope) * vcc +
		ddm->s.constants.vcc.offset) / 1e4;
}

static inline float bias(union sfp_ddm const *ddm, __u16 i)
{
	return (fixed_point(ddm->s.constants.bias.slope) * i +
		ddm->s.constants.bias.offset) / 5e2;
}

static inline float txpower(union sfp_ddm const *ddm, __u16 p)
{
	return (fixed_point(ddm->s.constants.tx_power.slope) * p +
		ddm->s.constants.tx_power.offset) / 1e4;
}

static inline float rxpower(union sfp_ddm const *ddm, __u16 p)
{
	return (ddm->s.constants.rx_power.a4 * p * p * p * p +
		ddm->s.constants.rx_power.a3 * p * p * p +
		ddm->s.constants.rx_power.a2 * p * p +
		ddm->s.constants.rx_power.a1 * p +
		ddm->s.constants.rx_power.a0) / 1e4;
}

#endif				/* _SFF_8472_H_ */
