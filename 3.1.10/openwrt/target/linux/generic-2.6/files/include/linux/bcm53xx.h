
#ifndef _BROADCOM_53XX_SWITCH_H_
#define _BROADCOM_53XX_SWITCH_H_

#include <linux/types.h>

#ifdef __KERNEL__

#include <linux/bcmphy.h>
#include <linux/if.h>

struct bcmphy;

int switch_print_media(char *buf, int media);

int bcm53xx_probe(struct bcmphy *);
int bcm53xx_ioctl(struct bcmphy *, struct ifreq *, int);
void bcm53xx_media_check(struct bcmphy *);

#else
#include <linux/sockios.h>
#endif				/* __KERNEL__ */

#ifdef CONFIG_BOARD_NEUFBOX4
#define BROADCOM_5325E_SWITCH 1
#endif
#ifdef CONFIG_BOARD_NEUFBOX5
#define BROADCOM_5395S_SWITCH 1
#endif

union bcm53xx_reg_union {
	__be16 raw[4];
	__be16 u16;
	__be32 u32;
	__be64 u64;
} __attribute__ ((__packed__));

struct bcm53xx_ioctl_data {
	union bcm53xx_reg_union u;
	__u8 page;
	__u8 reg;
	__u8 len;
} __attribute__ ((__packed__));

enum {
	SIOCGROBOREGS = SIOCDEVPRIVATE + 14,
	SIOCSROBOREGS
};

/****************************************************************************
  External switch pseudo PHY: Page (0x00)
 ****************************************************************************/

#define PAGE_CONTROL						0x00

#define ROBO_PORT_CONTROL0				0x00
#define ROBO_PORT_CONTROL1				0x01
#define ROBO_PORT_CONTROL2				0x02
#define ROBO_PORT_CONTROL3				0x03
#define ROBO_PORT_CONTROL4				0x04
#define STP_NO_SPANNING_TREE			0
#define STP_DISABLED_STATE			1
#define STP_BLOCKING_STATE			2
#define STP_LISTENING_STATE			3
#define STP_LEARNING_STATE			4
#define STP_FORWARDING_STATE			5

#define ROBO_MII_PORT_CONTROL				0x08
#define ROBO_MII_PORT_CONTROL_RX_UCST_EN	0x10
#define ROBO_MII_PORT_CONTROL_RX_MCST_EN	0x08
#define ROBO_MII_PORT_CONTROL_RX_BCST_EN	0x04

#define ROBO_SWITCH_MODE				0x0b
#define SWITCH_FORWARDING_DISABLE		0x00
#define SWITCH_FORWARDING_ENABLE		0x01
#define SWITCH_MODE_UNMANAGED			0x00
#define SWITCH_MODE_MANAGED			0x01

#define ROBO_SWITCH_MODE_FRAME_MANAGE_MODE		0x01
#define ROBO_SWITCH_MODE_SW_FWDG_EN			0x02

#define ROBO_CONTROL_MII1_PORT_STATE_OVERRIDE		0x0e
#define ROBO_CONTROL_MPSO_MII_SW_OVERRIDE	0x80
#define ROBO_CONTROL_MPSO_REVERSE_MII		0x10
#define ROBO_CONTROL_MPSO_LP_FLOW_CONTROL	0x08
#define ROBO_CONTROL_MPSO_SPEED100		0x04
#define ROBO_CONTROL_MPSO_FDX			0x02
#define ROBO_CONTROL_MPSO_LINKPASS		0x01

#define ROBO_5325_CONTROL_MULTICAST_IP_CONTROL		0x21
#define ROBO_5325_CONTROL_IP_MULTICAST		(1<<0)

#define ROBO_CONTROL_MPSO_LP_FLOW_CONTROL_5397		0x30
#define ROBO_CONTROL_MPSO_SPEED1000_5397		0x08

#define ROBO_CONTROL_MPSO_OVERRIDE_ALL ( \
				ROBO_CONTROL_MPSO_MII_SW_OVERRIDE | \
				ROBO_CONTROL_MPSO_REVERSE_MII | \
				ROBO_CONTROL_MPSO_LP_FLOW_CONTROL | \
				ROBO_CONTROL_MPSO_SPEED100 | \
				ROBO_CONTROL_MPSO_FDX | \
				ROBO_CONTROL_MPSO_LINKPASS \
				)

#define ROBO_CONTROL_MPSO_OVERRIDE_ALL_5397 ( \
				ROBO_CONTROL_MPSO_MII_SW_OVERRIDE | \
				ROBO_CONTROL_MPSO_LP_FLOW_CONTROL_5397 | \
				ROBO_CONTROL_MPSO_SPEED100 | \
				ROBO_CONTROL_MPSO_FDX | \
				ROBO_CONTROL_MPSO_LINKPASS \
				)

#define ROBO_POWER_DOWN_MODE				0x0f
#define ROBO_POWER_DOWN_MODE_PORT1_PHY_DISABLE	0x01
#define ROBO_POWER_DOWN_MODE_PORT2_PHY_DISABLE	0x02
#define ROBO_POWER_DOWN_MODE_PORT3_PHY_DISABLE	0x04
#define ROBO_POWER_DOWN_MODE_PORT4_PHY_DISABLE	0x08
#define ROBO_POWER_DOWN_MODE_PORT5_PHY_DISABLE	0x10
#define ROBO_POWER_DOWN_MODE_ALL		0x1f

#define ROBO_DISABLE_LEARNING				0x3c

union bcm53xx_control {
	__u8 u8;
	struct {
		__u8 stp_state:3;
		__u8 reserved_4_2:3;
		__u8 TX_disable:1;
		__u8 RX_disable:1;
	} s;
};
union bcm53xx_mii_control {
	__u8 u8;
	struct {
		__u8 reserved_7_5:3;
		__u8 RX_unicast:1;
		__u8 RX_multicast:1;
		__u8 RX_broadcast:1;
		__u8 reserved_1_0:2;
	} s;
};

union bcm53xx_mode {
	__u8 u8;
	struct {
		__u8 reserved_7_2:6;
		__u8 switch_forwarding:1;
		__u8 switch_mode:1;
	} s;
};

/****************************************************************************
  External status registers PHY: Page (0x01)
 ****************************************************************************/

#define PAGE_STATUS						0x01

#define ROBO_LINK_STATUS				0x00
#define LINK_STATUS_FAIL			0x00
#define LINK_STATUS_PASS			0x01

#define ROBO_LINK_STATUS_CHANGE				0x02
#define LINK_STATUS_CONSTANT			0x00
#define LINK_STATUS_CHANGE			0x01

#define ROBO_PORT_SPEED_SUMMARY				0x04
#define PORT_SPEED_10MBPS			0x00
#define PORT_SPEED_100MBPS			0x01
#define PORT_SPEED_1000MBPS			0x02
#define PORT_SPEED_ILLEGAL_STATE		0x03

#define ROBO_5325_DUPLEX_STATUS_SUMMARY		0x06
#define ROBO_5395_DUPLEX_STATUS_SUMMARY		0x08

#define DUPLEX_STATUS_HALF_DUPLEX		0x00
#define DUPLEX_STATUS_FULL_DUPLEX		0x01

#define ROBO_PAUSE_STATUS_SUMMARY			0x0A
#define ROBO_SOURCE_ADDRESS_CHANGE			0x0E
#define ROBO_LAST_SOURCE_ADDRESS_PORT0			0x10
#define ROBO_LAST_SOURCE_ADDRESS_PORT1			0x16
#define ROBO_LAST_SOURCE_ADDRESS_PORT2			0x1C
#define ROBO_LAST_SOURCE_ADDRESS_PORT3			0x22
#define ROBO_LAST_SOURCE_ADDRESS_PORT4			0x28
#define ROBO_LAST_SOURCE_ADDRESS_IMP_PORT		0x40

union bcm53xx_media_status {
	__u16 u16;
	struct {
		__u16 reserved_9_15:7;
		__u16 IMP_port:1;
		__u16 reserved_5_7:3;
		__u16 port4:1;
		__u16 port3:1;
		__u16 port2:1;
		__u16 port1:1;
		__u16 port0:1;
	} s;
};

union bcm5325_media_speed {
	__u16 u16;
	struct {
		__u16 reserved_15_9:7;
		__u16 IMP_port:1;
		__u16 reserved_7_5:3;
		__u16 port4:1;
		__u16 port3:1;
		__u16 port2:1;
		__u16 port1:1;
		__u16 port0:1;

	} s;
};

union bcm5395_media_speed {
	__u32 u32;
	struct {
		__u32 reserved_18_32:14;
		__u32 IMP_port:2;
		__u32 reserved_10_15:6;
		__u32 port4:2;
		__u32 port3:2;
		__u32 port2:2;
		__u32 port1:2;
		__u32 port0:2;

	} s;
};

union bcm53xx_media_duplex {
	__u16 u16;
	struct {
		__u16 reserved_9_15:7;
		__u16 IMP_port:1;
		__u16 reserved_5_7:3;
		__u16 port4:1;
		__u16 port3:1;
		__u16 port2:1;
		__u16 port1:1;
		__u16 port0:1;
	} s;
};

/****************************************************************************
  External switch pseudo PHY: Page (0x02)
 ****************************************************************************/

#define PAGE_MANAGEMENT						0x02
#define ROBO_GLOBAL_CONFIGURATION			0x00
#define NO_FRAME_MANAGEMENT			0x00
#define ENABLE_MII_PORT				0x80
#define RECEIVE_IGMP				0x08
#define MIB_MODE_SELECT				0x04
#define RECEIVE_BPDU				0x02

union bcm53xx_global_config {
	__u8 u8;
	struct {
		__u8 enable_IMP_port:2;
		__u8 reserved_5:1;
		__u8 interrupt_enable:1;
		__u8 reserved_3_2:2;
		__u8 RX_BDPU_enable:1;
		__u8 reset_MIB:1;
	} s;
};

#define ROBO_DEV_ID					0x30

#define ROBO_PROTOCOL_CONTROL				0x50

union bcm53xx_proto_control {
	__u16 u16;
	struct {
		__u16 reserved_15_9:7;
		__u16 igmp_fwd_mode:1;
		__u16 igmp_dip_en:1;
		__u16 igmp_ip_en:1;
		__u16 icmpv6_fwd_mode:1;
		__u16 icmpv6_en:1;
		__u16 icmpv4_en:1;
		__u16 dhcp_en:1;
		__u16 rarp_en:1;
		__u16 arp_en:1;
	} s;
};

/****************************************************************************
  External switch pseudo PHY: Page (0x04)
 ****************************************************************************/

#define PAGE_ARL_CONTROL					0x04

#define ROBO_ARL_CONTROL_CONTROL			0x00

#define ROBO_ARL_ADDR0					0x10
#define ROBO_ARL_VEC0					0x16
#define ROBO_ARL_ADDR1					0x20
#define ROBO_ARL_VEC1					0x26

/****************************************************************************
  External switch pseudo PHY: Page (0x05)
 ****************************************************************************/

#define PAGE_ARL						0x05
#define ROBO_ARL_CONTROL				0x00
#define ROBO_ARL_CONTROL_READ			0x01
#define ROBO_ARL_CONTROL_START			0x80
#define ROBO_ARL_CONTROL_DONE			0x80

#define ROBO_ARL_ADDR_INDEX				0x02

#define ROBO_ARL_VID_TABLE_INDEX			0x08

#define ROBO_ARL_ENTRY0					0x10
#define ROBO_ARL_ENTRY1					0x18

#define ROBO_5325_ARL_CPU_PORT				( 3 << 5 )
#define ROBO_5395_ARL_CPU_PORT				( 1 << 8 )

union bcm53xx_arl_table_control {
	__u8 u8;
	struct {
		__u8 start_done:1;
		__u8 reserved_6_1:6;
		__u8 read:1;
	} s;
} __attribute__ ((packed));

union bcm5325_arl {
	__u64 raw;
	struct {
		__u64 valid:1;
		__u64 _static:1;
		__u64 age:1;
		__u64 reserved_60_55:6;
		__u64 portid:7;
		__u8 mac_address[6];
	} s;
} __attribute__ ((packed));

#define ROBO_5325_ARL_ENTRY_COUNT 2

union bcm5395_arl {
	struct raw_struct {
		__u64 u64;
		__u32 u32;
	} raw;
	struct {
		__u64 reserved_63_60:4;
		__u64 vid:12;
		__u8 mac_address[6];
		__u32 reserved_31_17:15;
		__u32 valid:1;
		__u32 _static:1;
		__u32 age:1;
		__u32 tc:3;
		__u32 reserved_10_9:2;
		__u32 portid:9;
	} s;
} __attribute__ ((packed));

#define ROBO_5395_ARL_ENTRY_COUNT 4

/****************************************************************************
    PORT MIB REGISTER: Page (0x20 -> 0x24)
****************************************************************************/

#define PAGE_PORT0_MIB						0x20
#define PAGE_PORT1_MIB						0x21
#define PAGE_PORT2_MIB						0x22
#define PAGE_PORT3_MIB						0x23
#define PAGE_PORT4_MIB						0x24
#define PAGE_PORTIMP_MIB					0x28
/* mode 0 */
#define MIB_5325E_TX_PACKETS				0x00
#define MIB_5325E_TX_UNICAST_PACKETS			0x02
#define MIB_5325E_RX_GOOD_PACKETS			0x04
#define MIB_5325E_RX_UNICAST_PACKETS			0x06

/* mode 1 */
#define MIB_5325E_TX_COLLISIONS				0x00
#define MIB_5325E_TX_OCTETS				0x02
#define MIB_5325E_RX_FCS_ERRORS				0x04
#define MIB_5325E_RX_GOOD_OCTETS			0x06

#define MIB_5395S_TX_OCTETS				0x00
#define MIB_5395S_TX_DROP_PACKETS			0x08
#define MIB_5395S_TX_QOS0_PACKETS			0x0C
#define MIB_5395S_TX_BROADCAST_PACKETS			0x10
#define MIB_5395S_TX_MULTICAST_PACKETS			0x14
#define MIB_5395S_TX_UNICAST_PACKETS			0x18
#define MIB_5395S_TX_COLLISIONS				0x1C
#define MIB_5395S_TX_SINGLE_COLLISION			0x20
#define MIB_5395S_TX_MULTIPLE_COLLISION			0x24
#define MIB_5395S_TX_DEFERRED_TRANSMIT			0x28
#define MIB_5395S_TX_LATE_COLLISION			0x2C
#define MIB_5395S_TX_EXCESSIVE_COLLISION		0x30
#define MIB_5395S_TX_FRAME_IN_DISC			0x34
#define MIB_5395S_TX_PAUSE_PACKETS			0x38
#define MIB_5395S_TX_QOS1_PACKETS			0x3C
#define MIB_5395S_TX_QOS2_PACKETS			0x40
#define MIB_5395S_TX_QOS3_PACKETS			0x44

#define MIB_5395S_RX_OCTETS				0x50
#define MIB_5395S_RX_UNDERSIZE_PACKETS			0x58
#define MIB_5395S_RX_PAUSE_PACKETS			0x5C
#define MIB_5395S_RX_PACKETS_64OCTETS			0x60
#define MIB_5395S_RX_PACKETS_127OCTETS			0x64
#define MIB_5395S_RX_PACKETS_255OCTETS			0x68
#define MIB_5395S_RX_PACKETS_511OCTETS			0x6C
#define MIB_5395S_RX_PACKETS_1023OCTETS			0x70
#define MIB_5395S_RX_PACKETS_1522OCTETS			0x74
#define MIB_5395S_RX_OVERSIZE_PACKETS			0x78
#define MIB_5395S_RX_JABBERS				0x7C
#define MIB_5395S_RX_ALIGNMENT_ERRORS			0x80
#define MIB_5395S_RX_FCS_ERRORS				0x84
#define MIB_5395S_RX_GOOD_OCTETS			0x88
#define MIB_5395S_RX_DROP_PACKETS			0x90
#define MIB_5395S_RX_UNICAST_PACKETS			0x94
#define MIB_5395S_RX_MULTICAST_PACKETS			0x98
#define MIB_5395S_RX_BROADCAST_PACKETS			0x9C
#define MIB_5395S_RX_SA_CHANGES				0xA0
#define MIB_5395S_RX_FRAGMENTS				0xA4
#define MIB_5395S_RX_EXCESS_SIZE_DISC			0xA8
#define MIB_5395S_RX_SYMBOL_ERROR			0xAC
#define MIB_5395S_RX_PACKETS_2047OCTETS			0xB0
#define MIB_5395S_RX_PACKETS_4095OCTETS			0xB4
#define MIB_5395S_RX_PACKETS_8191OCTETS			0xB8
#define MIB_5395S_RX_PACKETS_9728OCTETS			0xBC
#define MIB_5395S_RX_DISCARD				0xC0

/****************************************************************************
QOS: Page (0x30)
 ****************************************************************************/

#define PAGE_PORT_QOS					0x30

#define ROBO_QOS_CONTROL				0x00
#define ROBO_5325_QOS_CPU_CTRL_ENABLE			0x8000
#define ROBO_5325_QOS_TXQ_MODE_MULT			0x0400
#define ROBO_5395_QOS_CPU_CTRL_ENABLE			0x40
#define ROBO_QOS_PQ_CONTROL				0x02
#define ROBO_QOS_LAYER_SEL				0x04
#define ROBO_QOS_8021P_ENABLE				0x04
#define ROBO_QOS_DIFFSERV_ENABLE			0x06
#define ROBO_5325_QOS_PAUSE_ENABLE			0x13
#define ROBO_5325_QOS_PRIO_THRESHOLD			0x15
#define ROBO_QOS_DSCP_PRIO00				0x30

#define ROBO_5395_QOS_TC_TO_COS_MAP			0x62
#define ROBO_5395_QOS_TX_QUEUE_CTRL			0x80
#define ROBO_5395_QOS_TX_QUEUE_WIEGTH			0x81

#define QOS_5325E_DSCP_PRIO_REG_SIZE			8
#define QOS_5325E_DSCP_PRIO_REG_COUNT			2

#define QOS_5395S_DSCP_PRIO_REG_SIZE			6
#define QOS_5395S_DSCP_PRIO_REG_COUNT			4

/****************************************************************************
  External switch pseudo PHY: Page (0x31)
 ****************************************************************************/

#define PAGE_PORT_BASED_VLAN					0x31

/****************************************************************************
  External switch pseudo PHY: Page (0xff)
 ****************************************************************************/

#define ROBO_PAGE_SELECT					0xff

/****************************************************************************
  External switch pseudo PHY: Page (0x34)
 ****************************************************************************/

#define VLAN_ID_MAX5350				15

#define PAGE_VLAN				0x34

#define ROBO_VLAN_CTRL0				0x00
#define ROBO_VLAN_CTRL0_ENABLE_1Q		(1 << 7)
#define ROBO_VLAN_CTRL0_SVLM			(0 << 5)
#define ROBO_VLAN_CTRL0_IVLM			(3 << 5)
#define ROBO_VLAN_CTRL0_FR_CTRL_CHG_PRI		(1 << 2)
#define ROBO_VLAN_CTRL0_FR_CTRL_CHG_VID		(2 << 2)
#define ROBO_VLAN_CTRL1				0x01
#define ROBO_VLAN_CTRL2				0x02
#define ROBO_VLAN_CTRL3				0x03
#define ROBO_VLAN_CTRL3_8BIT_CHECK		(1 << 7)
#define ROBO_VLAN_CTRL3_MAXSIZE_1532		(1 << 6)
#define ROBO_VLAN_CTRL3_MII_DROP_NON_1Q		(0 << 5)
#define ROBO_VLAN_CTRL3_DROP_NON_1Q_SHIFT	0
#define ROBO_5325_VLAN_CTRL4		        0x04
#define ROBO_5325_VLAN_CTRL5			0x05
#define ROBO_5395_VLAN_CTRL4		        0x05
#define ROBO_5395_VLAN_CTRL5			0x06
#define ROBO_VLAN_CTRL5_VID_HIGH_8BIT_NOT_CHECKED (1 << 5)
#define ROBO_VLAN_CTRL5_APPLY_BYPASS_VLAN	(1 << 4)
#define ROBO_VLAN_CTRL5_DROP_VTAB_MISS		(1 << 3)
#define ROBO_VLAN_CTRL5_ENBL_MANAGE_RX_BYPASS	(1 << 1)
#define ROBO_VLAN_CTRL5_ENBL_CRC_GEN		(1 << 0)
#define ROBO_5325_VLAN_ACCESS			0x06
#define ROBO_5395_VLAN_ACCESS			0x07
#define ROBO_VLAN_ACCESS_START_DONE		(1 << 13)
#define ROBO_VLAN_ACCESS_WRITE_STATE		(1 << 12)
#define ROBO_VLAN_ACCESS_HIGH8_VID_SHIFT		4
#define ROBO_VALN_ACCESS_LOW4_VID_SHIFT		0
#define ROBO_VLAN_WRITE					0x08
#define ROBO_VLAN_WRITE_VALID			(1 << 20)
#define ROBO_VLAN_HIGH_8BIT_VID_SHIFT		12
#define ROBO_VLAN_UNTAG_SHIFT			6
#define ROBO_VLAN_GROUP_SHIFT			0
#define MII_PORT_FOR_VLAN			5
#define ROBO_VLAN_READ					0x0C
#define ROBO_VLAN_READ_VALID			(1 << 20)
#define ROBO_VLAN_PTAG0					0x10
#define ROBO_VLAN_PTAG1					0x12
#define ROBO_VLAN_PTAG2					0x14
#define ROBO_VLAN_PTAG3					0x16
#define ROBO_VLAN_PTAG4					0x18
#define ROBO_VLAN_PTAG5					0x1A
#define ROBO_VLAN_PMAP					0x20

/****************************************************************************
  Registers for pseudo PHY access
 ****************************************************************************/

#define ROBO_MII_PAGE			0x10
#define ROBO_MII_PAGE_SHIFT	8
#define ROBO_MII_PAGE_ENABLE	0x01

#define ROBO_MII_ADDR			0x11
#define ROBO_MII_ADDR_SHIFT	8
#define ROBO_MII_OP_DONE	0x00
#define ROBO_MII_ADDR_WRITE	0x01
#define ROBO_MII_ADDR_READ	0x02

#define ROBO_MII_DATA0			0x18

/* Wrapper */

#ifdef BROADCOM_5325E_SWITCH
#define ROBO_ARL_ENTRY_COUNT			ROBO_5325_ARL_ENTRY_COUNT
#define ROBO_QOS_CPU_CTRL_ENABLE		ROBO_5325_QOS_CPU_CTRL_ENABLE
#define ROBO_QOS_TXQ_MODE_MULT			ROBO_5325_QOS_TXQ_MODE_MULT
#define QOS_DSCP_PRIO_REG_SIZE			QOS_5325E_DSCP_PRIO_REG_SIZE
#define QOS_DSCP_PRIO_REG_COUNT			QOS_5325E_DSCP_PRIO_REG_COUNT
#define ROBO_VLAN_CTRL4				ROBO_5325_VLAN_CTRL4
#define ROBO_VLAN_CTRL5				ROBO_5325_VLAN_CTRL5
#define	ROBO_VLAN_ACCESS			ROBO_5325_VLAN_ACCESS
#endif

#ifdef BROADCOM_5395S_SWITCH
#define ROBO_ARL_ENTRY_COUNT			ROBO_5395_ARL_ENTRY_COUNT
#define ROBO_QOS_CPU_CTRL_ENABLE		ROBO_5395_QOS_CPU_CTRL_ENABLE
#define QOS_DSCP_PRIO_REG_SIZE			QOS_5395S_DSCP_PRIO_REG_SIZE
#define QOS_DSCP_PRIO_REG_COUNT			QOS_5395S_DSCP_PRIO_REG_COUNT
#define ROBO_VLAN_CTRL4				ROBO_5395_VLAN_CTRL4
#define ROBO_VLAN_CTRL5				ROBO_5395_VLAN_CTRL5
#define	ROBO_VLAN_ACCESS			ROBO_5395_VLAN_ACCESS
#endif

struct bcm53xx_arl {
	union {
		union bcm5325_arl bcm5325;
		union bcm5395_arl bcm5395;
	} u;
} __attribute__ ((packed));

#define DSCP_COUNT					64
#ifdef BROADCOM_5325E_SWITCH
#define UNIT	1ul
#define CAST(x)	(unsigned long)(x)
#endif
#ifdef BROADCOM_5395S_SWITCH
#define UNIT	1ull
#define CAST(x)	(unsigned long long)(x)
#endif
#define QOS_DSCP_PRIO_LOG2 \
	( ( ( QOS_DSCP_PRIO_REG_SIZE * QOS_DSCP_PRIO_REG_COUNT * \
	      8 /* bit per byte */ ) / DSCP_COUNT ) - UNIT )

#define QOS_PRIO_DSCP_MASK ( ( UNIT << (QOS_DSCP_PRIO_LOG2 + UNIT ) ) - UNIT )

#define QOS_PRIO_DSCP_REG(dscp) \
	( ( ( ( CAST(dscp) << QOS_DSCP_PRIO_LOG2 ) / DSCP_COUNT ) \
	    * QOS_DSCP_PRIO_REG_SIZE ) + ROBO_QOS_DSCP_PRIO00 )

#define QOS_PRIO_DSCP_SHIFT(dscp) \
	( ( CAST(dscp) & ( ( DSCP_COUNT >> QOS_DSCP_PRIO_LOG2 ) - UNIT ) ) \
	  * ( QOS_DSCP_PRIO_LOG2 + UNIT ) )

#endif
