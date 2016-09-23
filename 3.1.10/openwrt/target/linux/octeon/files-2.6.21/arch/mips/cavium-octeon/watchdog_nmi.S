/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2007 Cavium Networks
 */
#include <asm/asm.h>
#include <asm/mipsregs.h>
#include <asm/addrspace.h>
#include <asm/regdef.h>
#include <asm/stackframe.h>

#define CP0_CVMMEMCTL $11,7

	.text
	.set 	push
	.set 	noreorder
	.set 	noat
        NESTED(octeon_watchdog_nmi, PT_SIZE, sp)
	// For the next few instructions running the debugger may cause
	// corruption of k0 in the saved registers. Since we're about to
	// crash, nobody probably cares.
        dmtc0	k0, CP0_DESAVE			// Save K0 into the debug scratch register
	dmfc0	k0, CP0_CVMMEMCTL		// Use K0 to do a read/modify/write of CVMMEMCTL
	dins	k0, $0, 0, 6			// Clear out the size of CVMSEG
	ori	k0, 54				// Set CVMSEG to its largest value
	dmtc0	k0, CP0_CVMMEMCTL		// Store the CVMMEMCTL value
	dla	k0, octeon_watchdog_nmi_stage2	// Load the address of the second stage handler
	jr	k0				// Jump to the second stage handler
	 dmfc0	k0, CP0_DESAVE			// Restore K0 from DESAVE (delay slot)
	.set pop
        END(octeon_watchdog_nmi)

#define SAVE_REG(r)	sd $r, -32768+6912-(32-r)*8($0)

        NESTED(octeon_watchdog_nmi_stage2, PT_SIZE, sp)
	.set 	push
	.set 	noreorder
	.set 	noat
	// Save all regosters to the top CVMSEG. This
	// shouldn't corrupt any state used by the kernel. Also
	// all registers should have the value right before the NMI.
	SAVE_REG(0)
	SAVE_REG(1)
	SAVE_REG(2)
	SAVE_REG(3)
	SAVE_REG(4)
	SAVE_REG(5)
	SAVE_REG(6)
	SAVE_REG(7)
	SAVE_REG(8)
	SAVE_REG(9)
	SAVE_REG(10)
	SAVE_REG(11)
	SAVE_REG(12)
	SAVE_REG(13)
	SAVE_REG(14)
	SAVE_REG(15)
	SAVE_REG(16)
	SAVE_REG(17)
	SAVE_REG(18)
	SAVE_REG(19)
	SAVE_REG(20)
	SAVE_REG(21)
	SAVE_REG(22)
	SAVE_REG(23)
	SAVE_REG(24)
	SAVE_REG(25)
	SAVE_REG(26)
	SAVE_REG(27)
	SAVE_REG(28)
	SAVE_REG(29)
	SAVE_REG(30)
	SAVE_REG(31)
	li	sp, -32768+6912-32*8		// Set the stack to begin right below the registers
	dla	a0, octeon_watchdog_nmi_stage3	// Load the address of the third stage handler
	jal	a0				// Call the third stage handler
	 move	a0, sp				// a0 is the address of the saved registers
1:	b	1b				// Loop forvever if we get here.
	 nop
	.set pop
        END(octeon_watchdog_nmi_stage2)

