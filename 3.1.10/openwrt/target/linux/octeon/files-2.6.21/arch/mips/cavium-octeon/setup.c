/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2004-2007 Cavium Networks
 */
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/serial.h>
#include <linux/types.h>
#include <linux/string.h>	/* for memset */
#include <linux/console.h>
#include <linux/serial.h>
#include <linux/tty.h>
#include <asm/time.h>
#include <linux/serial_core.h>
#include <linux/string.h>

#include <asm/reboot.h>
#include <asm/io.h>
#include <asm/time.h>
#include <asm/processor.h>
#include <asm/reboot.h>
#include <asm/system.h>
#include <asm/irq_cpu.h>
#include <asm/mipsregs.h>
#include <asm/bootinfo.h>
#include <asm/gdb-stub.h>
#include "hal.h"
#include "cvmx-l2c.h"
#include "cvmx-bootmem.h"

extern void octeon_user_io_init(void);
static unsigned long CYCLES_PER_JIFFY;
static int ECC_REPORT_SINGLE_BIT_ERRORS = 0;
static unsigned long long MAX_MEMORY = 512ull << 20;


/**
 * Reboot Octeon
 *
 * @param command Command to pass to the bootloader. Currently ignored.
 */
static void octeon_restart(char *command)
{
#ifdef CONFIG_SMP
	int cpu;
#endif
	mb();
	/* Disabled BIST on reset due to a chip errata G-200 for Cn38XX and
	   CN31XX */
	if (!OCTEON_IS_MODEL(OCTEON_CN38XX_PASS2) &&
	    !OCTEON_IS_MODEL(OCTEON_CN31XX)) {
		/* BIST should always be enabled when doing a soft reset. L2
		   Cache locking for instance is not cleared unless BIST is
		   enabled */
		cvmx_write_csr(CVMX_CIU_SOFT_BIST, 1);
		/* Read it back to make sure it is set before we reset the
		   chip. */
		cvmx_read_csr(CVMX_CIU_SOFT_BIST);
	}

	/* Disable all watchdogs before soft reset. They don't get cleared */
#ifdef CONFIG_SMP
	for (cpu = 0; cpu < NR_CPUS; cpu++)
		if (cpu_online(cpu))
			cvmx_write_csr(CVMX_CIU_WDOGX(cpu_logical_map(cpu)), 0);
#else
	cvmx_write_csr(CVMX_CIU_WDOGX(cvmx_get_core_num()), 0);
#endif

	while (1)
		cvmx_write_csr(CVMX_CIU_SOFT_RST, 1);
}


/**
 * Permanently stop a core.
 *
 * @param arg
 */
static void octeon_kill_core(void *arg)
{
	mb();
	if (octeon_is_simulation()) {
		/* The simulator needs the watchdog to stop for dead cores */
		cvmx_write_csr(CVMX_CIU_WDOGX(cvmx_get_core_num()), 0);
		/* A break instruction causes the simulator stop a core */
		asm volatile ("sync\nbreak");
	}
}


/**
 * Halt the system
 */
static void octeon_halt(void)
{
	smp_call_function(octeon_kill_core, NULL, 0, 0);
	octeon_poweroff();
	octeon_kill_core(NULL);
}


/**
 * Read the Octeon high performance counter
 *
 * @return The counter value. For some brain dead reason, the kernel
 *         uses a 32bit number here.
 */
static cycles_t octeon_hpt_read(void)
{
	cycles_t cycles;
      asm("rdhwr %0,$31":"=r"(cycles));
	return cycles;
}


/**
 * Acknowledge a timer tick. We don't use the standard Mips
 * one because it confuses the timer ticks and the HPT clock.
 */
static void octeon_timer_ack(void)
{
	uint32_t count;
	uint32_t next_compare = read_c0_compare() + CYCLES_PER_JIFFY;
	write_c0_compare(next_compare);
	count = read_c0_count();
	if ((count - next_compare) < 0x7fffffff) {
		next_compare = count + CYCLES_PER_JIFFY;
		write_c0_compare(next_compare);
	}
}


/**
 * Interrupt entry point for timer ticks
 *
 * @param irq
 * @param dev_id
 * @return
 */
static irqreturn_t octeon_main_timer_interrupt(int irq, void *dev_id)
{
	if (read_c0_cause() & (1 << 30)) {
		if (smp_processor_id() == 0) {
			/* This function calls the timer ack internally */
			timer_interrupt(irq, dev_id);
		} else {
			octeon_timer_ack();
			local_timer_interrupt(irq, dev_id);
		}
		return IRQ_HANDLED;
	} else
		return IRQ_NONE;
}


/**
 * Setup the first cores timer interrupt
 *
 * @param irq
 * @return
 */
void __init plat_timer_setup(struct irqaction *irq)
{
	irq->handler = octeon_main_timer_interrupt;
	irq->flags |= SA_SHIRQ;
	setup_irq(7, irq);
}


/**
 * Handle all the error condition interrupts that might occur.
 *
 * @param cpl
 * @param dev_id
 * @return
 */
static irqreturn_t octeon_rlm_interrupt(int cpl, void *dev_id)
{
	irqreturn_t result = IRQ_NONE;
	cvmx_npei_rsl_int_blocks_t rsl_blocks;

	uint64_t clr_val;
	if (octeon_has_feature(OCTEON_FEATURE_PCIE))
		rsl_blocks.u64 = cvmx_read_csr(CVMX_PEXP_NPEI_RSL_INT_BLOCKS);
	else
		rsl_blocks.u64 = cvmx_read_csr(CVMX_NPI_RSL_INT_BLOCKS);

	/* rsl_blocks Bits 63-31 not used */

	if (rsl_blocks.s.iob) {	/* 30 - IOB_INT_SUM */
		cvmx_iob_int_sum_t err;

		err.u64 = cvmx_read_csr(CVMX_IOB_INT_SUM);
		cvmx_write_csr(CVMX_IOB_INT_SUM, err.u64);
		if (err.u64) {
			unsigned int port = cvmx_read_csr(CVMX_IOB_PKT_ERR);
			if (err.s.np_sop)
				printk("\nIOB: Port %u SOP error\n", port);
			if (err.s.np_eop)
				printk("\nIOB: Port %u EOP error\n", port);
			if (err.s.p_sop)
				printk("\nIOB: Passthrough Port %u SOP error\n",
				       port);
			if (err.s.p_eop)
				printk("\nIOB: Passthrough Port %u EOP error\n",
				       port);
			if (err.s.np_dat)
				printk("\nIOB: Data arrived before a SOP for the same port for a non-passthrough packet.\n");
			if (err.s.p_dat)
				printk("\nIOB: Data arrived before a SOP for the same port for a passthrough packet.\n");
			result = IRQ_HANDLED;
		}
	}


	if (rsl_blocks.s.lmc1) {	/* 29 - LMC_MEM_CFG1 */
		static unsigned long single_bit_errors = 0;
		static unsigned long double_bit_errors = 0;
		const int ddr_controller = 1;
		cvmx_lmcx_mem_cfg0_t mem_cfg0;
                cvmx_lmc_fadr_t fadr;

		mem_cfg0.u64 =cvmx_read_csr(CVMX_LMCX_MEM_CFG0(ddr_controller));
                fadr.u64 = cvmx_read_csr(CVMX_LMCX_FADR (ddr_controller));
		cvmx_write_csr(CVMX_LMCX_MEM_CFG0(ddr_controller),mem_cfg0.u64);
		if (mem_cfg0.s.sec_err || mem_cfg0.s.ded_err) {
			single_bit_errors += hweight64(mem_cfg0.s.sec_err);
			double_bit_errors += hweight64(mem_cfg0.s.ded_err);
			if ((mem_cfg0.s.ded_err) || (mem_cfg0.s.sec_err &&
				ECC_REPORT_SINGLE_BIT_ERRORS)) {
				printk("\nDDR%d ECC: %lu Single bit corrections, %lu Double bit errors\n" "DDR%d ECC:\tFailing dimm:   %u\n" "DDR%d ECC:\tFailing rank:   %u\n" "DDR%d ECC:\tFailing bank:   %u\n" "DDR%d ECC:\tFailing row:    0x%x\n" "DDR%d ECC:\tFailing column: 0x%x\n", ddr_controller, single_bit_errors, double_bit_errors, ddr_controller, fadr.s.fdimm, ddr_controller, fadr.s.fbunk, ddr_controller, fadr.s.fbank, ddr_controller, fadr.s.frow, ddr_controller, fadr.s.fcol);
			}
			result = IRQ_HANDLED;
		}
	}

	/* rsl_blocks Bits 28-24 not used */

	if (rsl_blocks.s.asxpcs1) {	/* 23 - ASX1_INT_REG */
		if (OCTEON_IS_MODEL(OCTEON_CN3XXX) ||
		    OCTEON_IS_MODEL(OCTEON_CN58XX) ||
		    OCTEON_IS_MODEL(OCTEON_CN50XX)) {
			cvmx_asxx_int_reg_t err;

			err.u64 = cvmx_read_csr(CVMX_ASXX_INT_REG(1));
			cvmx_write_csr(CVMX_ASXX_INT_REG(1), err.u64);
			if (err.u64) {
				int port;
				for (port = 0; port < 4; port++) {
					if (err.s.ovrflw & (1 << port))
						printk("ASX1: RX FIFO overflow on RMGII port %d\n", port + 16);
					if (err.s.txpop & (1 << port))
						printk("ASX1: TX FIFO underflow on RMGII port %d\n", port + 16);
					if (err.s.txpsh & (1 << port))
						printk("ASX1: TX FIFO overflow on RMGII port %d\n", port + 16);
				}
				result = IRQ_HANDLED;
			}
		} else {
			printk("FIXME: PCS0/1_INT(0..3)_REG needs decode\n");
		}
	}

	if (rsl_blocks.s.asxpcs0) {	/* 22- ASX0_INT_REG */
		if (OCTEON_IS_MODEL(OCTEON_CN3XXX) ||
		    OCTEON_IS_MODEL(OCTEON_CN58XX) ||
		    OCTEON_IS_MODEL(OCTEON_CN50XX)) {
			cvmx_asxx_int_reg_t err;

			err.u64 = cvmx_read_csr(CVMX_ASXX_INT_REG(0));
			cvmx_write_csr(CVMX_ASXX_INT_REG(0), err.u64);
			if (err.u64) {
				int port;
				for (port = 0; port < 4; port++) {
					if (err.s.ovrflw & (1 << port))
						printk("ASX0: RX FIFO overflow on RMGII port %d\n", port);
					if (err.s.txpop & (1 << port))
						printk("ASX0: TX FIFO underflow on RMGII port %d\n", port);
					if (err.s.txpsh & (1 << port))
						printk("ASX0: TX FIFO overflow on RMGII port %d\n", port);
				}
				result = IRQ_HANDLED;
			}
		} else {
			printk("FIXME: PCS0/1_INT(0..3)_REG needs decode\n");
		}
	}

	/* rsl_blocks Bit 21 not used */

	if (rsl_blocks.s.pip) {	/* 20 - PIP_INT_REG. */
		cvmx_pip_int_reg_t err;

		err.u64 = cvmx_read_csr(CVMX_PIP_INT_REG);
		cvmx_write_csr(CVMX_PIP_INT_REG, err.u64);
		if (err.u64) {
			/* Don't report disabled errors */
			err.u64 &= cvmx_read_csr(CVMX_PIP_INT_EN);
			if (err.s.beperr)
				printk("PIP: Parity Error in back end memory\n");
			if (err.s.feperr)
				printk("PIP: Parity Error in front end memory\n");
			if (err.s.todoovr)
				printk("PIP: Todo list overflow (see PIP_BCK_PRS[HIWATER])\n");
			if (err.s.skprunt)
				printk("PIP: Packet was engulfed by skipper\n");
			if (err.s.badtag)
				printk("PIP: A bad tag was sent from IPD\n");
			if (err.s.prtnxa)
				printk("PIP: Non-existent port\n");
			if (err.s.bckprs)
				printk("PIP: PIP asserted backpressure\n");
			if (err.s.crcerr)
				printk("PIP: PIP calculated bad CRC\n");
			if (err.s.pktdrp)
				printk("PIP: Packet Dropped due to QOS\n");
			result = IRQ_HANDLED;
		}
	}

	/* 19 - SPX1_INT_REG & STX1_INT_REG */
	/* Currently not checked. These should be checked by the ethernet
	   driver */

	/* 18 - SPX0_INT_REG & STX0_INT_REG */
	/* Currently not checked. These should be checked by the ethernet
	   driver */

	if (rsl_blocks.s.lmc0) {	/* 17 - LMC_MEM_CFG0 */
		static unsigned long single_bit_errors = 0;
		static unsigned long double_bit_errors = 0;
		const int ddr_controller = 0;
		cvmx_lmcx_mem_cfg0_t mem_cfg0;
                cvmx_lmc_fadr_t fadr;

		mem_cfg0.u64 =cvmx_read_csr(CVMX_LMCX_MEM_CFG0(ddr_controller));
                fadr.u64 = cvmx_read_csr(CVMX_LMCX_FADR(ddr_controller));
		cvmx_write_csr(CVMX_LMCX_MEM_CFG0(ddr_controller),mem_cfg0.u64);
		if (mem_cfg0.s.sec_err || mem_cfg0.s.ded_err) {
			single_bit_errors += hweight64(mem_cfg0.s.sec_err);
			double_bit_errors += hweight64(mem_cfg0.s.ded_err);
			if ((mem_cfg0.s.ded_err) || (mem_cfg0.s.sec_err &&
				ECC_REPORT_SINGLE_BIT_ERRORS)) {
				printk("\nDDR%d ECC: %lu Single bit corrections, %lu Double bit errors\n" "DDR%d ECC:\tFailing dimm:   %u\n" "DDR%d ECC:\tFailing rank:   %u\n" "DDR%d ECC:\tFailing bank:   %u\n" "DDR%d ECC:\tFailing row:    0x%x\n" "DDR%d ECC:\tFailing column: 0x%x\n", ddr_controller, single_bit_errors, double_bit_errors, ddr_controller, fadr.s.fdimm, ddr_controller, fadr.s.fbunk, ddr_controller, fadr.s.fbank, ddr_controller, fadr.s.frow, ddr_controller, fadr.s.fcol);
			}
			result = IRQ_HANDLED;
		}
	}

	if (rsl_blocks.s.l2c) {	/* 16 - L2T_ERR & L2D_ERR */
		cvmx_l2t_err_t terr;
		cvmx_l2d_err_t derr;

		terr.u64 = cvmx_read_csr(CVMX_L2T_ERR);
		cvmx_write_csr(CVMX_L2T_ERR, terr.u64);
		if (terr.u64) {
			if (terr.s.ded_err) {
				printk("L2T ECC: double bit:\tfadr: 0x%x, fset: 0x%x, fsyn: 0x%x, jiffies: %lud\n", terr.s.fadr, terr.s.fset, terr.s.fsyn, jiffies);
			}
			if (terr.s.sec_err && ECC_REPORT_SINGLE_BIT_ERRORS) {
				printk("L2T ECC: single bit:\tfadr: 0x%x, fset: 0x%x, fsyn: 0x%x, jiffies: %lud\n", terr.s.fadr, terr.s.fset, terr.s.fsyn, jiffies);
			}
			if (terr.s.ded_err || terr.s.sec_err) {
				if (!terr.s.fsyn) {
					/* Syndrome is zero, which means error
					   was in non-hit line, so flush all
					   associations */
					int i;
					int l2_assoc = cvmx_l2c_get_num_assoc();

					for (i = 0; i < l2_assoc; i++)
						cvmx_l2c_flush_line(i,
								    terr.s.
								    fadr);
				} else
					cvmx_l2c_flush_line(terr.s.fset,
							    terr.s.fadr);

			}
			if (terr.s.lckerr2)
				printk("L2T: HW detected a case where a Rd/Wr Miss from PP#n could not find an available/unlocked set (for replacement).\n");
			if (terr.s.lckerr)
				printk("L2T: SW attempted to LOCK DOWN the last available set of the INDEX (which is ignored by HW - but reported to SW).\n");
			result = IRQ_HANDLED;
		}

		clr_val = derr.u64 = cvmx_read_csr(CVMX_L2D_ERR);
		if (derr.u64) {

			cvmx_l2d_fadr_t fadr;
			result = IRQ_HANDLED;

			if (derr.s.ded_err ||
			    (derr.s.sec_err && ECC_REPORT_SINGLE_BIT_ERRORS)) {
				const int coreid = (int) cvmx_get_core_num();

				uint64_t syn0 = cvmx_read_csr(CVMX_L2D_FSYN0);
				uint64_t syn1 = cvmx_read_csr(CVMX_L2D_FSYN1);
				fadr.u64 = cvmx_read_csr(CVMX_L2D_FADR);

				if (derr.s.ded_err) {
					printk("\nL2D ECC double (core %d): fadr: 0x%llx, syn0:0x%llx, syn1: 0x%llx, jiffies: %lud\n", coreid, (unsigned long long) fadr.u64, (unsigned long long) syn0, (unsigned long long) syn1, jiffies);
				} else {
					printk("\nL2D ECC single (core %d): fadr: 0x%llx, syn0:0x%llx, syn1: 0x%llx, jiffies: %lud\n", coreid, (unsigned long long) fadr.u64, (unsigned long long) syn0, (unsigned long long) syn1, jiffies);
				}
				/* Flush the line that had the error */
				if (derr.s.ded_err || derr.s.sec_err)
					cvmx_l2c_flush_line(fadr.cn38xx.fset,
							    fadr.cn38xx.
							    fadr >> 1);
			}
		}
		cvmx_write_csr(CVMX_L2D_ERR, clr_val);
	}

	if (rsl_blocks.s.usb1) {	/* 15 - USB1 USBN1_INT_SUM */
		cvmx_usbnx_int_sum_t err;
		err.u64 = cvmx_read_csr(CVMX_USBNX_INT_SUM(1));
		cvmx_write_csr(CVMX_USBNX_INT_SUM(1), err.u64);
		if (err.u64) {
			if (err.s.nd4o_dpf)
				printk("USB1: NCB DMA Out Data Fifo Push Full\n");
			if (err.s.nd4o_dpe)
				printk("USB1: NCB DMA Out Data Fifo Pop Empty\n");
			if (err.s.nd4o_rpf)
				printk("USB1: NCB DMA Out Request Fifo Push Full\n");
			if (err.s.nd4o_rpe)
				printk("USB1: NCB DMA Out Request Fifo Pop Empty\n");
			if (err.s.ltl_f_pf)
				printk("USB1: L2C Transfer Length Fifo Push Full\n");
			if (err.s.ltl_f_pe)
				printk("USB1: L2C Transfer Length Fifo Pop Empty\n");
			if (err.s.u2n_c_pe)
				printk("USB1: U2N Control Fifo Pop Empty\n");
			if (err.s.u2n_c_pf)
				printk("USB1: U2N Control Fifo Push Full\n");
			if (err.s.u2n_d_pf)
				printk("USB1: U2N Data Fifo Push Full\n");
			if (err.s.u2n_d_pe)
				printk("USB1: U2N Data Fifo Pop Empty\n");
			if (err.s.n2u_pe)
				printk("USB1: N2U Fifo Pop Empty\n");
			if (err.s.n2u_pf)
				printk("USB1: N2U Fifo Push Full\n");
			if (err.s.uod_pf)
				printk("USB1: UOD Fifo Push Full\n");
			if (err.s.uod_pe)
				printk("USB1: UOD Fifo Pop Empty\n");
			if (err.s.rq_q3_e)
				printk("USB1: Request Queue-3 Fifo Pushed When Full\n");
			if (err.s.rq_q3_f)
				printk("USB1: Request Queue-3 Fifo Pushed When Full\n");
			if (err.s.rq_q2_e)
				printk("USB1: Request Queue-2 Fifo Pushed When Full\n");
			if (err.s.rq_q2_f)
				printk("USB1: Request Queue-2 Fifo Pushed When Full\n");
			if (err.s.rg_fi_f)
				printk("USB1: Register Request Fifo Pushed When Full\n");
			if (err.s.rg_fi_e)
				printk("USB1: Register Request Fifo Pushed When Full\n");
			if (err.s.lt_fi_f)
				printk("USB1: L2C Request Fifo Pushed When Full\n");
			if (err.s.lt_fi_e)
				printk("USB1: L2C Request Fifo Pushed When Full\n");
			if (err.s.l2c_a_f)
				printk("USB1: L2C Credit Count Added When Full\n");
			if (err.s.l2c_s_e)
				printk("USB1: L2C Credit Count Subtracted When Empty\n");
			if (err.s.dcred_f)
				printk("USB1: Data CreditFifo Pushed When Full\n");
			if (err.s.dcred_e)
				printk("USB1: Data Credit Fifo Pushed When Full\n");
			if (err.s.lt_pu_f)
				printk("USB1: L2C Trasaction Fifo Pushed When Full\n");
			if (err.s.lt_po_e)
				printk("USB1: L2C Trasaction Fifo Popped When Full\n");
			if (err.s.nt_pu_f)
				printk("USB1: NPI Trasaction Fifo Pushed When Full\n");
			if (err.s.nt_po_e)
				printk("USB1: NPI Trasaction Fifo Popped When Full\n");
			if (err.s.pt_pu_f)
				printk("USB1: PP  Trasaction Fifo Pushed When Full\n");
			if (err.s.pt_po_e)
				printk("USB1: PP  Trasaction Fifo Popped When Full\n");
			if (err.s.lr_pu_f)
				printk("USB1: L2C Request Fifo Pushed When Full\n");
			if (err.s.lr_po_e)
				printk("USB1: L2C Request Fifo Popped When Empty\n");
			if (err.s.nr_pu_f)
				printk("USB1: NPI Request Fifo Pushed When Full\n");
			if (err.s.nr_po_e)
				printk("USB1: NPI Request Fifo Popped When Empty\n");
			if (err.s.pr_pu_f)
				printk("USB1: PP  Request Fifo Pushed When Full\n");
			if (err.s.pr_po_e)
				printk("USB1: PP  Request Fifo Popped When Empty\n");
			result = IRQ_HANDLED;
		}
	}

	if (rsl_blocks.s.rad) {	/* 14 - RAID RAD_REG_ERROR */
		cvmx_rad_reg_error_t err;
		err.u64 = cvmx_read_csr(CVMX_RAD_REG_ERROR);
		cvmx_write_csr(CVMX_RAD_REG_ERROR, err.u64);
		if (err.u64) {
			if (err.s.doorbell)
				printk("RAID: A doorbell count has overflowed\n");
			result = IRQ_HANDLED;
		}
	}

	if (rsl_blocks.s.usb) {	/* 13 - USB0 USBN0_INT_SUM */
		cvmx_usbnx_int_sum_t err;
		err.u64 = cvmx_read_csr(CVMX_USBNX_INT_SUM(0));
		cvmx_write_csr(CVMX_USBNX_INT_SUM(0), err.u64);
		if (err.u64) {
			if (err.s.nd4o_dpf)
				printk("USB0: NCB DMA Out Data Fifo Push Full\n");
			if (err.s.nd4o_dpe)
				printk("USB0: NCB DMA Out Data Fifo Pop Empty\n");
			if (err.s.nd4o_rpf)
				printk("USB0: NCB DMA Out Request Fifo Push Full\n");
			if (err.s.nd4o_rpe)
				printk("USB0: NCB DMA Out Request Fifo Pop Empty\n");
			if (err.s.ltl_f_pf)
				printk("USB0: L2C Transfer Length Fifo Push Full\n");
			if (err.s.ltl_f_pe)
				printk("USB0: L2C Transfer Length Fifo Pop Empty\n");
			if (err.s.u2n_c_pe)
				printk("USB0: U2N Control Fifo Pop Empty\n");
			if (err.s.u2n_c_pf)
				printk("USB0: U2N Control Fifo Push Full\n");
			if (err.s.u2n_d_pf)
				printk("USB0: U2N Data Fifo Push Full\n");
			if (err.s.u2n_d_pe)
				printk("USB0: U2N Data Fifo Pop Empty\n");
			if (err.s.n2u_pe)
				printk("USB0: N2U Fifo Pop Empty\n");
			if (err.s.n2u_pf)
				printk("USB0: N2U Fifo Push Full\n");
			if (err.s.uod_pf)
				printk("USB0: UOD Fifo Push Full\n");
			if (err.s.uod_pe)
				printk("USB0: UOD Fifo Pop Empty\n");
			if (err.s.rq_q3_e)
				printk("USB0: Request Queue-3 Fifo Pushed When Full\n");
			if (err.s.rq_q3_f)
				printk("USB0: Request Queue-3 Fifo Pushed When Full\n");
			if (err.s.rq_q2_e)
				printk("USB0: Request Queue-2 Fifo Pushed When Full\n");
			if (err.s.rq_q2_f)
				printk("USB0: Request Queue-2 Fifo Pushed When Full\n");
			if (err.s.rg_fi_f)
				printk("USB0: Register Request Fifo Pushed When Full\n");
			if (err.s.rg_fi_e)
				printk("USB0: Register Request Fifo Pushed When Full\n");
			if (err.s.lt_fi_f)
				printk("USB0: L2C Request Fifo Pushed When Full\n");
			if (err.s.lt_fi_e)
				printk("USB0: L2C Request Fifo Pushed When Full\n");
			if (err.s.l2c_a_f)
				printk("USB0: L2C Credit Count Added When Full\n");
			if (err.s.l2c_s_e)
				printk("USB0: L2C Credit Count Subtracted When Empty\n");
			if (err.s.dcred_f)
				printk("USB0: Data CreditFifo Pushed When Full\n");
			if (err.s.dcred_e)
				printk("USB0: Data Credit Fifo Pushed When Full\n");
			if (err.s.lt_pu_f)
				printk("USB0: L2C Trasaction Fifo Pushed When Full\n");
			if (err.s.lt_po_e)
				printk("USB0: L2C Trasaction Fifo Popped When Full\n");
			if (err.s.nt_pu_f)
				printk("USB0: NPI Trasaction Fifo Pushed When Full\n");
			if (err.s.nt_po_e)
				printk("USB0: NPI Trasaction Fifo Popped When Full\n");
			if (err.s.pt_pu_f)
				printk("USB0: PP  Trasaction Fifo Pushed When Full\n");
			if (err.s.pt_po_e)
				printk("USB0: PP  Trasaction Fifo Popped When Full\n");
			if (err.s.lr_pu_f)
				printk("USB0: L2C Request Fifo Pushed When Full\n");
			if (err.s.lr_po_e)
				printk("USB0: L2C Request Fifo Popped When Empty\n");
			if (err.s.nr_pu_f)
				printk("USB0: NPI Request Fifo Pushed When Full\n");
			if (err.s.nr_po_e)
				printk("USB0: NPI Request Fifo Popped When Empty\n");
			if (err.s.pr_pu_f)
				printk("USB0: PP  Request Fifo Pushed When Full\n");
			if (err.s.pr_po_e)
				printk("USB0: PP  Request Fifo Popped When Empty\n");
			result = IRQ_HANDLED;
		}
	}

	if (rsl_blocks.s.pow) {	/* 12 - POW_ECC_ERR */
		cvmx_pow_ecc_err_t err;

		err.u64 = cvmx_read_csr(CVMX_POW_ECC_ERR);
		cvmx_write_csr(CVMX_POW_ECC_ERR, err.u64);
		if (err.u64) {
			if (err.s.sbe && ECC_REPORT_SINGLE_BIT_ERRORS)
				printk("ECC: POW single bit error\n");
			if (err.s.dbe)
				printk("ECC: POW double bit error\n");
			if (err.s.dbe ||
			    (err.s.sbe && ECC_REPORT_SINGLE_BIT_ERRORS))
				printk("ECC:\tFailing syndrome %u\n",
				       err.s.syn);
			if (err.s.rpe)
				printk("POW: Remote pointer error\n");
			if (err.s.iop & (1 << 0))
				printk("POW: Received SWTAG/SWTAG_FULL/SWTAG_DESCH/DESCH/UPD_WQP from PP in NULL_NULL state\n");
			if (err.s.iop & (1 << 1))
				printk("POW: Received SWTAG/SWTAG_DESCH/DESCH/UPD_WQP from PP in NULL state\n");
			if (err.s.iop & (1 << 2))
				printk("POW: Received SWTAG/SWTAG_FULL/SWTAG_DESCH/GET_WORK from PP with pending tag switch to ORDERED or ATOMIC\n");
			if (err.s.iop & (1 << 3))
				printk("POW: Received SWTAG/SWTAG_FULL/SWTAG_DESCH from PP with tag specified as NULL_NULL\n");
			if (err.s.iop & (1 << 4))
				printk("POW: Received SWTAG_FULL/SWTAG_DESCH from PP with tag specified as NULL\n");
			if (err.s.iop & (1 << 5))
				printk("POW: Received SWTAG/SWTAG_FULL/SWTAG_DESCH/DESCH/UPD_WQP/GET_WORK/NULL_RD from PP with GET_WORK pending\n");
			if (err.s.iop & (1 << 6))
				printk("POW: Received SWTAG/SWTAG_FULL/SWTAG_DESCH/DESCH/UPD_WQP/GET_WORK/NULL_RD from PP with NULL_RD pending\n");
			if (err.s.iop & (1 << 7))
				printk("POW: Received CLR_NSCHED from PP with SWTAG_DESCH/DESCH/CLR_NSCHED pending\n");
			if (err.s.iop & (1 << 8))
				printk("POW: Received SWTAG/SWTAG_FULL/SWTAG_DESCH/DESCH/UPD_WQP/GET_WORK/NULL_RD from PP with CLR_NSCHED pending\n");
			if (err.s.iop & (1 << 9))
				printk("POW: Received illegal opcode\n");
			if (err.s.iop & (1 << 10))
				printk("POW: Received ADD_WORK with tag specified as NULL_NULL\n");
			if (err.s.iop & (1 << 11))
				printk("POW: Received DBG load from PP with DBG load pending\n");
			if (err.s.iop & (1 << 12))
				printk("POW: Received CSR load from PP with CSR load pending\n");
			result = IRQ_HANDLED;
		}
	}

	if (rsl_blocks.s.tim) {	/* 11 - TIM_REG_ERROR */
		cvmx_tim_reg_error_t err;

		err.u64 = cvmx_read_csr(CVMX_TIM_REG_ERROR);
		cvmx_write_csr(CVMX_TIM_REG_ERROR, err.u64);
		if (err.u64) {
			int i;
			for (i = 0; i < 16; i++)
				if (err.s.mask & (1 << i))
					printk("TIM: Timer wheel %d error\n",
					       i);
			result = IRQ_HANDLED;
		}
	}

	if (rsl_blocks.s.pko) {	/* 10 - PKO_REG_ERROR */
		cvmx_pko_reg_error_t err;

		err.u64 = cvmx_read_csr(CVMX_PKO_REG_ERROR);
		cvmx_write_csr(CVMX_PKO_REG_ERROR, err.u64);
		if (err.u64) {
			if (err.s.currzero)
				printk("PKO: A packet data pointer has size=0\n");
			if (err.s.doorbell)
				printk("PKO: A doorbell count has overflowed\n");
			if (err.s.parity)
				printk("PKO: A read-parity error has occurred in the port data buffer\n");
			result = IRQ_HANDLED;
		}
	}

	if (rsl_blocks.s.ipd) {	/* 9 - IPD_INT_SUM */
		cvmx_ipd_int_sum_t err;

		err.u64 = cvmx_read_csr(CVMX_IPD_INT_SUM);
		cvmx_write_csr(CVMX_IPD_INT_SUM, err.u64);
		if (err.u64) {
			if (err.s.pq_sub)
				printk("IPD: Port-qos subtract causes the counter to wrap.\n");
			if (err.s.pq_add)
				printk("IPD: Port-qos add causes the counter to wrap.\n");
			if (err.s.bc_ovr)
				printk("IPD: Byte-count to send to IOB overflows.\n");
			if (err.s.d_coll)
				printk("IPD: Packet/WQE data to be sent to IOB collides.\n");
			if (err.s.c_coll)
				printk("IPD: Packet/WQE commands to be sent to IOB collides.\n");
			if (err.s.cc_ovr)
				printk("IPD: Command credits to the IOB overflow.\n");
			if (err.s.dc_ovr)
				printk("IPD: Data credits to the IOB overflow.\n");
			if (err.s.bp_sub)
				printk("IPD: Backpressure subtract supplied illegal value.\n");
			if (err.s.prc_par3)
				printk("IPD: Parity error detected for bits [127:96] of the PBM memory.\n");
			if (err.s.prc_par2)
				printk("IPD: Parity error detected for bits [95:64] of the PBM memory.\n");
			if (err.s.prc_par1)
				printk("IPD: Parity error detected for bits [63:32] of the PBM memory.\n");
			if (err.s.prc_par0)
				printk("IPD: Parity error detected for bits [31:0] of the PBM memory.\n");
			result = IRQ_HANDLED;
		}
	}

	/* rsl_blocks Bits 8 not used */

	if (rsl_blocks.s.zip) {	/* 7 - ZIP_ERROR */
		if (octeon_has_feature(OCTEON_FEATURE_ZIP)) {
			cvmx_zip_error_t err;
			err.u64 = cvmx_read_csr(CVMX_ZIP_ERROR);
			cvmx_write_csr(CVMX_ZIP_ERROR, err.u64);
			if (err.s.doorbell)
				printk("ZIP: Doorbell overflow\n");
			result = IRQ_HANDLED;
		}
	}

	if (rsl_blocks.s.reserved_6_6) {	/* 6 - DFA_ERR */
		cvmx_dfa_err_t err;

		err.u64 = cvmx_read_csr(CVMX_DFA_ERR);
		cvmx_write_csr(CVMX_DFA_ERR, err.u64);
		if (err.u64) {
			if (err.s.dblovf)
				printk("DFA: Doorbell Overflow detected\n");
			if (err.s.cp2perr)
				printk("DFA: PP-CP2 Parity Error Detected\n");
			if (err.s.dteperr)
				printk("DFA: DTE Parity Error Detected\n");

			if (err.s.dtedbe)
				printk("ECC: DFA DTE 29b Double Bit Error Detected\n");
			if (err.s.dtesbe && ECC_REPORT_SINGLE_BIT_ERRORS)
				printk("ECC: DFA DTE 29b Single Bit Error Corrected\n");
			if (err.s.dtedbe ||
			    (err.s.dtesbe && ECC_REPORT_SINGLE_BIT_ERRORS))
				printk("ECC:\tFailing syndrome %u\n",
				       err.s.dtesyn);

			if (err.s.cp2dbe)
				printk("ECC: DFA PP-CP2 Double Bit Error Detected\n");
			if (err.s.cp2sbe && ECC_REPORT_SINGLE_BIT_ERRORS)
				printk("ECC: DFA PP-CP2 Single Bit Error Corrected\n");
			if (err.s.cp2dbe ||
			    (err.s.cp2sbe && ECC_REPORT_SINGLE_BIT_ERRORS))
				printk("ECC:\tFailing syndrome %u\n",
				       err.s.cp2syn);
			result = IRQ_HANDLED;
		}
	}

	if (rsl_blocks.s.fpa) {	/* 5 - FPA_INT_SUM */
		cvmx_fpa_int_sum_t err;

		err.u64 = cvmx_read_csr(CVMX_FPA_INT_SUM);
		cvmx_write_csr(CVMX_FPA_INT_SUM, err.u64);
		if (err.u64) {
			/* Don't report disabled errors */
			err.u64 &= cvmx_read_csr(CVMX_FPA_INT_ENB);
			if (err.s.q7_perr)
				printk("FPA: Queue 7 pointer read from the stack in the L2C does not have the FPA owner ship bit set.\n");
			if (err.s.q7_coff)
				printk("FPA: Queue 7 stack end tag is present and the count available is greater than than pointers present in the FPA.\n");
			if (err.s.q7_und)
				printk("FPA: Queue 7 page count available goes negative.\n");
			if (err.s.q6_perr)
				printk("FPA: Queue 6 pointer read from the stack in the L2C does not have the FPA owner ship bit set.\n");
			if (err.s.q6_coff)
				printk("FPA: Queue 6 stack end tag is present and the count available is greater than than pointers present in the FPA.\n");
			if (err.s.q6_und)
				printk("FPA: Queue 6 page count available goes negative.\n");
			if (err.s.q5_perr)
				printk("FPA: Queue 5 pointer read from the stack in the L2C does not have the FPA owner ship bit set.\n");
			if (err.s.q5_coff)
				printk("FPA: Queue 5 stack end tag is present and the count available is greater than than pointers present in the FPA.\n");
			if (err.s.q5_und)
				printk("FPA: Queue 5 page count available goes negative.\n");
			if (err.s.q4_perr)
				printk("FPA: Queue 4 pointer read from the stack in the L2C does not have the FPA owner ship bit set.\n");
			if (err.s.q4_coff)
				printk("FPA: Queue 4 stack end tag is present and the count available is greater than than pointers present in the FPA.\n");
			if (err.s.q4_und)
				printk("FPA: Queue 4 page count available goes negative.\n");
			if (err.s.q3_perr)
				printk("FPA: Queue 3 pointer read from the stack in the L2C does not have the FPA owner ship bit set.\n");
			if (err.s.q3_coff)
				printk("FPA: Queue 3 stack end tag is present and the count available is greater than than pointers present in the FPA.\n");
			if (err.s.q3_und)
				printk("FPA: Queue 3 page count available goes negative.\n");
			if (err.s.q2_perr)
				printk("FPA: Queue 2 pointer read from the stack in the L2C does not have the FPA owner ship bit set.\n");
			if (err.s.q2_coff)
				printk("FPA: Queue 2 stack end tag is present and the count available is greater than than pointers present in the FPA.\n");
			if (err.s.q2_und)
				printk("FPA: Queue 2 page count available goes negative.\n");
			if (err.s.q1_perr)
				printk("FPA: Queue 1 pointer read from the stack in the L2C does not have the FPA owner ship bit set.\n");
			if (err.s.q1_coff)
				printk("FPA: Queue 1 stack end tag is present and the count available is greater than than pointers present in the FPA.\n");
			if (err.s.q1_und)
				printk("FPA: Queue 1 page count available goes negative.\n");
			if (err.s.q0_perr)
				printk("FPA: Queue 0 pointer read from the stack in the L2C does not have the FPA owner ship bit set.\n");
			if (err.s.q0_coff)
				printk("FPA: Queue 0 stack end tag is present and the count available is greater than than pointers present in the FPA.\n");
			if (err.s.q0_und)
				printk("FPA: Queue 0 page count available goes negative.\n");
			if (err.s.fed1_dbe)
				printk("ECC: FPA Double Bit Error detected in FPF1.\n");
			if (err.s.fed1_sbe && ECC_REPORT_SINGLE_BIT_ERRORS)
				printk("ECC: FPA Single Bit Error detected in FPF1.\n");
			if (err.s.fed0_dbe)
				printk("ECC: FPA Double Bit Error detected in FPF0.\n");
			if (err.s.fed0_sbe && ECC_REPORT_SINGLE_BIT_ERRORS)
				printk("ECC: FPA Single Bit Error detected in FPF0.\n");
			result = IRQ_HANDLED;
		}
	}

	if (rsl_blocks.s.key) {	/* 4 - KEY_INT_SUM */
		cvmx_key_int_sum_t err;

		err.u64 = cvmx_read_csr(CVMX_KEY_INT_SUM);
		cvmx_write_csr(CVMX_KEY_INT_SUM, err.u64);
		if (err.u64) {
			/* Don't report disabled errors */
			err.u64 &= cvmx_read_csr(CVMX_KEY_INT_ENB);
			if (err.s.ked1_dbe)
				printk("ECC: KED1 double-bit error.\n");
			if (err.s.ked1_sbe && ECC_REPORT_SINGLE_BIT_ERRORS)
				printk("ECC: KED1 single-bit error.\n");
			if (err.s.ked0_dbe)
				printk("ECC: KED0 double-bit error.\n");
			if (err.s.ked0_sbe && ECC_REPORT_SINGLE_BIT_ERRORS)
				printk("ECC: KED0 single-bit error.\n");
			result = IRQ_HANDLED;
		}
	}

	if (rsl_blocks.s.npei) {	/* 3 - NPI_INT_SUM */
		if (!octeon_has_feature(OCTEON_FEATURE_PCIE)) {
			cvmx_pci_int_sum2_t err;

			err.u64 = cvmx_read_csr(CVMX_NPI_PCI_INT_SUM2);
			cvmx_write_csr(CVMX_NPI_PCI_INT_SUM2, err.u64);
			if (err.u64) {
				/* Don't report disabled errors */
				err.u64 &= cvmx_read_csr(CVMX_NPI_PCI_INT_ENB2);
				if (err.s.ill_rd)
					printk("PCI ERROR[ILL_RD]: A read to a disabled area of BAR1 or BAR2, when the mem area is disabled.\n");
				if (err.s.ill_wr)
					printk("PCI ERROR[ILL_WR]: A write to a disabled area of BAR1 or BAR2, when the mem area is disabled.\n");
				if (err.s.win_wr)
					printk("PCI ERROR[WIN_WR]: A write to the disabled window write-data register took place.\n");
				if (err.s.dma1_fi)
					printk("PCI ERROR[DMA1_FI]: A DMA operation operation finished that was required to set the FORCE-INT bit for counter 1.\n");
				if (err.s.dma0_fi)
					printk("PCI ERROR[DMA0_FI]: A DMA operation operation finished that was required to set the FORCE-INT bit for counter 0.\n");
				if (err.s.dtime1)
					printk("PCI ERROR[DTIME1]: When the value in the PCI_DMA_CNT1 register is not 0 the DMA_CNT1\n" "                  timer counts. When the DMA1_CNT timer has a value greater than the\n" "                  PCI_DMA_TIME1 register this bit is set. The timer is reset when the bit\n" "                  is written with a one.\n");
				if (err.s.dtime0)
					printk("PCI ERROR[DTIME0]: When the value in the PCI_DMA_CNT0 register is not 0 the DMA_CNT0\n" "                  timer counts. When the DMA0_CNT timer has a value greater than the\n" "                  PCI_DMA_TIME0 register this bit is set. The timer is reset when the bit\n" "                  is written with a one.\n");
				if (err.s.dcnt1)
					printk("PCI ERROR[DCNT1]: This bit indicates that PCI_DMA_CNT1 value is greater than the value in\n" "                  the PCI_DMA_INT_LEV1 register.\n");
				if (err.s.dcnt0)
					printk("PCI ERROR[DCNT0]: This bit indicates that PCI_DMA_CNT0 value is greater than the value in\n" "                  the PCI_DMA_INT_LEV0 register.\n");
				if (err.s.ptime3)
					printk("PCI ERROR[PTIME3]: When the value in the PCI_PKTS_SENT3 register is not 0 the Sent3\n" "                  timer counts. When the Sent3 timer has a value greater than the\n" "                  PCI_PKTS_SENT_TIME3 register this bit is set. The timer is reset when\n" "                  the bit is written with a 1.\n");
				if (err.s.ptime2)
					printk("PCI ERROR[PTIME2]: When the value in the PCI_PKTS_SENT(2) register is not 0 the Sent2 timer\n" "                  counts. When the Sent2 timer has a value greater than the\n" "                  PCI_PKTS_SENT2 register this bit is set. The timer is reset when the bit\n" "                  is written with a 1.\n");
				if (err.s.ptime1)
					printk("PCI ERROR[PTIME1]: When the value in the PCI_PKTS_SENT(1) register is not 0 the Sent1 timer\n" "                  counts. When the Sent1 timer has a value greater than the\n" "                  PCI_PKTS_SENT1 register this bit is set. The timer is reset when the bit\n" "                  is written with a 1.\n");
				if (err.s.ptime0)
					printk("PCI ERROR[PTIME0]: When the value in the PCI_PKTS_SENT0 register is not 0 the Sent0 timer\n" "                  counts. When the Sent0 timer has a value greater than the\n" "                  PCI_PKTS_SENT0 register this bit is set. The timer is reset when the bit\n" "                  is written with a 1.\n");
				if (err.s.pcnt3)
					printk("PCI ERROR[PCNT3]: This bit indicates that PCI_PKTS_SENT3 value is greater than the value in\n" "                  the PCI_PKTS_SENT_INT_LEV3 register.\n");
				if (err.s.pcnt2)
					printk("PCI ERROR[PCNT2]: This bit indicates that PCI_PKTS_SENT2 value is greater than the value in\n" "                  the PCI_PKTS_SENT_INT_LEV2 register.\n");
				if (err.s.pcnt1)
					printk("PCI ERROR[PCNT1]: This bit indicates that PCI_PKTS_SENT1 value is greater than the value in\n" "                  the PCI_PKTS_SENT_INT_LEV1 register.\n");
				if (err.s.pcnt0)
					printk("PCI ERROR[PCNT0]: This bit indicates that PCI_PKTS_SENT0 value is greater than the value in\n" "                  the PCI_PKTS_SENT_INT_LEV0 register.\n");
				if (err.s.rsl_int)
					printk("PCI ERROR[RSL_INT]: This bit is set when the RSL Chain has generated an interrupt.\n");
				if (err.s.ill_rrd)
					printk("PCI ERROR[ILL_RRD]: A read to the disabled PCI registers took place.\n");
				if (err.s.ill_rwr)
					printk("PCI ERROR[ILL_RWR]: A write to the disabled PCI registers took place.\n");
				if (err.s.dperr)
					printk("PCI ERROR[DPERR]: Data parity error detected by PCX core\n");
				if (err.s.aperr)
					printk("PCI ERROR[APERR]: Address parity error detected by PCX core\n");
				if (err.s.serr)
					printk("PCI ERROR[SERR]: SERR# detected by PCX core\n");
				if (err.s.tsr_abt)
					printk("PCI ERROR[TSR_ABT]: Target split-read abort detected\n");
				if (err.s.msc_msg)
					printk("PCI ERROR[MSC_MSG]: Master split completion message detected\n");
				if (err.s.msi_mabt)
					printk("PCI ERROR[MSI_MABT]: PCI MSI master abort.\n");
				if (err.s.msi_tabt)
					printk("PCI ERROR[MSI_TABT]: PCI MSI target abort.\n");
				if (err.s.msi_per)
					printk("PCI ERROR[MSI_PER]: PCI MSI parity error.\n");
				if (err.s.mr_tto)
					printk("PCI ERROR[MR_TTO]: PCI master retry time-out on read.\n");
				if (err.s.mr_abt)
					printk("PCI ERROR[MR_ABT]: PCI master abort on read.\n");
				if (err.s.tr_abt)
					printk("PCI ERROR[TR_ABT]: PCI target abort on read.\n");
				if (err.s.mr_wtto)
					printk("PCI ERROR[MR_WTTO]: PCI master retry time-out on write.\n");
				if (err.s.mr_wabt)
					printk("PCI ERROR[MR_WABT]: PCI master abort detected on write.\n");
				if (err.s.tr_wabt)
					printk("PCI ERROR[TR_WABT]: PCI target abort detected on write.\n");
				result = IRQ_HANDLED;
			}
		} else {
			printk("FIXME: NPEI_INT_SUM needs decode\n");
		}
	}

	if (rsl_blocks.s.gmx1) {	/* 2 - GMX1_RX*_INT_REG &
					   GMX1_TX_INT_REG */
		/* Currently not checked. These should be checked by the
		   ethernet driver */
	}

	if (rsl_blocks.s.gmx0) {	/* 1 - GMX0_RX*_INT_REG &
					   GMX0_TX_INT_REG */
		/* Currently not checked. These should be checked by the
		   ethernet driver */
	}

	if (rsl_blocks.s.mio) {	/* 0 - MIO_BOOT_ERR */
		cvmx_mio_boot_err_t err;

		err.u64 = cvmx_read_csr(CVMX_MIO_BOOT_ERR);
		cvmx_write_csr(CVMX_MIO_BOOT_ERR, err.u64);
		if (err.u64) {
			/* Don't report disabled errors */
			err.u64 &= cvmx_read_csr(CVMX_MIO_BOOT_INT);
			if (err.s.wait_err)
				printk("BOOT BUS: Wait mode error\n");
			if (err.s.adr_err)
				printk("BOOT BUS: Address decode error\n");
			result = IRQ_HANDLED;
		}
	}

	return result;
}


/**
 * Return a string representing the system type
 *
 * @return
 */
const char *get_system_type(void)
{
	return octeon_board_type_string();
}


/**
 * Early entry point for arch setup
 */
void prom_init(void)
{
	const int coreid = cvmx_get_core_num();
	int i;
	int argc;
	struct uart_port octeon_port;
	int octeon_uart;
	extern void pci_console_init(const char *arg);

	octeon_hal_init();
	octeon_check_cpu_bist();
#ifdef CONFIG_CAVIUM_OCTEON_2ND_KERNEL
	octeon_uart = 1;
#else
	octeon_uart = octeon_get_boot_uart();
#endif

	/* Disable All CIU Interrupts. The ones we need will be enabled later.
	   Read the SUM register so we know the write completed. */
	cvmx_write_csr(CVMX_CIU_INTX_EN0((coreid * 2)), 0);
	cvmx_write_csr(CVMX_CIU_INTX_EN0((coreid * 2 + 1)), 0);
	cvmx_write_csr(CVMX_CIU_INTX_EN1((coreid * 2)), 0);
	cvmx_write_csr(CVMX_CIU_INTX_EN1((coreid * 2 + 1)), 0);
	cvmx_read_csr(CVMX_CIU_INTX_SUM0((coreid * 2)));

#ifdef CONFIG_SMP
	octeon_write_lcd("LinuxSMP");
#else
	octeon_write_lcd("Linux");
#endif

#if !defined(CONFIG_KGDB) || !defined(CONFIG_CAVIUM_GDB)
	/* When debugging the linux kernel, force the cores to enter the debug
	   exception handler to break in.  */
	if (octeon_get_boot_debug_flag()) {
		cvmx_write_csr(CVMX_CIU_DINT, 1 << cvmx_get_core_num());
		cvmx_read_csr(CVMX_CIU_DINT);
	}
#endif

	/* Default to 64MB in the simulator to speed things up */
	if (octeon_is_simulation())
		MAX_MEMORY = 64ull << 20;

	arcs_cmdline[0] = 0;
	argc = octeon_get_boot_num_arguments();
	for (i = 0; i < argc; i++) {
		const char *arg = octeon_get_boot_argument(i);
		if ((strncmp(arg, "MEM=", 4) == 0) ||
		    (strncmp(arg, "mem=", 4) == 0)) {
			sscanf(arg + 4, "%llu", &MAX_MEMORY);
			MAX_MEMORY <<= 20;
			if (MAX_MEMORY == 0)
				MAX_MEMORY = 32ull << 30;
		} else if (strcmp(arg, "ecc_verbose") == 0) {
			ECC_REPORT_SINGLE_BIT_ERRORS = 1;
			printk("Reporting of single bit ECC errors is turned on\n");
		} else if (strlen(arcs_cmdline) + strlen(arg) + 1 <
			   sizeof(arcs_cmdline) - 1) {
			strcat(arcs_cmdline, " ");
			strcat(arcs_cmdline, arg);
		}
	}

	if (strstr(arcs_cmdline, "console=pci"))
		pci_console_init(strstr(arcs_cmdline, "console=pci") + 8);

	if (strstr(arcs_cmdline, "console=") == NULL) {
#ifdef CONFIG_GDB_CONSOLE
		strcat(arcs_cmdline, " console=gdb");
#else
#ifdef CONFIG_CAVIUM_OCTEON_2ND_KERNEL
		strcat(arcs_cmdline, " console=ttyS0,115200");
#else
		if (octeon_uart == 1)
			strcat(arcs_cmdline, " console=ttyS1,115200");
		else
			strcat(arcs_cmdline, " console=ttyS0,115200");
#endif
#endif
	}

	if (octeon_is_simulation()) {
		/* The simulator uses a mtdram device pre filled with the
		   filesystem. Also specify the calibration delay to avoid
		   calculating it every time */
		strcat(arcs_cmdline,
		       " rw root=1f00 lpj=60176 slram=root,0x40000000,+1073741824");
	}

	/* you should these macros defined in include/asm/bootinfo.h */
	mips_machgroup = MACH_GROUP_CAVIUM;
	mips_machtype = MACH_CAVIUM_OCTEON;

	mips_hpt_frequency = octeon_get_clock_rate();
	clocksource_mips.read = octeon_hpt_read;
	mips_timer_ack = octeon_timer_ack;
	CYCLES_PER_JIFFY = ((mips_hpt_frequency + HZ / 2) / HZ);

	_machine_restart = octeon_restart;
	_machine_halt = octeon_halt;

	memset(&octeon_port, 0, sizeof(octeon_port));
	octeon_port.flags = ASYNC_SKIP_TEST | UPF_SHARE_IRQ;
	octeon_port.iotype = UPIO_MEM;
	octeon_port.regshift = 3;	/* I/O addresses are every 8 bytes */
	octeon_port.uartclk = mips_hpt_frequency;	/* Clock rate of the
							   chip */
	octeon_port.fifosize = 64;
	octeon_port.mapbase = 0x0001180000000800ull + (1024 * octeon_uart);
	octeon_port.membase = cvmx_phys_to_ptr(octeon_port.mapbase);
#ifdef CONFIG_CAVIUM_OCTEON_2ND_KERNEL
	octeon_port.line = 0;
#else
	octeon_port.line = octeon_uart;
#endif
	if (!OCTEON_IS_MODEL(OCTEON_CN38XX_PASS2))	/* Only CN38XXp{1,2}
							   has errata with uart
							   interrupt */
		octeon_port.irq = 42 + octeon_uart;
	early_serial_setup(&octeon_port);

	octeon_user_io_init();

#ifdef CONFIG_KGDB
	{
		extern void putDebugChar(char ch);
		const char *s = "\r\nConnect GDB to this port\r\n";
		while (*s)
			putDebugChar(*s++);
	}
#endif

	strlcat(arcs_cmdline, " "CONFIG_CMDLINE, COMMAND_LINE_SIZE);
}



void __init plat_mem_setup(void)
{
#if CONFIG_CAVIUM_RESERVE32
	extern uint64_t octeon_reserve32_memory;
#endif
	uint64_t mem_alloc_size;
	uint64_t total;

	/* The Mips memory init uses the first memory location for some memory
	   vectors. When SPARSEMEM is in use, it doesn't verify that the size
	   is big enough for the final vectors. Making the smallest chuck 4MB
	   seems to be enough to consistantly work. This needs to be debugged
	   more */
	mem_alloc_size = 4 << 20;
	total = 0;
	if (mem_alloc_size > MAX_MEMORY)
		mem_alloc_size = MAX_MEMORY;

	/* When allocating memory, we want incrementing addresses from
	   bootmem_alloc so the code in add_memory_region can merge regions
	   next to each other */
	cvmx_bootmem_lock();
	while ((boot_mem_map.nr_map < BOOT_MEM_MAP_MAX) && (total < MAX_MEMORY)) {
#if defined(CONFIG_64BIT) || defined(CONFIG_64BIT_PHYS_ADDR)
		int64_t memory =
			cvmx_bootmem_phy_alloc(mem_alloc_size, 0, 0, 0x100000,
					       CVMX_BOOTMEM_FLAG_NO_LOCKING);
#elif defined(CONFIG_HIGHMEM)
		int64_t memory =
			cvmx_bootmem_phy_alloc(mem_alloc_size, 0, 1ull << 31,
					       0x100000,
					       CVMX_BOOTMEM_FLAG_NO_LOCKING);
#else
		int64_t memory =
			cvmx_bootmem_phy_alloc(mem_alloc_size, 0, 512 << 20,
					       0x100000,
					       CVMX_BOOTMEM_FLAG_NO_LOCKING);
#endif
		if (memory >= 0) {
			/* This function automatically merges address regions
			   next to each other if they are received in
			   incrementing order */
			add_memory_region(memory, mem_alloc_size, BOOT_MEM_RAM);
			total += mem_alloc_size;
		} else
			break;
	}
	cvmx_bootmem_unlock();

#if CONFIG_CAVIUM_RESERVE32
	/* Now that we've allocated the kernel memory it is safe to free the
		reserved region. We free it here so that builtin drivers can
		use the memory */
	if (octeon_reserve32_memory)
		cvmx_bootmem_free_named("CAVIUM_RESERVE32");
#endif /* CONFIG_CAVIUM_RESERVE32 */

	if (total == 0)
		panic("Unable to allocate memory from cvmx_bootmem_phy_alloc\n");
}


void prom_free_prom_memory(void)
{
	/* Add an interrupt handler for general failures. */
	request_irq(OCTEON_IRQ_RML, octeon_rlm_interrupt, SA_SHIRQ, "RML/RSL",
		    octeon_rlm_interrupt);

	/* Enable interrupt on IOB port SOP and EOP errors */
	{
		cvmx_iob_int_enb_t csr;
		csr.u64 = cvmx_read_csr(CVMX_IOB_INT_ENB);
		if (!OCTEON_IS_MODEL(OCTEON_CN3XXX)) {
			/* These two don't exist for chips before CN58XX */
			csr.s.p_dat = 1;
			csr.s.np_dat = 1;
		}
		csr.s.p_eop = 1;
		csr.s.p_sop = 1;
		csr.s.np_eop = 1;
		csr.s.np_sop = 1;
		cvmx_write_csr(CVMX_IOB_INT_ENB, csr.u64);
	}

	/* Enable ASX interrupts on errors */
	if (OCTEON_IS_MODEL(OCTEON_CN3XXX) || OCTEON_IS_MODEL(OCTEON_CN58XX) ||
	    OCTEON_IS_MODEL(OCTEON_CN50XX)) {
		int mask = 0xf;
		cvmx_asxx_int_en_t csr;
		if (OCTEON_IS_MODEL(OCTEON_CN31XX) ||
		    OCTEON_IS_MODEL(OCTEON_CN30XX) ||
		    OCTEON_IS_MODEL(OCTEON_CN50XX)) {
			mask = 0x7;
		} else {
			csr.u64 = cvmx_read_csr(CVMX_ASXX_INT_EN(1));
			csr.s.txpsh = mask;
			csr.s.txpop = mask;
			csr.s.ovrflw = mask;
			cvmx_write_csr(CVMX_ASXX_INT_EN(1), csr.u64);
		}

		csr.u64 = cvmx_read_csr(CVMX_ASXX_INT_EN(0));
		csr.s.txpsh = mask;
		csr.s.txpop = mask;
		csr.s.ovrflw = mask;
		cvmx_write_csr(CVMX_ASXX_INT_EN(0), csr.u64);
	}

	/* Enable PIP interrupts on errors */
	{
		cvmx_pip_int_en_t csr;
		csr.u64 = cvmx_read_csr(CVMX_PIP_INT_EN);
		csr.s.beperr = 1;
		csr.s.feperr = 1;
		csr.s.todoovr = 1;
		csr.s.skprunt = 1;
		csr.s.badtag = 1;
		csr.s.prtnxa = 1;
		csr.s.bckprs = 0;
		csr.s.crcerr = 0;
		csr.s.pktdrp = 0;
		cvmx_write_csr(CVMX_PIP_INT_EN, csr.u64);
	}

	/* Enable ECC Interrupts for double bit errors from main memory */
	if (OCTEON_IS_MODEL(OCTEON_CN3XXX) || OCTEON_IS_MODEL(OCTEON_CN58XX) ||
	    OCTEON_IS_MODEL(OCTEON_CN50XX)) {
		cvmx_lmc_mem_cfg0_t csr;
		csr.u64 = cvmx_read_csr(CVMX_LMC_MEM_CFG0);
		csr.s.intr_ded_ena = 1;
		csr.s.intr_sec_ena = ECC_REPORT_SINGLE_BIT_ERRORS;
		cvmx_write_csr(CVMX_LMC_MEM_CFG0, csr.u64);
	} else {
		cvmx_lmc_mem_cfg0_t csr;
		cvmx_l2c_cfg_t l2c_cfg;
		l2c_cfg.u64 = cvmx_read_csr(CVMX_L2C_CFG);
		if (l2c_cfg.s.dpres0) {
			csr.u64 = cvmx_read_csr(CVMX_LMCX_MEM_CFG0(0));
			csr.s.intr_ded_ena = 1;
			csr.s.intr_sec_ena = ECC_REPORT_SINGLE_BIT_ERRORS;
			cvmx_write_csr(CVMX_LMCX_MEM_CFG0(0), csr.u64);
		}
		if (l2c_cfg.s.dpres1) {
			csr.u64 = cvmx_read_csr(CVMX_LMCX_MEM_CFG0(1));
			csr.s.intr_ded_ena = 1;
			csr.s.intr_sec_ena = ECC_REPORT_SINGLE_BIT_ERRORS;
			cvmx_write_csr(CVMX_LMCX_MEM_CFG0(1), csr.u64);
		}
	}

	/* Enable ECC Interrupts for double bit errors from L2C Tags */
	{
		cvmx_l2t_err_t csr;
		csr.u64 = cvmx_read_csr(CVMX_L2T_ERR);
		csr.s.lck_intena2 = 1;
		csr.s.lck_intena = 1;
		csr.s.ded_intena = 1;
		csr.s.sec_intena = ECC_REPORT_SINGLE_BIT_ERRORS;
		csr.s.ecc_ena = 1;
		cvmx_write_csr(CVMX_L2T_ERR, csr.u64);
	}

	/* Enable ECC Interrupts for double bit errors from L2D Errors */
	{
		cvmx_l2d_err_t csr;
		csr.u64 = cvmx_read_csr(CVMX_L2D_ERR);
		csr.s.ded_intena = 1;
		csr.s.sec_intena = ECC_REPORT_SINGLE_BIT_ERRORS;
		csr.s.ecc_ena = 1;
		cvmx_write_csr(CVMX_L2D_ERR, csr.u64);
	}

	/* Enable USB1 errors */
	if (OCTEON_IS_MODEL(OCTEON_CN52XX)) {
		cvmx_usbnx_int_enb_t csr;
		csr.u64 = -1;
		csr.s.reserved_38_63 = 0;
		cvmx_write_csr(CVMX_USBNX_INT_ENB(1), csr.u64);
	}

	/* Enable RAID errors */
	if (OCTEON_IS_MODEL(OCTEON_CN56XX)) {
		cvmx_rad_reg_int_mask_t csr;
		csr.u64 = cvmx_read_csr(CVMX_RAD_REG_INT_MASK);
		csr.s.doorbell = 1;
		cvmx_write_csr(CVMX_RAD_REG_INT_MASK, csr.u64);
	}

	/* Enable USB0 errors */
	if (!OCTEON_IS_MODEL(OCTEON_CN38XX) && !OCTEON_IS_MODEL(OCTEON_CN58XX)) {
		cvmx_usbnx_int_enb_t csr;
		csr.u64 = -1;
		csr.s.reserved_38_63 = 0;
		cvmx_write_csr(CVMX_USBNX_INT_ENB(0), csr.u64);
	}

	/* Enable ECC Interrupts for double bit errors from the POW */
	{
		cvmx_pow_ecc_err_t csr;
		csr.u64 = cvmx_read_csr(CVMX_POW_ECC_ERR);
		if (!OCTEON_IS_MODEL(OCTEON_CN38XX_PASS2) &&
		    !OCTEON_IS_MODEL(OCTEON_CN31XX)) {
			/* These doesn't exist for chips CN31XX and CN38XXp2 */
			csr.s.iop_ie = 0x1fff;
		}
		csr.s.rpe_ie = 1;
		csr.s.dbe_ie = 1;
		csr.s.sbe_ie = ECC_REPORT_SINGLE_BIT_ERRORS;
		cvmx_write_csr(CVMX_POW_ECC_ERR, csr.u64);
	}

	/* Enable Timer interrupt on errors */
	{
		cvmx_tim_reg_int_mask_t csr;
		csr.u64 = cvmx_read_csr(CVMX_TIM_REG_INT_MASK);
		csr.s.mask = 0xffff;
		cvmx_write_csr(CVMX_TIM_REG_INT_MASK, csr.u64);
	}

	/* Enable PKO interrupt on errors */
	{
		cvmx_pko_reg_int_mask_t csr;
		csr.u64 = cvmx_read_csr(CVMX_PKO_REG_INT_MASK);
		if (!OCTEON_IS_MODEL(OCTEON_CN3XXX)) {
			/* These doesn't exist for chips before CN58XX */
			csr.s.currzero = 1;
		}
		csr.s.doorbell = 1;
		csr.s.parity = 1;
		cvmx_write_csr(CVMX_PKO_REG_INT_MASK, csr.u64);
	}

	/* Enable interrupts on IPD errors */
	{
		cvmx_ipd_int_enb_t csr;
		csr.u64 = cvmx_read_csr(CVMX_IPD_INT_ENB);
		if (!OCTEON_IS_MODEL(OCTEON_CN3XXX) &&
		    !OCTEON_IS_MODEL(OCTEON_CN58XX) &&
		    !OCTEON_IS_MODEL(OCTEON_CN50XX)) {
			/* These doesn't exist for chips before CN56XX */
			csr.s.pq_sub = 1;
			csr.s.pq_add = 1;
		}
		if (!OCTEON_IS_MODEL(OCTEON_CN38XX_PASS2) &&
		    !OCTEON_IS_MODEL(OCTEON_CN31XX) &&
		    !OCTEON_IS_MODEL(OCTEON_CN30XX) &&
		    !OCTEON_IS_MODEL(OCTEON_CN50XX)) {
			/* These doesn't exist for chips CN31XX and CN38XXp2 */
			csr.s.bc_ovr = 1;
			csr.s.d_coll = 1;
			csr.s.c_coll = 1;
			csr.s.cc_ovr = 1;
			csr.s.dc_ovr = 1;
		}
		csr.s.bp_sub = 1;
		csr.s.prc_par3 = 1;
		csr.s.prc_par2 = 1;
		csr.s.prc_par1 = 1;
		csr.s.prc_par0 = 1;
		cvmx_write_csr(CVMX_IPD_INT_ENB, csr.u64);
	}

	/* Enable zip interrupt on errors */
	if (octeon_has_feature(OCTEON_FEATURE_ZIP)) {
		cvmx_zip_int_mask_t csr;
		csr.u64 = cvmx_read_csr(CVMX_ZIP_INT_MASK);
		csr.s.doorbell = 1;
		cvmx_write_csr(CVMX_ZIP_INT_MASK, csr.u64);
	}

	/* Enable DFA interrupts on errors. CN30XX, CN56XX don't have a DFA
	   block. For others we have to read the fuse in CVMCTL to know if is
	   there. We disable DFA_ERROR[CP2PARENA] since they fire even when you
	   aren't using the parity features */
	if (!OCTEON_IS_MODEL(OCTEON_CN30XX) &&
	    !OCTEON_IS_MODEL(OCTEON_CN56XX) &&
	    !OCTEON_IS_MODEL(OCTEON_CN50XX) &&
	    ((__read_64bit_c0_register($9, 7) & (1 << 28)) == 0)) {
		cvmx_dfa_err_t csr;
		csr.u64 = cvmx_read_csr(CVMX_DFA_ERR);
		csr.s.dblina = 1;
		csr.s.cp2pina = 1;
		csr.s.cp2parena = 0;
		csr.s.dtepina = 1;
		csr.s.dteparena = 1;
		csr.s.dtedbina = 1;
		csr.s.dtesbina = ECC_REPORT_SINGLE_BIT_ERRORS;
		csr.s.dteeccena = 1;
		csr.s.cp2dbina = 1;
		csr.s.cp2sbina = ECC_REPORT_SINGLE_BIT_ERRORS;
		csr.s.cp2eccena = 1;
		cvmx_write_csr(CVMX_DFA_ERR, csr.u64);
	}

	/* Enable FPA interrupt on errors */
	{
		/* The Queue X stack end tag check is disabled due to Octeon
		   Pass 2 errata FPA-100. This error condition can be set
		   erroneously. */
		cvmx_fpa_int_enb_t csr;
		csr.u64 = cvmx_read_csr(CVMX_FPA_INT_ENB);
		csr.s.q7_perr = 1;
		csr.s.q7_coff = 0;
		csr.s.q7_und = 1;
		csr.s.q6_perr = 1;
		csr.s.q6_coff = 0;
		csr.s.q6_und = 1;
		csr.s.q5_perr = 1;
		csr.s.q5_coff = 0;
		csr.s.q5_und = 1;
		csr.s.q4_perr = 1;
		csr.s.q4_coff = 0;
		csr.s.q4_und = 1;
		csr.s.q3_perr = 1;
		csr.s.q3_coff = 0;
		csr.s.q3_und = 1;
		csr.s.q2_perr = 1;
		csr.s.q2_coff = 0;
		csr.s.q2_und = 1;
		csr.s.q1_perr = 1;
		csr.s.q1_coff = 0;
		csr.s.q1_und = 1;
		csr.s.q0_perr = 1;
		csr.s.q0_coff = 0;
		csr.s.q0_und = 1;
		csr.s.fed1_dbe = 1;
		csr.s.fed1_sbe = ECC_REPORT_SINGLE_BIT_ERRORS;
		csr.s.fed0_dbe = 1;
		csr.s.fed0_sbe = ECC_REPORT_SINGLE_BIT_ERRORS;
		cvmx_write_csr(CVMX_FPA_INT_ENB, csr.u64);
	}

	/* Enable Key memory interupts on errors */
	if (octeon_has_feature(OCTEON_FEATURE_KEY_MEMORY)) {
		cvmx_key_int_enb_t csr;
		csr.u64 = cvmx_read_csr(CVMX_KEY_INT_ENB);
		csr.s.ked1_dbe = 1;
		csr.s.ked1_sbe = ECC_REPORT_SINGLE_BIT_ERRORS;
		csr.s.ked0_dbe = 1;
		csr.s.ked0_sbe = ECC_REPORT_SINGLE_BIT_ERRORS;
		cvmx_write_csr(CVMX_KEY_INT_ENB, csr.u64);
	}

	/* Enable reporting PCI bus errors */
	if (octeon_is_pci_host()) {
		cvmx_pci_int_enb2_t csr;
		cvmx_npi_int_enb_t enb;
		csr.u64 = cvmx_read_csr(CVMX_NPI_PCI_INT_ENB2);
		csr.s.ill_rd = 1;
		csr.s.ill_wr = 1;
		csr.s.win_wr = 1;
		csr.s.dma1_fi = 1;
		csr.s.dma0_fi = 1;
		csr.s.rdtime1 = 1;
		csr.s.rdtime0 = 1;
		csr.s.rdcnt1 = 1;
		csr.s.rdcnt0 = 1;
		csr.s.rptime3 = 1;
		csr.s.rptime2 = 1;
		csr.s.rptime1 = 1;
		csr.s.rptime0 = 1;
		csr.s.rpcnt3 = 1;
		csr.s.rpcnt2 = 1;
		csr.s.rpcnt1 = 1;
		csr.s.rpcnt0 = 1;
		csr.s.rrsl_int = 1;
		csr.s.ill_rrd = 1;
		csr.s.ill_rwr = 1;
		csr.s.rdperr = 1;
		csr.s.raperr = 1;
		csr.s.rserr = 1;
		csr.s.rtsr_abt = 1;
		csr.s.rmsc_msg = 0;
		csr.s.rmsi_mabt = 1;
		csr.s.rmsi_tabt = 1;
		csr.s.rmsi_per = 1;
		csr.s.rmr_tto = 1;
		csr.s.rmr_abt = 0;
		csr.s.rtr_abt = 1;
		csr.s.rmr_wtto = 1;
		csr.s.rmr_wabt = 1;
		csr.s.rtr_wabt = 1;
		cvmx_write_csr(CVMX_NPI_PCI_INT_ENB2, csr.u64);

		enb.u64 = cvmx_read_csr(CVMX_NPI_INT_ENB);
		enb.s.pci_rsl = 1;
		cvmx_write_csr(CVMX_NPI_INT_ENB, enb.u64);
	}

	/* Enable Bootbus interupts on errors */
	{
		cvmx_mio_boot_int_t csr;
		csr.u64 = cvmx_read_csr(CVMX_MIO_BOOT_INT);
		csr.s.adr_int = 1;
		csr.s.wait_int = 1;
		cvmx_write_csr(CVMX_MIO_BOOT_INT, csr.u64);
	}

	/* This call is here so that it is performed after any TLB
	   initializations. It needs to be after these in case the
	   CONFIG_CAVIUM_RESERVE32_USE_WIRED_TLB option is set */
	octeon_hal_setup_reserved32();
}
