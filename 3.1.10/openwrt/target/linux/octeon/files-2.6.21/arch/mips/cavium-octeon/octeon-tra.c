/*
 *   Octeon TRA (trace buffer) driver
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2008 Cavium Networks
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <asm/tlbdebug.h>
#include "hal.h"
#include "cvmx-tra.h"

/* This define control whether every core is stopped to display its state
    when a trace buffer interrupt occurs. Doing this could cause deadlock,
    so it is off by default */
#define OCTEON_TRA_DUMP_CORES_ON_INTERRUPT 0


/**
 * Called when OCTEON_TRA_DUMP_CORES_ON_INTERRUPT is set to
 * dump the state of each core. Be careful what is put in here
 * since the system might be in a broken state.
 *
 * @param unused
 */
static void octeon_tra_dump_regs(void *unused)
{
    static DEFINE_SPINLOCK(lock);
    /* This lock is so the core output doesn't intermix with other cores */
    spin_lock(&lock);
    show_regs(get_irq_regs());
    dump_tlb_all();
    spin_unlock(&lock);
}


/**
 * This function is called when the trace buffer hits a trigger
 * or fills. We don't enable the fill interrupt, so it should
 * only be on triggers.
 *
 * @param cpl    Interrupt number
 * @param dev_id unused
 *
 * @return IRQ status, should always be IRQ_HANDLED
 */
static irqreturn_t octeon_tra_interrupt(int cpl, void *dev_id)
{
    /* Stop the trace buffer in case it is still running. A trigger
        should have already stopped it */
    cvmx_tra_enable(0);
    /* Clear the trace buffer interrupt status */
    cvmx_write_csr(CVMX_TRA_INT_STATUS, cvmx_read_csr(CVMX_TRA_INT_STATUS));

    /* We can optionally stop the other cores */
    if (OCTEON_TRA_DUMP_CORES_ON_INTERRUPT)
    {
        printk("Octeon Trace Buffer Dumping Core state\n");
        on_each_cpu(octeon_tra_dump_regs, NULL, 0, 1);
    }

    printk("Octeon Trace Buffer Start\n");
    cvmx_tra_display();
    printk("Octeon Trace Buffer End\n");

    /* Restart the trace buffer */
    cvmx_tra_enable(1);
    return IRQ_HANDLED;
}


/**
 * Module/ driver initialization.
 *
 * @return Zero on success
 */
static int __init octeon_tra_init(void)
{
    cvmx_tra_ctl_t control;
    cvmx_tra_filt_cmd_t filter;
    cvmx_tra_filt_sid_t source_filter;
    cvmx_tra_filt_did_t dest_filter;
    cvmx_tra_trig0_did_t trig0_did;
    uint64_t address;
    uint64_t address_mask;

    /* If this chip doesn't have a TRA, silently do nothing */
    if (!octeon_has_feature(OCTEON_FEATURE_TRA))
        return 0;

    control.u64 = 0;
    control.s.ignore_o = 1; /* We interpret wrap as being allowed to overwrite data */
    control.s.ciu_trg = 1;  /* Trigger a CIU interrupt when even happen */
    control.s.full_thr = 2; /* 3/4 full threshhold, but we don't use this for anything */
    control.s.time_grn = 1; /* Make timestamps very accurate */
    control.s.trig_ctl = 3; /* Use both triggers as stops */
    control.s.wrap = 1;     /* We don't want the TRA to stop when full */
    control.s.ena = 0;      /* It has to be disabled during setup */

    /* Setup the TRA filter to capture everything. The easiest way to do this
        is to set all bits except the reserved ones */
    filter.u64 = -1;
    filter.s.reserved_17_63 = 0;
    source_filter.u64 = -1;
    source_filter.s.reserved_20_63 = 0;
    dest_filter.u64 = -1;
    dest_filter.s.reserved_32_63 = 0;
    cvmx_tra_setup(control, filter, source_filter, dest_filter, 0, 0);

    /* Lets set the first trigger to match invalid accesses after the 2nd
        256MB. This is anything after 0x420000000. Since we can only really
        pick powers of two, we use the addressmask to ignore bits 63-35,33-30,
        and 28-0. If we were monitoring a lower address we couldn't ignore
        so many bits */
    address = 0x420000000ull;
    address_mask = 0x420000000ull;

    /* Setup the trigger 0 to stop the TRA when a specific memory address
        matches */
    filter.u64 = 0;
    filter.s.saa = 1;       /* Atomic operations can change memory */
    filter.s.iobdma = 0;    /* IO bus DMA accesses can't affect memory */
    filter.s.iobst = 0;     /* IO bus stores (CSRs) can't affect memory */
    filter.s.iobld64 = 0;   /* 64bit IO bus reads (CSRs) can't affect memory */
    filter.s.iobld32 = 0;   /* 32bit IO bus reads (CSRs) can't affect memory */
    filter.s.iobld16 = 0;   /* 16bit IO bus reads (CSRs) can't affect memory */
    filter.s.iobld8 = 0;    /* 8bit IO bus reads (CSRs) can't affect memory */
    filter.s.stt = 1;       /* Store full skipping L2 can change memory */
    filter.s.stp = 1;       /* Store partial can change memory */
    filter.s.stc = 1;       /* Store conditional can change memory */
    filter.s.stf = 1;       /* Store full can change memory */
    filter.s.ldt = 1;       /* Icache fills, skipping L2, may be of interest */
    filter.s.ldi = 1;       /* Icache fills may be of interest */
    filter.s.ldd = 1;       /* Dcache fills may be of interest */
    filter.s.psl1 = 1;      /* Dcache fills, skipping L2, may be of interest */
    filter.s.pl2 = 1;       /* Prefetch into L2 may be of interest */
    filter.s.dwb = 1;       /* Don't write back can change memory */

    /* Allow all destinations to match the trigger */
    trig0_did.u64 = -1;
    trig0_did.s.reserved_32_63 = 0;

    cvmx_tra_trig_setup(0, filter, source_filter, trig0_did, address, address_mask);

    /* Setup the 2nd trigger to match a different address. Lets try
        the region 0x400000000-0x40fffffff. Everything else is the same */
    address=0x400000000ull;
    address_mask=0xfffffffff0000000ull;
    cvmx_tra_trig_setup(1, filter, source_filter, trig0_did, address, address_mask);

    /* Hook up to the trace buffer interrupt so we know when a trigger happens */
    request_irq(OCTEON_IRQ_TRACE, octeon_tra_interrupt, SA_SHIRQ,
                "Trace buffer", octeon_tra_interrupt);

    /* All setup is complete. Enable the trace buffer */
    cvmx_tra_enable(1);
    printk("Octeon TRA driver loaded.\n");
    return 0;
}


/**
 * Module / driver shutdown
 */
static void __exit octeon_tra_cleanup(void)
{
    if (!octeon_has_feature(OCTEON_FEATURE_TRA))
        return;
    cvmx_tra_enable(0);
    free_irq(OCTEON_IRQ_TRACE, octeon_tra_interrupt);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cavium Networks <support@caviumnetworks.com>");
MODULE_DESCRIPTION("Cavium Networks Octeon TRA driver.");
module_init(octeon_tra_init);
module_exit(octeon_tra_cleanup);
