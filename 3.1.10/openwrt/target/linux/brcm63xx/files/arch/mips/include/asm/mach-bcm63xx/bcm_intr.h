/*
<:copyright-gpl 
 Copyright 2003 Broadcom Corp. All Rights Reserved. 
 
 This program is free software; you can distribute it and/or modify it 
 under the terms of the GNU General Public License (Version 2) as 
 published by the Free Software Foundation. 
 
 This program is distributed in the hope it will be useful, but WITHOUT 
 ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License 
 for more details. 
 
 You should have received a copy of the GNU General Public License along 
 with this program; if not, write to the Free Software Foundation, Inc., 
 59 Temple Place - Suite 330, Boston MA 02111-1307, USA. 
:>
*/

#ifndef __BCM_INTR_H
#define __BCM_INTR_H

#ifdef __cplusplus
    extern "C" {
#endif

#if defined(CONFIG_BCM63XX_CPU_6358)
#include <6358_intr.h>
#endif
#if defined(CONFIG_BCM63XX_CPU_6362)
#include <6362_intr.h>
#endif

/* defines */
#if defined(CONFIG_BCM63XX_CPU_6358)
typedef int (*FN_HANDLER) (int, void *);
#endif
#if defined(CONFIG_BCM63XX_CPU_6362)
/* The following definitions must match the definitions in linux/interrupt.h for 
   irqreturn_t and irq_handler_t */

typedef enum {  
    BCM_IRQ_NONE = 0,
    BCM_IRQ_HANDLED = 1,
    BCM_IRQ_WAKE_THREAD = 2
} FN_HANDLER_RT;
typedef FN_HANDLER_RT (*FN_HANDLER) (int, void *);
#endif


/* prototypes */
/* NOTE: The enable/disable functions do not appear symmetric, allowing enabling but not disabling of external interrupts. */
extern void enable_brcm_irq(unsigned int irq);
extern void disable_brcm_irq(unsigned int irq);
extern void dump_intr_regs(void);

/* bill BCM interrupt control prototypes */
/* NOTE: These routines only operate on HW interrupts between INTERRUPT_ID_TIMER and INTERRUPT_ID_I2C. */
extern void disable_brcm_irqsave(unsigned int irq, unsigned long stateSaveArray[]);
extern void restore_brcm_irqsave(unsigned int irq, unsigned long stateSaveArray[]);

#ifdef __cplusplus
    }
#endif

#endif
