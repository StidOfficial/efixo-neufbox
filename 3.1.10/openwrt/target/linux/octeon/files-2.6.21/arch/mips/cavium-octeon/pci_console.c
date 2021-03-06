/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2006-2007 Cavium Networks
 */
#include <linux/console.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/tty_flip.h>
#undef OCTEON_MODEL
#define USE_RUNTIME_MODEL_CHECKS 1
#include "hal.h"
#include "cvmx-bootmem.h"
#include "octeon-pci-console.h"

typedef struct {
	struct console con;
	struct tty_driver *ttydrv;
	struct timer_list poll_timer;
	int open_count;
	int index;
} pci_console_state_t;

static pci_console_state_t pci_console_state;
static struct tty_operations octeon_pci_tty_ops;
static spinlock_t pci_console_lock;
static uint64_t pci_console_base_address;


/**
 * Get the pci console state from a struct console
 *
 * @param con    struct console to get console for
 *
 * @return The console state
 */
static inline pci_console_state_t *get_state_con(struct console *con)
{
	return (pci_console_state_t *) con->data;
}


/**
 * Get the pci console state from a tty
 *
 * @param tty    tty to get console for
 *
 * @return The console state
 */
static inline pci_console_state_t *get_state_tty(struct tty_struct *tty)
{
	return (pci_console_state_t *) tty->driver->driver_state;
}


/**
 * Low level kernel write to the PCI console
 *
 * @param console_num
 *               Console to write to
 * @param str    String to write
 * @param len    Length of the string
 */
static void pci_console_lowlevel_write(int console_num, const char *str,
				       unsigned len)
{
	unsigned long flags;
	spin_lock_irqsave(&pci_console_lock, flags);
	while (len > 0) {
		int written =
			octeon_pci_console_write(pci_console_base_address,
						 console_num, str, len,
						 OCT_PCI_CON_FLAG_NONBLOCK);
		if (written > 0) {
			str += written;
			len -= written;
		}
	}
	spin_unlock_irqrestore(&pci_console_lock, flags);
}


/**
 * Kernel write to the PCI console
 *
 * @param con    Console to write to
 * @param str    String to write
 * @param len    Length of the string
 */
static void pci_console_write(struct console *con, const char *str,
			      unsigned len)
{
	pci_console_lowlevel_write(get_state_con(con)->index, str, len);
}


/**
 * Get a TTY driver for the console device. Used to allow
 * userspace to write to the kernel's console.
 *
 * @param con    Kernel's console
 * @param index  Which console index
 * @return TTY driver for userspace. NULL on failure.
 */
static struct tty_driver *pci_console_device(struct console *con, int *index)
{
	pci_console_state_t *console_state = get_state_con(con);
	*index = 0;
	return console_state->ttydrv;
}


/**
 * Called by Linux when the console=string is parsed
 *
 * @param con    Kernel's console
 * @param arg    Argument string
 * @return Zero on success
 */
static int pci_console_setup(struct console *con, char *arg)
{
	octeon_write_lcd("pci cons");
	if (pci_console_base_address == 0) {
		cvmx_bootmem_named_block_desc_t *block_desc =
			cvmx_bootmem_find_named_block
			(OCTEON_PCI_CONSOLE_BLOCK_NAME);
		if (block_desc == NULL) {
			octeon_write_lcd("pci fail");
			return -1;
		}
		pci_console_base_address = block_desc->base_addr;
	}
	return 0;
}


/**
 * Initialize the PCI console for use
 */
void pci_console_init(const char *arg)
{
	memset(&pci_console_state, 0, sizeof(pci_console_state));
	strcpy(pci_console_state.con.name, "pci");
	pci_console_state.con.write = pci_console_write;
	pci_console_state.con.device = pci_console_device;
	pci_console_state.con.setup = pci_console_setup;
	pci_console_state.con.data = &pci_console_state;
	if (arg && (arg[3] >= '0') && (arg[3] <= '9'))
		sscanf(arg + 3, "%d", &pci_console_state.index);
	else
		pci_console_state.index = 0;
	register_console(&pci_console_state.con);
}


/**
 * Called by a timer to poll the PCI device for input data
 *
 * @param arg    Pointer to the TTY structure
 */
static void pci_tty_read_poll(unsigned long arg)
{
	struct tty_struct *tty = (struct tty_struct *) arg;
	int index = get_state_tty(tty)->index;
	unsigned long flags;
	int count;
	spin_lock_irqsave(&pci_console_lock, flags);
	count = octeon_pci_console_read_avail(pci_console_base_address, index);
	if (count > 0) {
		char buffer[count];
		count = octeon_pci_console_read(pci_console_base_address, index,
						buffer, sizeof(buffer),
						OCT_PCI_CON_FLAG_NONBLOCK);
		tty_insert_flip_string(tty, buffer, count);
		tty_flip_buffer_push(tty);
	}
	spin_unlock_irqrestore(&pci_console_lock, flags);
	mod_timer(&get_state_tty(tty)->poll_timer, jiffies + 1);
}


/**
 * Called when userspace opens the TTY device. Can be called
 * multiple times.
 *
 * @param tty    Device to open
 * @param filp
 * @return Zero on success
 */
static int pci_tty_open(struct tty_struct *tty, struct file *filp)
{
	pci_console_state_t *console_state = get_state_tty(tty);
	console_state->open_count++;
	if (console_state->open_count == 1) {
		init_timer(&console_state->poll_timer);
		console_state->poll_timer.data = (unsigned long) tty;
		console_state->poll_timer.function = pci_tty_read_poll;
		mod_timer(&console_state->poll_timer, jiffies + 1);
	}
	return 0;
}


/**
 * Called when userspace closes the console TTY
 *
 * @param tty    TTY to close
 * @param filp
 */
static void pci_tty_close(struct tty_struct *tty, struct file *filp)
{
	pci_console_state_t *console_state = get_state_tty(tty);
	console_state->open_count--;
	if (console_state->open_count == 0)
		del_timer(&console_state->poll_timer);
}


/**
 * Called when usersapce does a block write
 *
 * @param tty    TTY to write too
 * @param buf    Data to write
 * @param count  number of bytes
 * @return Number of bytes written
 */
static int pci_tty_write(struct tty_struct *tty, const unsigned char *buf,
			 int count)
{
	pci_console_lowlevel_write(get_state_tty(tty)->index, buf, count);
	return count;
}


/**
 * Write a single character
 *
 * @param tty    TTY to write to
 * @param ch     Character to write
 */
static void pci_tty_put_char(struct tty_struct *tty, unsigned char ch)
{
	pci_console_lowlevel_write(get_state_tty(tty)->index, &ch, 1);
}


/**
 * Write a single character
 *
 * @param tty    TTY to write to
 * @param ch     Character to write
 */
static void pci_tty_send_xchar(struct tty_struct *tty, char ch)
{
	pci_console_lowlevel_write(get_state_tty(tty)->index, &ch, 1);
}


/**
 * Determine the amount of room available for output
 *
 * @param tty    TTY structure
 * @return Number of bytes
 */
static int pci_tty_write_room(struct tty_struct *tty)
{
	unsigned long flags;
	int count;
	spin_lock_irqsave(&pci_console_lock, flags);
	count = octeon_pci_console_write_avail(pci_console_base_address,
					       get_state_tty(tty)->index);
	spin_unlock_irqrestore(&pci_console_lock, flags);
	if (count)
		return count;
	else
		return 0;
}


/**
 * Return the number of characters pending. Needed for vi to work.
 *
 * @param tty    TTY structure
 *
 * @return Number of bytes
 */
static int pci_tty_chars_in_buffer(struct tty_struct *tty)
{
	return 0;
}

static __init int pci_console_module_init(void)
{
	pci_console_state.ttydrv = alloc_tty_driver(1);
	if (!pci_console_state.ttydrv)
		return 0;

	pci_console_state.ttydrv->owner = THIS_MODULE;
	pci_console_state.ttydrv->driver_name = "pci_console";
	pci_console_state.ttydrv->name = "ttyPCI";
	pci_console_state.ttydrv->type = TTY_DRIVER_TYPE_SERIAL;
	pci_console_state.ttydrv->subtype = SERIAL_TYPE_NORMAL;
	pci_console_state.ttydrv->flags = TTY_DRIVER_REAL_RAW;
	pci_console_state.ttydrv->major = 4;
	pci_console_state.ttydrv->minor_start = 96;
	pci_console_state.ttydrv->init_termios = tty_std_termios;
	pci_console_state.ttydrv->init_termios.c_cflag =
		B9600 | CS8 | CREAD | HUPCL | CLOCAL;
	pci_console_state.ttydrv->driver_state = &pci_console_state;
	tty_set_operations(pci_console_state.ttydrv, &octeon_pci_tty_ops);
	tty_register_driver(pci_console_state.ttydrv);
	return 0;
}

module_init(pci_console_module_init);

static struct tty_operations octeon_pci_tty_ops = {
	.open = pci_tty_open,
	.close = pci_tty_close,
	.write = pci_tty_write,
	.put_char = pci_tty_put_char,
	.write_room = pci_tty_write_room,
	.send_xchar = pci_tty_send_xchar,
	.chars_in_buffer = pci_tty_chars_in_buffer,
};
