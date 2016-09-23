/*
 * Extra-simple block driver for the Octeon bootbus compact flash. This
 * driver is based on the excellent article and example code from LWM.
 * http://lwn.net/Articles/58719/
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2005-2007 Cavium Networks
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/kernel.h>	/* printk() */
#include <linux/fs.h>		/* everything... */
#include <linux/errno.h>	/* error codes */
#include <linux/types.h>	/* size_t */
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>
#include <linux/ide.h>
#include <asm/delay.h>
#include <linux/completion.h>

#include "cvmx-app-init.h"
#include "hal.h"

#define VERSION "1.1"
#define DEVICE_NAME "cf"
MODULE_LICENSE("GPL");

/*
 * We can tweak our hardware sector size, but the kernel talks to us
 * in terms of small sectors, always.
 */
#define KERNEL_SECTOR_SIZE 512

/*
 * The internal representation of our device.
 */

typedef struct {
	void *base_ptr;
	unsigned long num_sectors;
	unsigned long sector_size;
	struct gendisk *gd;
	struct hd_geometry geo;
	spinlock_t lock;
	request_queue_t *queue;
	struct completion comp;
	int is16bit;
	int is_true_ide;	/* is16bit must also be set */
} cf_device_t;

static cf_device_t STATIC_DEVICE;


/**
 * Check if the Compact flash is idle and doesn't have any
 * errors.
 *
 * @param cf     Device to check
 * @return Zero on success
 */
static inline int ata_wait_idle(cf_device_t * cf)
{
	unsigned char status;
	unsigned long timeout = jiffies + HZ;

	// octeon_led_set(0, 30);

	if (cf->is_true_ide) {
		status = __raw_readw(cf->base_ptr + 14) & 0xff;
		while (status & 0x80) {
			if (unlikely(time_after(jiffies, timeout)))
				break;
			udelay(5);
			status = __raw_readw(cf->base_ptr + 14) & 0xff;
		}
	} else if (cf->is16bit) {
		status = __raw_readw(cf->base_ptr + 6) >> 8;
		while (status & 0x80) {
			if (unlikely(time_after(jiffies, timeout)))
				break;
			udelay(5);
			status = __raw_readw(cf->base_ptr + 6) >> 8;
		}
	} else {
		status = __raw_readb(cf->base_ptr + 7);
		while (status & 0x80) {
			if (unlikely(time_after(jiffies, timeout)))
				break;
			udelay(5);
			status = __raw_readb(cf->base_ptr + 7);
		}
	}
	// octeon_led_clear(0, 30);

	if (unlikely(status & 0x80)) {
		if (cf->gd)
			printk("%s: Timeout\n", cf->gd->disk_name);
		return -1;
	} else if (unlikely(status & 1)) {
		if (cf->gd)
			printk("%s: Error\n", cf->gd->disk_name);
		return -1;
	} else
		return 0;
}


/**
 * Wait for data request ready
 *
 * @param cf     Device to check
 * @return Zero on success
 */
static inline int ata_wait_drq_ready(cf_device_t * cf)
{
	unsigned char status;
	unsigned long timeout = jiffies + HZ;

	// octeon_led_set(0, 30);
	if (cf->is_true_ide) {
		status = __raw_readw(cf->base_ptr + 14) & 0xff;
		while ((status & 0x08) == 0) {
			if (unlikely(time_after(jiffies, timeout)))
				break;
			udelay(1);
			status = __raw_readw(cf->base_ptr + 14) & 0xff;
		}
	} else if (cf->is16bit) {
		status = __raw_readw(cf->base_ptr + 6) >> 8;
		while ((status & 0x08) == 0) {
			if (unlikely(time_after(jiffies, timeout)))
				break;
			udelay(1);
			status = __raw_readw(cf->base_ptr + 6) >> 8;
		}
	} else {
		status = __raw_readb(cf->base_ptr + 7);
		while ((status & 0x08) == 0) {
			if (unlikely(time_after(jiffies, timeout)))
				break;
			udelay(1);
			status = __raw_readb(cf->base_ptr + 7);
		}
	}
	// octeon_led_clear(0, 30);


	if (unlikely((status & 0x08) == 0)) {
		if (cf->gd)
			printk("%s: Timeout\n", cf->gd->disk_name);
		return -1;
	} else
		return 0;
}


/**
 * Send low level ATA command to the device
 *
 * @param cf      Device to send commadn to
 * @param sectors Number of sectors for access
 * @param lba     Logical block address
 * @param command ATA command
 * @return Zero on success
 */
static int ata_command(cf_device_t * cf, int sectors, unsigned long lba,
		       int command)
{
	/* Wait to not be busy before we start */
	if (ata_wait_idle(cf))
		return -1;

	if (cf->is_true_ide) {
		__raw_writew(sectors, cf->base_ptr + 4);
		__raw_writew(lba & 0xff, cf->base_ptr + 6);
		__raw_writew((lba >> 8) & 0xff, cf->base_ptr + 8);
		__raw_writew((lba >> 16) & 0xff, cf->base_ptr + 10);
		__raw_writew(((lba >> 24) & 0x0f) | 0xe0, cf->base_ptr + 12);
		__raw_writew(command, cf->base_ptr + 14);
	} else if (cf->is16bit) {
		__raw_writew(sectors | ((lba & 0xff) << 8), cf->base_ptr + 2);
		__raw_writew(lba >> 8, cf->base_ptr + 4);
		__raw_writew(((lba >> 24) & 0x0f) | 0xe0 | command << 8,
			     cf->base_ptr + 6);
	} else {
		__raw_writeb(sectors, cf->base_ptr + 2);
		__raw_writeb(lba & 0xff, cf->base_ptr + 3);
		__raw_writeb((lba >> 8) & 0xff, cf->base_ptr + 4);
		__raw_writeb((lba >> 16) & 0xff, cf->base_ptr + 5);
		__raw_writeb(((lba >> 24) & 0x0f) | 0xe0, cf->base_ptr + 6);
		__raw_writeb(command, cf->base_ptr + 7);
	}

	return 0;
}


/**
 * Identify the compact flash
 *
 * @param cf         Device to access
 * @param drive_info IDE drive information
 * @return Zero on success
 */
static int ata_identify(cf_device_t * cf, struct hd_driveid *drive_info)
{
	if (ata_command(cf, 0, 0, WIN_IDENTIFY))
		return -1;

	/* Wait for read to complete (BSY clear) */
	if (ata_wait_idle(cf))
		return -1;
	if (cf->is16bit) {
		uint16_t *ptr = (uint16_t *) drive_info;
		int count;
		for (count = 0; count < sizeof(*drive_info); count += 2)
			*ptr++ = readw(cf->base_ptr);	/* Swaps internally */
	} else {
		unsigned char *ptr = (unsigned char *) drive_info;
		int count;
		for (count = 0; count < sizeof(*drive_info); count++)
			*ptr++ = readb(cf->base_ptr);
	}
	ide_fix_driveid(drive_info);
	ide_fixstring(drive_info->model, sizeof(drive_info->model), 0);
	ide_fixstring(drive_info->fw_rev, sizeof(drive_info->fw_rev), 0);
	ide_fixstring(drive_info->serial_no, sizeof(drive_info->serial_no), 0);
	return 0;
}


/**
 * Read sectors from the device
 *
 * @param cf        Device to read from
 * @param lba_start Start sector
 * @param num_sectors
 *                  Number of sectors to read
 * @param buffer    Buffer to put the results in
 * @return Number of sectors read
 */
static int ata_read(cf_device_t * cf, unsigned long lba_start,
		    unsigned long num_sectors, char *buffer)
{
	int sectors_read = 0;

	// octeon_led_set(0, 31);
	while (sectors_read < num_sectors) {
		int count;
		int sectors_to_read = num_sectors;

		if (sectors_to_read > 256)
			sectors_to_read = 256;

		if (ata_command
		    (cf, sectors_to_read & 0xff, lba_start, WIN_READ))
			goto done;
		lba_start += sectors_to_read;

		while (sectors_to_read--) {
			/* Wait for read to complete (BSY clear) */
			if (ata_wait_idle(cf))
				goto done;
			if (ata_wait_drq_ready(cf))
				goto done;

			if (cf->is16bit) {
				uint16_t *ptr = (uint16_t *) buffer;
				for (count = 0; count < cf->sector_size;
				     count += 2)
					*ptr++ = readw(cf->base_ptr);
				buffer += cf->sector_size;
			} else {
				for (count = 0; count < cf->sector_size;
				     count++)
					*buffer++ = readb(cf->base_ptr);
			}
			sectors_read++;
		}
	}
      done:
	// octeon_led_clear(0, 31);

	return sectors_read;
}


/**
 * Write sectors to the device
 *
 * @param cf        Device to write to
 * @param lba_start Starting sector number
 * @param num_sectors
 *                  Number of sectors to write
 * @param buffer    Data buffer to write
 * @return Number of sectors written
 */
static int ata_write(cf_device_t * cf, unsigned long lba_start,
		     unsigned long num_sectors, const char *buffer)
{
	int sectors_written = 0;

	// octeon_led_set(1, 31);
	while (sectors_written < num_sectors) {
		int count;
		int sectors_to_write = num_sectors;

		if (sectors_to_write > 256)
			sectors_to_write = 256;

		if (ata_command
		    (cf, sectors_to_write & 0xff, lba_start, WIN_WRITE))
			goto done;
		lba_start += sectors_to_write;

		while (sectors_to_write--) {
			/* Wait for write command to be ready for data (BSY
			   clear) */
			if (ata_wait_idle(cf))
				goto done;
			if (ata_wait_drq_ready(cf))
				goto done;

			if (cf->is16bit) {
				const uint16_t *ptr = (const uint16_t *) buffer;
				for (count = 0; count < cf->sector_size;
				     count += 2) {
					writew(*ptr++, cf->base_ptr);
					/* Every 16 writes do a read so the
					   bootbus FIFO doesn't fill up */
					if (count && ((count & 0x1f) == 0))
						__raw_readw(cf->base_ptr + 6);
				}
				buffer += cf->sector_size;
			} else {
				for (count = 0; count < cf->sector_size;
				     count++) {
					writeb(*buffer++, cf->base_ptr);
					/* Every 16 writes do a read so the
					   bootbus FIFO doesn't fill up */
					if (count && ((count & 0xf) == 0))
						__raw_readb(cf->base_ptr + 7);
				}
			}
			sectors_written++;
		}
	}
      done:
	// octeon_led_clear(1, 31);

	return sectors_written;
}


/**
 * Identify a compact flash disk
 *
 * @param cf     Device to check and update
 * @return Zero on success. Failure will result in a device of zero
 *         size and a -1 return code.
 */
static int ebt3000cf_identify(cf_device_t * cf)
{
	struct hd_driveid drive_info;
	int result;

	memset(&drive_info, 0, sizeof(drive_info));

	result = ata_identify(cf, &drive_info);
	if (result == 0) {
		/* Sandisk 1G reports the wrong sector size */
		drive_info.sector_bytes = 512;
		printk("%s: %s Serial %s (%u sectors, %u bytes/sector)\n",
		       (cf->gd) ? cf->gd->disk_name : DEVICE_NAME,
		       drive_info.model, drive_info.serial_no,
		       drive_info.lba_capacity, (int) drive_info.sector_bytes);
		cf->num_sectors = drive_info.lba_capacity;
		cf->sector_size = drive_info.sector_bytes;
		cf->geo.cylinders = drive_info.cyls;
		cf->geo.heads = drive_info.heads;
		cf->geo.sectors = drive_info.sectors;
		cf->geo.start = 0;
	} else {
		cf->num_sectors = 0;
		cf->sector_size = KERNEL_SECTOR_SIZE;
	}

	return result;
}


/**
 * Handle an I/O request.
 *
 * @param cf         Device to access
 * @param lba_sector Starting sector
 * @param num_sectors
 *                   Number of sectors to transfer
 * @param buffer     Data buffer
 * @param write      Is the a write. Default to a read
 */
static int ebt3000_cf_transfer(cf_device_t * cf, unsigned long lba_sector,
			       unsigned long num_sectors, char *buffer,
			       int write)
{
	if ((lba_sector + num_sectors) > cf->num_sectors) {
		printk("%s: Attempt to access beyond end of device (%ld > %ld)\n", cf->gd->disk_name, lba_sector + num_sectors - 1, cf->num_sectors - 1);
		num_sectors = cf->num_sectors - lba_sector;
		if (num_sectors <= 0)
			return 0;
	}

	if (write)
		return ata_write(cf, lba_sector, num_sectors, buffer);
	else
		return ata_read(cf, lba_sector, num_sectors, buffer);
}


/**
 * Handle queued IO requests
 *
 * @param q      queue of requests
 */
static void ebt3000_cf_request(request_queue_t * q)
{
	/* For some unknown reason, sometimes the kernel calls us with
	   interrupts disabled. Since the CF is very slow, we just use the
	   kernel call to wakeup a thread. This way we never block for long
	   periods of time */
	struct request *req = elv_next_request(q);
	if (req) {
		cf_device_t *cf = req->rq_disk->private_data;
		complete(&cf->comp);
	}
}


/**
 * Ioctl.
 *
 * @param inode
 * @param filp
 * @param cmd
 * @param arg
 * @return
 */
int ebt3000_cf_ioctl(struct inode *inode, struct file *filp,
		     unsigned int cmd, unsigned long arg)
{
	struct block_device *bdev = inode->i_bdev;
	struct gendisk *disk = bdev->bd_disk;
	cf_device_t *cf = disk->private_data;
	struct hd_geometry geo;
	switch (cmd) {
	case HDIO_GETGEO:
		if (!arg)
			return -EINVAL;
		memcpy(&geo, &cf->geo, sizeof(geo));
		geo.start = get_start_sect(bdev);
		if (copy_to_user
		    ((struct hd_geometry __user *) arg, &geo, sizeof(geo)))
			return -EFAULT;
		return 0;
	}
	return -ENOTTY;		/* unknown command */
}


/**
 * Kernel thread that does the actual IO operations
 *
 * @param cf_obj The compact flash device
 * @return Never returns
 */
int ebt3000_cf_work(void *cf_obj)
{
	cf_device_t *cf = cf_obj;
	struct request *req;
	unsigned long flags;

	/* Give ourself a nice name and become a daemon */
	daemonize("octeon_%s", cf->gd->disk_name);


	/* Loop forever waiting for IO requests */
	while (1) {
		/* Wait for the queue request handler to signal us there are
		   requests available */
		wait_for_completion(&cf->comp);

		/* We need the queue lock */
		spin_lock_irqsave(&cf->lock, flags);

		/* Loop through all the pending requests */
		while ((req = elv_next_request(cf->queue)) != NULL) {
			if (!blk_fs_request(req)) {
				printk("%s: Skip non-CMD request\n",
				       req->rq_disk->disk_name);
				end_request(req, 0);
			} else {
				int count;
				/* Give away the lock while we're doing the
				   slow IOs */
				spin_unlock_irqrestore(&cf->lock, flags);
				count = ebt3000_cf_transfer(cf, req->sector,
							    req->
							    current_nr_sectors,
							    req->buffer,
							    rq_data_dir(req));
				/* We need the lock again to signal completion */
				spin_lock_irqsave(&cf->lock, flags);
				if (count == req->current_nr_sectors)
					end_request(req, 1);
				else
					end_request(req, -EIO);
			}
		}
		spin_unlock_irqrestore(&cf->lock, flags);
	}
	return 0;
}



/*
 * The device operations structure.
 */
static struct block_device_operations ebt3000_cf_ops = {
	.owner = THIS_MODULE,
	.ioctl = ebt3000_cf_ioctl
};


/**
 * Initialization
 *
 * @return
 */
static int __init ebt3000_cf_init(void)
{
	extern cvmx_bootinfo_t *octeon_bootinfo;
	cf_device_t *cf = &STATIC_DEVICE;
	int major_num;
	int region;

	printk(KERN_NOTICE DEVICE_NAME
	       ": Octeon bootbus compact flash driver version %s\n", VERSION);

	memset(cf, 0, sizeof(*cf));

#if 0
	/* Force driver to use true IDE compact flash for testing. */
	octeon_bootinfo->compact_flash_common_base_addr = 0x1d040000;
#endif

	if (octeon_bootinfo->major_version == 1
	    && octeon_bootinfo->minor_version >= 1) {
		if (octeon_bootinfo->compact_flash_common_base_addr)
			cf->base_ptr =
				cvmx_phys_to_ptr(octeon_bootinfo->
						 compact_flash_common_base_addr);
		else {
			printk(KERN_NOTICE DEVICE_NAME
			       ": Compact flash interface not present.\n");
			goto out;
		}
	} else
		cf->base_ptr = cvmx_phys_to_ptr(0x1d000800);


	/* Determine from base address is in true IDE mode or not */
	if (!(octeon_bootinfo->compact_flash_common_base_addr & 0xffff))
		cf->is_true_ide = 1;

	spin_lock_init(&cf->lock);
	init_completion(&cf->comp);

	/* Get a request queue. */
	cf->queue = blk_init_queue(ebt3000_cf_request, &cf->lock);
	if (cf->queue == NULL) {
		printk(DEVICE_NAME
		       ": unable to allocate block request queue\n");
		goto out;
	}
	blk_queue_hardsect_size(cf->queue, KERNEL_SECTOR_SIZE);

	/* Get registered. */
	major_num = register_blkdev(0, DEVICE_NAME);
	if (major_num <= 0) {
		printk(DEVICE_NAME ": unable to get major number\n");
		goto out;
	}

	/* And the gendisk structure. */
	cf->gd = alloc_disk(64);
	if (cf->gd == NULL) {
		printk(DEVICE_NAME ": unable to allocate disk\n");
		goto out_unregister;
	}

	/* Find the bootbus region for the CF to determine 16 or 8 bit */
	for (region = 0; region < 8; region++) {
		cvmx_mio_boot_reg_cfgx_t cfg;
		cfg.u64 = cvmx_read_csr(CVMX_MIO_BOOT_REG_CFGX(region));
		if (cfg.s.base ==
		    octeon_bootinfo->compact_flash_common_base_addr >> 16) {
			cf->is16bit = cfg.s.width;
			printk(KERN_NOTICE DEVICE_NAME
			       ": Compact flash found in bootbus region %d (%d bit%s).\n",
			       region, (cf->is16bit) ? 16 : 8,
			       (cf->is_true_ide) ? ", ide" : "");
			break;
		}
	}

	cf->gd->major = major_num;
	cf->gd->first_minor = 0;
	cf->gd->fops = &ebt3000_cf_ops;
	cf->gd->private_data = cf;
	cf->gd->queue = cf->queue;
	strcpy(cf->gd->disk_name, DEVICE_NAME "a");

	/* Set a size to make sure the kernel trys to find partitions. The real
	   size will be set when the thread starts processing */

	/* Identify the compact flash. We need its size */
	ebt3000cf_identify(cf);
	set_capacity(cf->gd,
		     cf->num_sectors * (cf->sector_size / KERNEL_SECTOR_SIZE));

	/* Create a kernel thread for doing the real IO operations */
	kernel_thread(ebt3000_cf_work, cf, 0);

	add_disk(cf->gd);

	return 0;

      out_unregister:
	unregister_blkdev(major_num, DEVICE_NAME);
      out:
	return -ENOMEM;
}

late_initcall(ebt3000_cf_init);
