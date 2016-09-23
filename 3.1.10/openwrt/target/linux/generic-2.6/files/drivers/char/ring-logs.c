/*
 *      neufbox_ring_log_array.c
 *
 *      Copyright 2006 Miguel GAIO <miguel.gaio@efixo.com>
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

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/platform_device.h>
#include <linux/ring_logs.h>
#include <linux/kernel.h>	/* printk(), min() */
#include <linux/slab.h>		/* kmalloc() */
#include <linux/fs.h>		/* everything... */
#include <linux/errno.h>	/* error codes */
#include <linux/types.h>	/* size_t */
#include <linux/fcntl.h>
#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/poll.h>
#include <linux/time.h>
#include <linux/mutex.h>
#include <asm/uaccess.h>
#include <asm/errno.h>

#define DRV_NAME        "ring-logs:"
#define DRV_VERSION     "2.00"

#define RING_LOGS 229

/** from struct ring_log
 * \note struct ring_log use mutex
 * read process is NOT destructive process
 * write success if buffer is full
 */
struct ring_log {
	struct device *dev;	/* Parent device */
	struct cdev cdev;	/* char device structure */
	u8 *buffer;		/* the buffer holding the data */
	size_t size;		/* the size of the allocated buffer */
	loff_t in;		/* data is added at offset (in % size) */
	loff_t out;		/* data is extracted from off. (out % size) */
	struct mutex lock;	/* lock */
};

static struct ring_log *ring_log_array;

static inline size_t __ring_log_len(struct ring_log *ring)
{
	return (size_t) (ring->in - ring->out);
}

static size_t __ring_log_get(struct ring_log *ring,
			      char __user * buf, size_t len, loff_t pos)
{
	size_t l;
	loff_t cur = (pos & (ring->size - 1));

	/* max len: current unread size */
	len = min(len, __ring_log_len(ring) - (size_t) (pos - ring->out));
	l = min(len, ring->size - (size_t) cur);

	/* first get the data from fifo->out until the end of the buffer */
	copy_to_user(buf, ring->buffer + cur, l);
	/* then get the rest (if any) from the beginning of the buffer */
	copy_to_user(buf + l, ring->buffer, len - l);

	return len;
}

static size_t __ring_log_put(struct ring_log *ring,
			      const char __user * buf, size_t len)
{
	size_t l;
	loff_t cur = (ring->in & (ring->size - 1));

	/* max len: buffer size */
	len = min(len, ring->size);
	l = min(len, ring->size - (size_t) cur);

	/* first put the data starting from fifo->in to buffer end */
	copy_from_user(ring->buffer + cur, buf, l);
	/* then put the rest (if any) at the beginning of the buffer */
	copy_from_user(ring->buffer, buf + l, len - l);

	ring->in += len;

	if (__ring_log_len(ring) > ring->size)
		ring->out = ring->in - ring->size;

	return len;
}

static inline size_t ring_log_len(struct ring_log *ring)
{
	size_t ret;

	mutex_lock(&ring->lock);
	ret = __ring_log_len(ring);
	mutex_unlock(&ring->lock);

	return ret;
}

static int ring_log_open(struct inode *inode, struct file *f)
{
	struct ring_log *ring;	/* ringice information */

	ring = container_of(inode->i_cdev, struct ring_log, cdev);

	f->private_data = ring;	/* for other methods */

	mutex_lock(&ring->lock);
	if (f->f_flags & O_TRUNC)
		ring->in = ring->out = 0;
	f->f_pos = ring->out;
	mutex_unlock(&ring->lock);

	return 0;		/* success */
}

static int ring_log_array_release(struct inode *inode, struct file *f)
{
	return 0;
}

static ssize_t ring_log_read(struct file *f, char __user * buf,
			      size_t count, loff_t * f_pos)
{
	struct ring_log *ring = f->private_data;
	size_t ret;

	mutex_lock(&ring->lock);
	ret = __ring_log_get(ring, buf, count, *f_pos);
	mutex_unlock(&ring->lock);

	*f_pos += ret;

	return ret;
}

static ssize_t ring_log_write(struct file *f, const char __user * buf,
			       size_t count, loff_t * f_pos)
{
	struct inode *inode = f->f_dentry->d_inode;
	struct ring_log *ring = f->private_data;
	size_t ret;

	mutex_lock(&ring->lock);
	ret = __ring_log_put(ring, buf, count);
	i_size_write(inode, ring->in);
	mutex_unlock(&ring->lock);

	*f_pos += ret;

	return ret;
}

loff_t ring_log_llseek(struct file * f, loff_t offset, int origin)
{
	struct ring_log *ring = f->private_data;
	long long retval;

	switch (origin) {
	case 2:
		offset += i_size_read(f->f_path.dentry->d_inode);
		break;
	case 1:
		offset += f->f_pos;
		break;
	case 0:
		offset += ring->out;
		break;
	}
	retval = -EINVAL;
	if (offset >= 0) {
		if (offset != f->f_pos) {
			f->f_pos = offset;
			f->f_version = 0;
		}
		retval = offset;
	}
	return retval;
}

struct file_operations ring_log_array_fops = {
	.owner		= THIS_MODULE,
	.open		= ring_log_open,
	.release	= ring_log_array_release,
	.llseek		= ring_log_llseek,
	.read		= ring_log_read,
	.write		= ring_log_write,
};

static int ring_log_setup_cdev(struct ring_log *ring, int index,
				struct ring_log_info *info)
{
	struct device *dev = ring->dev;
	dev_t devno;
	int err;

	ring->size = info->size;
	ring->buffer = kmalloc(ring->size, GFP_KERNEL);
	if (!ring->buffer) {
		dev_err(dev, "out of memory\n");
		return -ENOMEM;
	}
	ring->in = ring->out = 0u;
	mutex_init(&ring->lock);

	cdev_init(&ring->cdev, &ring_log_array_fops);
	ring->cdev.owner = THIS_MODULE;
	ring->cdev.ops = &ring_log_array_fops;
	devno = MKDEV(RING_LOGS, index);
	err = cdev_add(&ring->cdev, devno, 1);
	if (err) {
		dev_err(dev, "cdev_add failed err=%d\n", err);
		return err;
	}

	dev_info(dev, "%s (%uk)\n", info->name, info->size >> 10);

	return 0;
}

static int __init ring_logs_probe(struct platform_device *pdev)
{
	struct ring_log_platform_data *pdata = pdev->dev.platform_data;
	struct device *dev = &pdev->dev;
	struct ring_log *ring;
	dev_t devno;
	int i, err = 0;

	if (!pdata) {
		dev_err(dev, "invalid data\n");
		return -EINVAL;
	}

	ring_log_array =
	    kzalloc(sizeof(struct ring_log) * pdata->num_ring_logs,
		    GFP_KERNEL);
	if (!ring_log_array) {
		dev_err(dev, "out of memory\n");
		return -ENOMEM;
	}

	devno = MKDEV(RING_LOGS, 0);
	if ((err =
	     register_chrdev_region(devno, pdata->num_ring_logs,
				    "ring_logs")) < 0) {
		dev_err(dev, "register char devive failed err=%d\n",
			err);
		goto out_free;
	}

	for (i = 0; i < pdata->num_ring_logs; i++) {
		ring = &ring_log_array[i];
		ring->dev = dev;
		ring_log_setup_cdev(ring, i, &pdata->ring_logs[i]);
	}

	return 0;

 out_free:
	kfree(ring_log_array);
	return err;
}

static int __exit ring_logs_remove(struct platform_device *pdev)
{
	struct ring_log_platform_data *pdata = pdev->dev.platform_data;
	struct ring_log *ring;
	dev_t devno = MKDEV(RING_LOGS, 0);
	int i;

	/* Get rid of our char dev entries */
	if (ring_log_array) {
		for (i = 0; i < pdata->num_ring_logs; i++) {
			ring = &ring_log_array[i];
			kfree(ring->buffer);
			cdev_del(&ring->cdev);
		}
		kfree(ring_log_array);
	}

	/* cleanup_module is never called if registering failed */
	unregister_chrdev_region(devno, pdata->num_ring_logs);
	return 0;
}

static struct platform_driver ring_logs_driver = {
	.remove = __exit_p(ring_logs_remove),
	.driver = {
		   .name = "ring-logs",
		   .owner = THIS_MODULE,
		   },
};

static int __init ring_logs_init(void)
{
	return platform_driver_probe(&ring_logs_driver, ring_logs_probe);
}

static void __exit ring_logs_exit(void)
{
	platform_driver_unregister(&ring_logs_driver);
}

module_init(ring_logs_init);
module_exit(ring_logs_exit);

MODULE_AUTHOR("Miguel GAIO");
MODULE_DESCRIPTION("Ring Logs");
MODULE_VERSION(DRV_VERSION);
MODULE_LICENSE("GPL");
