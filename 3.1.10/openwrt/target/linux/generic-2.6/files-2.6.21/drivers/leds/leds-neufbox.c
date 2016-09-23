/*!
 * \file leds.c
 *
 * \brief Implement neufbox leds
 *
 * \author Copyright 2006 Miguel GAIO <miguel.gaio@efixo.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/leds.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/gpio.h>

#include <asm/bitops.h>
#include <asm/atomic.h>

#include <neufbox/leds.h>

#define LEDS_MINOR 132		/* LED device driver */

struct neufbox_led_data {
	struct led_classdev cdev;
	unsigned gpio;
	u8 active_low;
	atomic_t command;
	enum led_state state;
};

struct leds_device {
	struct timer_list timer; /** leds timer structure */
	unsigned long counter;	/** leds timer counter */
	atomic_t mode; /** leds device mode */
	void (*fn_leds_mode_process) (struct leds_device *);	/* callback for leds management */
	int num_leds;
	struct neufbox_led_data leds_data[1];
};


extern void gen_74x164_sync(void);


static struct leds_device *leds_dev;


static inline void led_off(struct neufbox_led_data *led)
{
	gpio_set_value(led->gpio, led->active_low);
	led->cdev.brightness = LED_OFF;
}

static inline void led_on(struct neufbox_led_data *led)
{
	gpio_set_value(led->gpio, !led->active_low);
	led->cdev.brightness = LED_FULL;
}

static inline int led_toggle(struct neufbox_led_data *led)
{
	int value = !gpio_get_value(led->gpio);

	gpio_set_value(led->gpio, value);
	led->cdev.brightness =
	    (led->cdev.brightness == LED_FULL) ? LED_OFF : LED_FULL;

	return led->active_low ? value : !value;
}

static void leds_process_disable(struct leds_device *dev)
{
	/* nothing TODO */
}

static void led_state_update(struct leds_device *dev,
			     struct neufbox_led_data *led, enum led_state state,
			     int *blink_sync)
{
	switch (state) {
	case led_state_unchanged:
		return;
	case led_state_on:
		led_on(led);
		break;

	case led_state_off:
		led_off(led);
		break;

	case led_state_toggle:
		led_toggle(led);
		break;

	case led_state_blinkonce:
		led_toggle(led);
		(void)atomic_cmpxchg(&led->command,
				     led_state_unchanged, led_state_toggle);
		break;

	case led_state_slowblinks:
		if (!(dev->counter % 8))
			led_toggle(led);
		(void)atomic_cmpxchg(&led->command,
				     led_state_unchanged, led_state_slowblinks);
		break;

	case led_state_blinks:
		if (*blink_sync < 0)
			*blink_sync = led_toggle(led);
		else if (*blink_sync)
			led_off(led);
		else
			led_on(led);
		(void)atomic_cmpxchg(&led->command,
				     led_state_unchanged, led_state_blinks);
		break;

	default:
		printk(KERN_ERR "leds: (%s) invalid state STATE=%d\n",
		       led->cdev.name, state);
		return;
	}

	led->state = state;
}

static void leds_process_control(struct leds_device *dev)
{
	struct neufbox_led_data *led;
	int num_leds = dev->num_leds;
	int blink_sync = -1;
	int i;

	for (i = 0; i < num_leds; i++) {
		enum led_state state;

		led = &dev->leds_data[i];
		state = atomic_read(&led->command);
		(void)atomic_cmpxchg(&led->command, state, led_state_unchanged);
		led_state_update(dev, led, state, &blink_sync);
	}

	gen_74x164_sync();
}

static void leds_process_k2000(struct leds_device *dev)
{
	int i;

	for (i = 0; i <= led_id_alarm; i++)
		led_off(&dev->leds_data[i]);

	i = dev->counter % 10;
	if (i > 5)
		i = 10 - i;
	led_on(&dev->leds_data[i]);

	gen_74x164_sync();

	dev->timer.expires = jiffies + (HZ);
}

static void leds_process_downloading(struct leds_device *dev)
{
	leds_process_k2000(dev);
	/* set led service to yellow */
	led_on(&dev->leds_data[led_id_red]);
	led_on(&dev->leds_data[led_id_green]);
	led_off(&dev->leds_data[led_id_blue]);
}

static void leds_process_burning(struct leds_device *dev)
{
	leds_process_k2000(dev);
	/* set led service to red */
	led_on(&dev->leds_data[led_id_red]);
	led_off(&dev->leds_data[led_id_green]);
	led_off(&dev->leds_data[led_id_blue]);
}

static void leds_process_panic(struct leds_device *dev)
{
	int num_leds = dev->num_leds;
	int i;

	if (dev->counter & 0x01)
		for (i = 0; i < num_leds; i++)
			led_on(&dev->leds_data[i]);
	else
		for (i = 0; i < num_leds; i++)
			led_off(&dev->leds_data[i]);

	gen_74x164_sync();
}

static void leds_process_demo(struct leds_device *dev)
{
	int i;

	for (i = 0; i <= led_id_alarm; i++)
		led_off(&dev->leds_data[i]);

	i = dev->counter % 3;

	switch (i) {
	case 0:
		led_on(&dev->leds_data[led_id_red]);
		led_off(&dev->leds_data[led_id_green]);
		led_off(&dev->leds_data[led_id_blue]);
		break;

	case 1:
		led_off(&dev->leds_data[led_id_red]);
		led_on(&dev->leds_data[led_id_green]);
		led_off(&dev->leds_data[led_id_blue]);
		break;

	case 2:
		led_off(&dev->leds_data[led_id_red]);
		led_off(&dev->leds_data[led_id_green]);
		led_on(&dev->leds_data[led_id_blue]);
		break;
	}

	led_on(&dev->leds_data[i]);
	led_on(&dev->leds_data[led_id_alarm - i]);

	gen_74x164_sync();
}

static void inline leds_timer_function(unsigned long data)
{
	struct leds_device *dev = (struct leds_device *)data;

	dev->timer.expires = jiffies + (HZ >> 3);
	(dev->fn_leds_mode_process) (dev);
	++dev->counter;
	add_timer(&dev->timer);
}

static int leds_set_mode(struct leds_device *dev, enum led_mode mode)
{
	struct neufbox_led_data *led;
	enum led_mode prev_mode = atomic_read(&dev->mode);
	int num_leds = dev->num_leds;
	int i;

	if (mode == prev_mode)
		return prev_mode;

	dev->counter = 0UL;

	switch (mode) {
	case led_mode_disable:
		dev->fn_leds_mode_process = leds_process_disable;
		break;

	case led_mode_control:
		dev->fn_leds_mode_process = leds_process_control;
		break;

	case led_mode_downloading:
		dev->fn_leds_mode_process = leds_process_downloading;
		break;

	case led_mode_burning:
		dev->fn_leds_mode_process = leds_process_burning;
		break;

	case led_mode_panic:
		dev->fn_leds_mode_process = leds_process_panic;
		break;

	case led_mode_demo:
		dev->fn_leds_mode_process = leds_process_demo;
		break;

	default:
		printk(KERN_ERR "leds: invalid mode %X\n", mode);
		return -1;
	}

	atomic_set(&dev->mode, mode);

	if (mode == led_mode_control) {
		for (i = 0; i < num_leds; i++) {
			led = &dev->leds_data[i];
			(void)atomic_cmpxchg(&led->command,
					     led_state_unchanged, led->state);
		}
	} else {
		for (i = 0; i < num_leds; i++)
			led_off(&dev->leds_data[i]);

		gen_74x164_sync();
	}

	return prev_mode;
}

void leds_config(u8 id, u8 state)
{
	struct leds_device *dev = leds_dev;
	struct neufbox_led_data *led;

	if (id >= led_id_last || state > led_state_blinks) {
		printk(KERN_WARNING
		       "%s: broken control [ID=%u] [STATE=%u]\n", "leds", id,
		       state);
		return ;
	}

	led = &dev->leds_data[id];
	(void)atomic_set(&led->command, state);
}

EXPORT_SYMBOL(leds_config);

static long leds_panic_blink(long time)
{
	struct leds_device *dev = leds_dev;
	int i;

	if (!dev)
		return 0;

	if (!(time % 256)) {
		int num_leds = dev->num_leds;
		static int on = 0;

		if ((on = !on))
			for (i = 0; i < num_leds; i++)
				led_on(&dev->leds_data[i]);
		else
			for (i = 0; i < num_leds; i++)
				led_off(&dev->leds_data[i]);

		gen_74x164_sync();
	}

	return 0;
}

static int misc_leds_open(struct inode *inode, struct file *file)
{
	struct leds_device *dev = leds_dev;

	file->private_data = dev;

	return nonseekable_open(inode, file);
}

static long misc_leds_compat_ioctl(struct file *file, unsigned int cmd,
				   unsigned long arg)
{
	struct leds_device *dev = file->private_data;
	struct leds_dev_ioctl_struct leds_ioctl;
	struct neufbox_led_data *led;
	enum led_mode mode;

	switch (cmd) {
	case LED_IOCTL_SET_MODE:
		if (copy_from_user
		    ((void *)&leds_ioctl, (void __user *)arg,
		     sizeof(leds_ioctl)) < 0) {
			return -EFAULT;
		}

		if ((mode = leds_set_mode(dev, leds_ioctl.mode)) < 0) {
			return -EINVAL;
		}

		leds_ioctl.mode = mode;
		__copy_to_user((void __user *)arg, (void *)&leds_ioctl,
			       sizeof(leds_ioctl));
		break;
	case LED_IOCTL_GET_MODE:
		leds_ioctl.mode = atomic_read(&dev->mode);
		if (copy_to_user
		    ((void __user *)arg, (void *)&leds_ioctl,
		     sizeof(leds_ioctl)) < 0) {
			return -EFAULT;
		}
		break;

	case LED_IOCTL_SET_LED:
		if (copy_from_user
		    ((void *)&leds_ioctl, (void __user *)arg,
		     sizeof(leds_ioctl)) < 0) {
			return -EFAULT;
		}
		leds_config(leds_ioctl.id, leds_ioctl.state);
		break;

	case LED_IOCTL_GET_LED:
		if (copy_from_user
		    ((void *)&leds_ioctl, (void __user *)arg,
		     sizeof(leds_ioctl)) < 0) {
			return -EFAULT;
		}

		if (leds_ioctl.id >= led_id_last)
			return -EINVAL;

		led = &dev->leds_data[leds_ioctl.id];
		/* in disable mode check for command state */
		if (atomic_read(&dev->mode) == led_mode_disable) {
			leds_ioctl.state = atomic_read(&led->command);
			if (leds_ioctl.state == led_state_unchanged)
				leds_ioctl.state = led->state;
		} else {
			leds_ioctl.state = led->state;
		}

		if (__copy_to_user
		    ((void __user *)arg, (void *)&leds_ioctl,
		     sizeof(leds_ioctl)) < 0) {
			return -EFAULT;
		}
		break;

	default:
		printk(KERN_WARNING "leds: invalid ioctl %d\n", cmd);
		return -ENOTTY;
	}

	return 0;
}

static int misc_leds_ioctl(struct inode *inode, struct file *file,
			   unsigned int cmd, unsigned long arg)
{
	return misc_leds_compat_ioctl(file, cmd, arg);
}

static struct file_operations misc_leds_fops = {
	.owner = THIS_MODULE,
	.llseek = no_llseek,
	.ioctl = misc_leds_ioctl,
	.compat_ioctl = misc_leds_compat_ioctl,
	.open = misc_leds_open,
};

static struct miscdevice leds_miscdev = {
	.minor = LEDS_MINOR,
	.name = "leds",
	.fops = &misc_leds_fops,
};

static void neufbox_led_set(struct led_classdev *led_cdev,
			    enum led_brightness value)
{
	struct neufbox_led_data *led =
	    container_of(led_cdev, struct neufbox_led_data, cdev);

	if (value == LED_OFF)
		(void)atomic_set(&led->command, led_state_off);
	else
		(void)atomic_set(&led->command, led_state_on);

}

static int __init neufbox_led_probe(struct platform_device *pdev)
{
	struct leds_device *dev;
	struct gpio_led_platform_data *pdata = pdev->dev.platform_data;
	struct gpio_led *cur_led;
	struct neufbox_led_data *leds_data, *led;
	int i, ret = 0;

	extern long (*panic_blink) (long time);

	if (!pdata)
		return -EBUSY;

	leds_dev = dev =
	    kzalloc(sizeof(struct leds_device) +
		    (sizeof(struct neufbox_led_data) * pdata->num_leds),
		    GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	/* setup hook panic */
	panic_blink = leds_panic_blink;

	dev->num_leds = pdata->num_leds;
	leds_data = dev->leds_data;
	for (i = 0; i < pdata->num_leds; i++) {
		int default_state;
		cur_led = &pdata->leds[i];
		led = &leds_data[i];

		led->cdev.name = cur_led->name;
		led->cdev.default_trigger = cur_led->default_trigger;
		led->gpio = cur_led->gpio;
		led->active_low = cur_led->active_low;
		led->cdev.brightness_set = neufbox_led_set;

		ret = gpio_request(led->gpio, led->cdev.name);
		if (ret < 0)
			goto err;

		if (cur_led->default_state == LEDS_GPIO_DEFSTATE_ON) {
			default_state = !led->active_low;
			led->cdev.brightness = LED_FULL;
			leds_config(i, led_state_on);
		} else {
			default_state = led->active_low;
			led->cdev.brightness = LED_OFF;
			leds_config(i, led_state_off);
		}

		gpio_direction_output(led->gpio, default_state);

		ret = led_classdev_register(&pdev->dev, &led->cdev);
		if (ret < 0) {
			gpio_free(led->gpio);
			goto err;
		}
	}

	platform_set_drvdata(pdev, leds_data);

	ret = misc_register(&leds_miscdev);
	if (ret < 0)
		goto err;

	leds_set_mode(dev, led_mode_control);

	/* setup timer */
	setup_timer(&dev->timer, leds_timer_function, (unsigned long)dev);
	/* start timer */
	mod_timer(&dev->timer, jiffies);

	return 0;

 err:
	if (i > 0) {
		for (i = i - 1; i >= 0; i--) {
			led_classdev_unregister(&leds_data[i].cdev);
			gpio_free(leds_data[i].gpio);
		}
	}

	kfree(leds_dev);

	return ret;
}

static int __exit neufbox_led_remove(struct platform_device *pdev)
{
	int i;
	struct gpio_led_platform_data *pdata = pdev->dev.platform_data;
	struct neufbox_led_data *leds_data;
	struct leds_device *dev = leds_dev;

	del_timer(&dev->timer);
	/* reset leds states */
	leds_set_mode(dev, led_mode_disable);
	misc_deregister(&leds_miscdev);
	/* free leds device structure */
	kfree(dev);

	leds_data = platform_get_drvdata(pdev);

	for (i = 0; i < pdata->num_leds; i++) {
		led_classdev_unregister(&leds_data[i].cdev);
		gpio_free(leds_data[i].gpio);
	}

	kfree(dev);

	return 0;
}

static struct platform_driver neufbox_led_driver = {
	.remove = __exit_p(neufbox_led_remove),
	.driver = {
		   .name = "leds-neufbox",
		   .owner = THIS_MODULE,
		   },
};

static int __init neufbox_led_init(void)
{
	return platform_driver_probe(&neufbox_led_driver, neufbox_led_probe);
}

static void __exit neufbox_led_exit(void)
{
	platform_driver_unregister(&neufbox_led_driver);
}

module_init(neufbox_led_init);
module_exit(neufbox_led_exit);

MODULE_ALIAS_MISCDEV(LEDS_MINOR);
MODULE_AUTHOR("Miguel GAIO");
MODULE_DESCRIPTION("NEUFBOX LED driver");
MODULE_LICENSE("GPL");
