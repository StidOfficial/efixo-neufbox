/*
 *  Driver for buttons on GPIO lines not capable of generating interrupts
 *
 *  Copyright (C) 2007-2010 Gabor Juhos <juhosg@openwrt.org>
 *  Copyright (C) 2010 Nuno Goncalves <nunojpg@gmail.com>
 *
 *  This file was based on: /drivers/input/misc/cobalt_btns.c
 *	Copyright (C) 2007 Yoichi Yuasa <yoichi_yuasa@tripeaks.co.jp>
 *
 *  also was based on: /drivers/input/keyboard/gpio_keys.c
 *	Copyright 2005 Phil Blundell
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/version.h>

#include <linux/timer.h>

#include <linux/input.h>
#include <linux/input-polldev.h>
#include <linux/ioport.h>
#include <linux/platform_device.h>

#include <neufbox/events.h>

#define DRV_NAME	"neufbox-events"
#define DRV_VERSION	"0.1.0"
#define PFX		DRV_NAME ": "

struct input_dev *idev;

void event_enqueue(unsigned id)
{
	pr_debug(PFX " id:%u\n", id & 0xff);
	input_event(idev, EV_MSC, MSC_RAW, id);
	input_sync(idev);
}

EXPORT_SYMBOL(event_enqueue);

static int __devinit neufbox_events_probe(struct platform_device *pdev)
{
	int err, i;

	idev = input_allocate_device();
	if (!idev) {
		printk(KERN_ERR DRV_NAME "no memory for input device\n");
		return -ENOMEM;
	}

	idev->evbit[0] = BIT(EV_MSC);
	idev->name = pdev->name;
	idev->phys = "neufbox-events/input0";
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
	idev->dev.parent = &pdev->dev;
#endif

	idev->id.bustype = BUS_HOST;
	idev->id.vendor = 0x0022;
	idev->id.product = 0x0001;
	idev->id.version = 0x0100;

	for (i = 0; i < 256; ++i) {
		input_set_capability(idev, EV_MSC, i);
	}

	if ((err = input_register_device(idev)) < 0) {
		printk(KERN_ERR DRV_NAME "fail to register input device");
		return err;
	}

	return 0;
}

static int __devexit neufbox_events_remove(struct platform_device *pdev)
{
	input_unregister_device(idev);
	input_free_device(idev);

	return 0;
}

static struct platform_driver neufbox_events_driver = {
	.probe = neufbox_events_probe,
	.remove = __devexit_p(neufbox_events_remove),
	.driver = {
		   .name = DRV_NAME,
		   .owner = THIS_MODULE,
		   },
};

static int __init neufbox_events_init(void)
{
	printk(KERN_INFO DRV_NAME " driver version " DRV_VERSION "\n");
	return platform_driver_register(&neufbox_events_driver);
}

static void __exit neufbox_events_exit(void)
{
	platform_driver_unregister(&neufbox_events_driver);
}

module_init(neufbox_events_init);
module_exit(neufbox_events_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Miguel GAIO <miguel.gaio at efixo.com>");
MODULE_VERSION(DRV_VERSION);
