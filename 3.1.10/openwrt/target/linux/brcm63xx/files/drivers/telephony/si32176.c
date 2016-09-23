/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2010 Tanguy Bouzéloc <tanguy.bouzeloc@efixo.com>
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/gpio.h>
#include <linux/device.h>
#include <linux/platform_device.h>

#define DRV_VER "0.0.1"

struct si32176 {
	int gpio;
};

static int si32176_reset(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct si32176 *slic = platform_get_drvdata(pdev);
	int gpio = slic->gpio;
	int ret;

	ret = gpio_direction_input(gpio);
	if (ret) {
		dev_err(dev, "slic power down failed");
		return ret;
	}
	
	msleep(250);
	ret = gpio_direction_output(gpio, 1);
	if (ret) {
		dev_err(dev, "slic power up failed\n");
		return ret;
	}

	msleep(250);
	return 0;
}

static int __init si32176_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct si32176 *slic;
	int gpio;
	int ret = 0;

	gpio = platform_get_irq(pdev, 0);

	if (gpio < 0) {
		dev_err(dev, "no gpio for device\n");
		ret = -ENXIO;
		goto out;
	}

	ret = gpio_is_valid(gpio);
	if (!ret) {
		dev_err(dev, "invalid gpio %d\n", gpio);
		goto out;
	}

	ret = gpio_request(gpio, "slic");
	if (ret) {
		dev_err(dev, "failed to allocate gpio %d\n", gpio);
		goto out;
	}
	
	slic = kmalloc(sizeof(struct si32176), GFP_KERNEL);
	if (!slic) {
		ret = -ENOMEM;
		goto out_gpio;
	}

	platform_set_drvdata(pdev, slic);
	slic->gpio = gpio;

	ret = si32176_reset(pdev);
	if (ret)
		goto out_mem;

	dev_info(dev, "(gpio %d) v%s\n", gpio, DRV_VER);
	return 0;

out_mem:
	kfree(slic);
out_gpio:
	gpio_free(gpio);
out :
	return ret;
}

static int __exit si32176_remove(struct platform_device *pdev)
{
	struct si32176 *slic = platform_get_drvdata(pdev);
	gpio_free(slic->gpio);
	kfree(slic);
	return 0;
}

#ifdef CONFIG_PM
static int si32176_suspend(struct platform_device *pdev, pm_message_t mesg)
{
	return 0;
}

static int si32176_resume(struct platform_device *pdev)
{
	return 0;
}
#else
#define si32176_suspend NULL
#define si32176_resume  NULL
#endif /* CONFIG_PM */

static struct platform_driver si32176_driver = {
	.driver = {
		.name = "si32176",
		.owner = THIS_MODULE,
	},
	.probe = si32176_probe,
	.remove = si32176_remove,
	.suspend = si32176_suspend,
	.resume = si32176_resume,
};

static int __init si32176_init(void)
{
	return platform_driver_register(&si32176_driver);
}

static void __exit si32176_exit(void)
{
	platform_driver_unregister(&si32176_driver);
}

module_init(si32176_init);
module_exit(si32176_exit);

MODULE_ALIAS("platform:si32176");
MODULE_AUTHOR("Tanguy Bouzéloc <tanguy.bouzeloc@efixo.com");
MODULE_DESCRIPTION("Silabs Si32176 SLIC driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VER);
