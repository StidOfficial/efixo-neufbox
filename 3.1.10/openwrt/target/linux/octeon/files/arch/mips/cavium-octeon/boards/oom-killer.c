
#include <linux/module.h>

static int __init panic_init(void)
{
	void *p;
	u64 x = 0;

	printk("oom killer vs panic!\n");

	while (1) {
		if (!(x % 4096)) {
			printk("panic %lu\n", x);
		}
		p = kmalloc(64 << 10, GFP_KERNEL);
		memset(p, 'c', 64 << 10);
	}

	printk("now it's time for panic!\n");
	panic("die....");

	return 0;
}

module_init(panic_init);
