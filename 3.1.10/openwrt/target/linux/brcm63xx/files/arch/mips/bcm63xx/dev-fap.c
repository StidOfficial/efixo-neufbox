
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/clk.h>
#include <linux/bootmem.h>

/*
#define FAP_CORE_SIZE 71376
#define FAP_INIT_SIZE 508
*/
#define FAP_CORE_SIZE 87168
#define FAP_INIT_SIZE 1024



void *fap_core;
void *fap_init;
EXPORT_SYMBOL(fap_core);
EXPORT_SYMBOL(fap_init);

void __init allocFapModBuffers(void)
{
	fap_core =
	    (void *)((FAP_CORE_SIZE > 0) ?
		     alloc_bootmem((unsigned long)FAP_CORE_SIZE) : NULL);
	fap_init =
	    (void *)((FAP_INIT_SIZE > 0) ?
		     alloc_bootmem((unsigned long)FAP_INIT_SIZE) : NULL);

	printk("Allocated FAP memory - CORE=0x%x SIZE=%d, INIT=0x%x SIZE=%d\n",
	       (unsigned int)fap_core, FAP_CORE_SIZE, (unsigned int)fap_init,
	       FAP_INIT_SIZE);
}

int __init bcm63xx_fap_register(void)
{
	struct clk *clk;

	/* enable USB host clock */
	clk = clk_get(NULL, "fap");
	if (IS_ERR(clk))
		return -ENODEV;

	clk_enable(clk);

	return 0;
}
