
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/clk.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/spi/spi.h>
#include <linux/completion.h>
#include <linux/err.h>

#include <bcm63xx_dev_spi.h>
#include <bcm_map_part.h>

#define PFX 		KBUILD_MODNAME
#define DRV_VER		"0.1.2"

struct bcm63xx_hsspi {
	spinlock_t              lock;
	int			stopping;
        struct completion	done;

	void __iomem		*regs;
	int			irq;

	/* Platform data */
        u32			speed_hz;
	unsigned		fifo_size;

	/* Data buffers */
	struct list_head	queue;
	struct spi_transfer	*cur;

	/* data iomem */
	u8 __iomem		*tx_io;
	const u8 __iomem	*rx_io;

	struct clk		*clk;
	struct platform_device	*pdev;
};

static inline u32 bcm_hsspi_readl(struct bcm63xx_hsspi *bs,
				  unsigned int offset)
{
        return bcm_readl(bs->regs + offset);
}

static inline void bcm_hsspi_writel(struct bcm63xx_hsspi *bs,
				    u32 value, unsigned int offset)
{
        bcm_writel(value, bs->regs + offset);
}

static int bcm63xx_hsspi_setup_transfer(struct spi_device *spi,
					struct spi_transfer *t)
{
	int clk_cfg;
	int hz;
	int div;

	struct bcm63xx_hsspi *bs = spi_master_get_devdata(spi->master);

	hz = (t) ? t->speed_hz : spi->max_speed_hz;

	if (spi->chip_select > spi->master->num_chipselect) {
		dev_err(&spi->dev, "%s, unsupported slave %d\n",
			__func__, spi->chip_select);
		return -EINVAL;
	}

	/* Check clock setting */
	div = (bs->speed_hz / hz);
	clk_cfg = 2048 / div;
	if (2048 % clk_cfg)
		clk_cfg++;

	clk_cfg = 1 << HS_SPI_ACCUM_RST_ON_LOOP |
		0 << HS_SPI_SPI_CLK_2X_SEL |
		clk_cfg << HS_SPI_FREQ_CTRL_WORD;

	bcm_hsspi_writel(bs, clk_cfg, HSSPI_CLK_CFG);
	dev_dbg(&spi->dev, "Setting clock register to %d (hz %d, cmd %02x)\n",
		div, hz, clk_cfg);

	return 0;
}

static int bcm63xx_hsspi_setup(struct spi_device *spi)
{
	struct bcm63xx_hsspi *bs;

	bs = spi_master_get_devdata(spi->master);

	if (bs->stopping)
		return -ESHUTDOWN;

	if (!spi->bits_per_word)
		spi->bits_per_word = 8;

	/* there is nothing to setup */

	return 0;
}

static void bcm_hsspi_transfer(struct spi_device *spi, struct spi_message *m)
{
	struct bcm63xx_hsspi *bs = spi_master_get_devdata(spi->master);
	struct spi_transfer *t;
	struct spi_transfer *next = NULL;
	u32 mode_ctl;
	u32 cmd_ctl;
	int prependcnt = 0;
	int length;
	int op;
	u16 cmd;

	t = bs->cur;
	if (t)
		t = list_first_entry(&t->transfer_list, struct spi_transfer, transfer_list);
	else
		t = list_first_entry(&m->transfers, struct spi_transfer, transfer_list);

	bs->cur = t;

	if (t->rx_buf && t->tx_buf)
		op = HSSPI_OP_READ_WRITE;
	else if (t->rx_buf)
		op = HSSPI_OP_READ;
	else
		op = HSSPI_OP_WRITE;

	length = t->len;

	if (m->state == (void*)1) {
		/* this controller does not support keeping the chip select active for all transfers
		   non NULL state indicates that we need to combine the transfers */
		next = list_first_entry(&t->transfer_list, struct spi_transfer, transfer_list);
		prependcnt = length;
		length = next->len;
		op = HSSPI_OP_READ;
		bs->cur = next;
	} else if (m->state == (void*)2) {
		/* this controller does not support keeping the chip select active for all transfers
		   non NULL state indicates that we need to combine the transfers */
		next = list_first_entry(&t->transfer_list, struct spi_transfer, transfer_list);
		length += next->len;
		bs->cur = next;
	}

	bcm63xx_hsspi_setup_transfer(spi, t);

	bcm_hsspi_writel(bs, HSSPI_INTR_CLEAR_ALL, HSSPI_INT_STATUS);
	bcm_hsspi_writel(bs, HSSPI_IRQ_PING0_CMD_DONE, HSSPI_INT_MASK);
	if (HSSPI_OP_READ == op) {
		mode_ctl = prependcnt << HS_SPI_PREPENDBYTE_CNT |
			0 << HS_SPI_MODE_ONE_WIRE |
			0 << HS_SPI_MULTIDATA_WR_SIZE |
			0 << HS_SPI_MULTIDATA_RD_SIZE |
			2 << HS_SPI_MULTIDATA_WR_STRT |
			2 << HS_SPI_MULTIDATA_RD_STRT |
			0xff << HS_SPI_FILLBYTE;

		bcm_hsspi_writel(bs, mode_ctl, HSSPI_MODE_CTL);

		cmd = (HSSPI_OP_READ << HSSPI_OP_CODE) | length;
		memcpy_toio(bs->tx_io, &cmd, sizeof(cmd));
		if (next)
			memcpy_toio(bs->tx_io + sizeof(cmd), t->tx_buf, prependcnt);
	} else {
		mode_ctl = 0 << HS_SPI_PREPENDBYTE_CNT |
			0 << HS_SPI_MODE_ONE_WIRE |
			0 << HS_SPI_MULTIDATA_WR_SIZE |
			0 << HS_SPI_MULTIDATA_RD_SIZE |
			2 << HS_SPI_MULTIDATA_WR_STRT |
			2 << HS_SPI_MULTIDATA_RD_STRT |
			0xff << HS_SPI_FILLBYTE;

		bcm_hsspi_writel(bs, mode_ctl, HSSPI_MODE_CTL);

		cmd = (op << HSSPI_OP_CODE) | length;
		memcpy_toio(bs->tx_io, &cmd, sizeof(cmd));
		memcpy_toio(bs->tx_io + sizeof(cmd), t->tx_buf, t->len);
		if (next)
			memcpy_toio(bs->tx_io + sizeof(cmd) + t->len, next->tx_buf, next->len);
	}

	cmd_ctl = m->spi->chip_select << HS_SPI_SS_NUM |
		0 << HS_SPI_PROFILE_NUM |
		0 << HS_SPI_TRIGGER_NUM |
		HS_SPI_COMMAND_START_NOW << HS_SPI_COMMAND_VALUE;
	bcm_hsspi_writel(bs, cmd_ctl, HSSPI_CMD_CTL);

	m->actual_length += prependcnt + length;
}

static int bcm63xx_hsspi_transfer(struct spi_device *spi,
				  struct spi_message *m)
{
	struct bcm63xx_hsspi *bs = spi_master_get_devdata(spi->master);
	struct spi_transfer *t;
	struct spi_transfer *next;
	int n = 0;
	int cs_change = 0;

	if (unlikely(list_empty(&m->transfers)))
		return -EINVAL;

	if (bs->stopping)
		return -ESHUTDOWN;

	list_for_each_entry(t, &m->transfers, transfer_list) {
		/* check transfer parameters */
		if (!(t->tx_buf || t->rx_buf))
			return -EINVAL;

		/* check the clock setting - if it is 0 then set to max clock of the device */
		if (t->speed_hz == 0) {
			if (spi->max_speed_hz == 0)
				return -EINVAL;

			t->speed_hz = spi->max_speed_hz;
		}

		n++;
		cs_change |= t->cs_change;
		WARN_ON(t->len > bs->fifo_size);
	}

	/* this controller does not support keeping the chip select active between
	   transfers. If a message is detected with a write transfer followed by a 
	   read transfer and cs_change is set to 0 then the two transfers need to be
	   combined. The message state is used to indicate that the transfers 
	   need to be combined */
	m->state = NULL;
	if ((n == 2) && (!cs_change)) {
		t = list_first_entry(&m->transfers, struct spi_transfer, transfer_list);
		if (t->tx_buf && (!t->rx_buf)) {
			next = list_first_entry(&t->transfer_list, struct spi_transfer, transfer_list);
			if ((!next->tx_buf) && next->rx_buf)
				m->state = (void *)1;
			if (next->tx_buf && (!next->rx_buf))
				m->state = (void *)2;
		}
	}

	m->status = -EINPROGRESS;
	m->actual_length = 0;

	/* disable interrupts for the SPI controller
	   using spin_lock_irqsave would disable all interrupts */
	bcm_hsspi_writel(bs, 0, HSSPI_INT_MASK);
	spin_lock(&bs->lock);

	list_add_tail(&m->queue, &bs->queue);
	if (!bs->cur) {
		m = list_first_entry(&bs->queue, struct spi_message, queue);
		/* there will always be one transfer in a given message */
		bcm_hsspi_transfer(spi, m);
	}

	spin_unlock(&bs->lock);
	bcm_hsspi_writel(bs, HSSPI_IRQ_PING0_CMD_DONE, HSSPI_INT_MASK);

	return 0;
}

static irqreturn_t bcm63xx_hsspi_interrupt(int irq, void *dev_id)
{
	struct spi_master *master = (struct spi_master *)dev_id;
	struct bcm63xx_hsspi *bs = spi_master_get_devdata(master);
	struct spi_device *spi = to_spi_device(&bs->pdev->dev);
	struct spi_message *m;
	struct spi_transfer *t;
	int intr;

	/* Read interupts and clear them immediately */
	intr = bcm_hsspi_readl(bs, HSSPI_MASK_INT_ST);
	bcm_hsspi_writel(bs, HSSPI_INTR_CLEAR_ALL, HSSPI_INT_STATUS);
	bcm_hsspi_writel(bs, 0, HSSPI_INT_MASK);

	/* A tansfer completed */
	if (intr) {
		spin_lock(&bs->lock);
		if (!bs->cur) {
			spin_unlock(&bs->lock);
			return IRQ_HANDLED;
		}

		t = bs->cur;

		/* Read out all the data */
		if (t->rx_buf)
			memcpy_fromio(t->rx_buf, bs->rx_io, t->len);

		/* t can specify a delay before the next transfer is started
		   this delay would be processed here normally. However, delay in the 
		   interrupt handler is bad so it is ignored. It is used for polling
		   mode */

		/* check to see if this is the last transfer in the message */
		m = list_first_entry(&bs->queue, struct spi_message, queue);
		if (m->transfers.prev == &t->transfer_list) {
			list_del(&m->queue);
			m->status = 0;

			spin_unlock(&bs->lock);
			m->complete(m->context);
			spin_lock(&bs->lock);

			bs->cur = NULL;

			/* continue if needed */
			if ((!list_empty(&bs->queue)) && (!bs->stopping)) {
				m = list_first_entry(&bs->queue, struct spi_message, queue);
				/* there will always be one transfer in a given message */
				bcm_hsspi_transfer(spi, m);
			}
		} else {
			/* Submit the next transfer */
			bcm_hsspi_transfer(spi, m);
		}

		spin_unlock(&bs->lock);
	}

	return IRQ_HANDLED;
}


static int __init bcm63xx_hsspi_probe(struct platform_device *pdev)
{
	struct resource *r;
	struct device *dev = &pdev->dev;
	struct bcm63xx_spi_pdata *pdata = pdev->dev.platform_data;
	int irq;
	struct spi_master *master;
	struct clk *clk;
	struct bcm63xx_hsspi *bs;
	int ret;

	r = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!r) {
		dev_err(dev, "no iomem\n");
		ret = -ENXIO;
		goto out;
	}

	irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		dev_err(dev, "no irq\n");
		ret = -ENXIO;
		goto out;
	}

	clk = clk_get(dev, "hsspi");
	if (IS_ERR(clk)) {
		dev_err(dev, "no clock for device\n");
		ret = -ENODEV;
		goto out;
	}

	master = spi_alloc_master(dev, sizeof(*bs));
	if (!master) {
		dev_err(dev, "out of memory\n");
		ret = -ENOMEM;
		goto out_free;
	}

	bs = spi_master_get_devdata(master);
	init_completion(&bs->done);

	platform_set_drvdata(pdev, master);
	bs->pdev = pdev;

	if (!request_mem_region(r->start, r->end - r->start, PFX)) {
		dev_err(dev, "iomem request failed\n");
		ret = -ENXIO;
		goto out_put_master;
	}

	bs->regs = ioremap_nocache(r->start, r->end - r->start);
	if (!bs->regs) {
		dev_err(dev, "unable to ioremap regs\n");
		ret = -ENOMEM;
		goto out_put_master;
	}
	bs->irq = irq;
	bs->clk = clk;
	bs->fifo_size = pdata->fifo_size;

	ret = request_irq(irq, bcm63xx_hsspi_interrupt, 0, pdev->name, master);
	if (ret) {
		dev_err(dev, "unable to request irq\n");
		goto out_unmap;
	}

	master->bus_num = pdata->bus_num;
	master->num_chipselect = pdata->num_chipselect;
	master->setup = bcm63xx_hsspi_setup;
	master->transfer = bcm63xx_hsspi_transfer;
	bs->speed_hz = pdata->speed_hz;
	bs->stopping = 0;
	bs->tx_io = (u8 *)(bs->regs + HSSPI_FIFO);
	bs->rx_io = (const u8 *)(bs->regs + HSSPI_FIFO);
	INIT_LIST_HEAD(&bs->queue);
	bs->cur = NULL;
	spin_lock_init(&bs->lock);

	/* Initialize hardware */
	clk_enable(bs->clk);
	bcm_hsspi_writel(bs, 0, HSSPI_INT_MASK);

	/* register and we are done */
	ret = spi_register_master(master);
	if (ret) {
		dev_err(dev, "spi register failed\n");
		goto out_reset_hw;
	}

	dev_info(dev, "at 0x%08x (irq %d, FIFOs size %d) v%s\n",
		 r->start, irq, bs->fifo_size, DRV_VER);

	return 0;

out_reset_hw:
	clk_disable(clk);
	free_irq(irq, master);
out_unmap:
	iounmap(bs->regs);
out_put_master:
	spi_master_put(master);
out_free:
	clk_put(clk);
out:
	return ret;
}

static int __exit bcm63xx_hsspi_remove(struct platform_device *pdev)
{
	struct spi_master	*master = platform_get_drvdata(pdev);
	struct bcm63xx_hsspi	*bs = spi_master_get_devdata(master);
	struct resource		*r = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	struct spi_message	*m;

	/* reset spi block */
	bcm_hsspi_writel(bs, 0, HSSPI_INT_MASK);
	spin_lock(&bs->lock);
	bs->stopping = 1;

	/* HW shutdown */
	clk_disable(bs->clk);
	clk_put(bs->clk);

	spin_unlock(&bs->lock);

	/* Terminate remaining queued transfers */
	list_for_each_entry(m, &bs->queue, queue) {
		m->status = -ESHUTDOWN;
		m->complete(m->context);
	}

	free_irq(bs->irq, master);
	iounmap(bs->regs);
	release_mem_region(r->start, r->end - r->start);
	platform_set_drvdata(pdev, 0);
	spi_unregister_master(master);

	return 0;
}

#ifdef CONFIG_PM
static int bcm63xx_hsspi_suspend(struct platform_device *pdev, pm_message_t mesg)
{
	struct spi_master	*master = platform_get_drvdata(pdev);
	struct bcm63xx_hsspi	*bs = spi_master_get_devdata(master);

        clk_disable(bs->clk);

	return 0;
}

static int bcm63xx_hsspi_resume(struct platform_device *pdev)
{
	struct spi_master	*master = platform_get_drvdata(pdev);
	struct bcm63xx_hsspi	*bs = spi_master_get_devdata(master);

	clk_enable(bs->clk);

	return 0;
}
#else
#define bcm63xx_hsspi_suspend	NULL
#define bcm63xx_hsspi_resume	NULL
#endif

static struct platform_driver bcm63xx_hsspi_driver = {
	.driver = {
		.name	= "bcm63xx-hsspi",
		.owner	= THIS_MODULE,
	},
	.probe		= bcm63xx_hsspi_probe,
	.remove		= bcm63xx_hsspi_remove,
	.suspend	= bcm63xx_hsspi_suspend,
	.resume		= bcm63xx_hsspi_resume,
};


static int __init bcm63xx_hsspi_init(void)
{
	return platform_driver_register(&bcm63xx_hsspi_driver);
}

static void __exit bcm63xx_hsspi_exit(void)
{
	platform_driver_unregister(&bcm63xx_hsspi_driver);
}

module_init(bcm63xx_hsspi_init);
module_exit(bcm63xx_hsspi_exit);

MODULE_ALIAS("platform:bcm63xx_hsspi");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VER);
