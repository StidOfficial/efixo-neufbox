#include <linux/autoconf.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/clk.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/spi/spi.h>

#include <bcm_map_part.h>
#include <bcm_intr.h>
#include <bcm63xx_regs.h>
#include <bcmSpiRes.h>

struct bcmspi
{
    spinlock_t               lock;
    char *                   devName;
    int                      irq;
    unsigned                 bus_num;
    unsigned                 num_chipselect;  
    u8                       stopping;
    struct list_head         queue;
    struct platform_device  *pdev;
    struct spi_transfer     *curTrans;
    struct clk              *clk;
    void __iomem            *regs;
};

static struct bcmspi BcmLegSpi = { SPIN_LOCK_UNLOCKED,
	"bcmLegSpiDev",
};

/* following are the frequency tables for the SPI controllers 
   they are ordered by frequency in descending order with column 
   2 represetning the register value */
#define LEG_SPI_FREQ_TABLE_SIZE  7
int legSpiClockFreq[LEG_SPI_FREQ_TABLE_SIZE][2] = {
	{20000000, 0},
	{12500000, 6},
	{6250000, 5},
	{3125000, 4},
	{1563000, 3},
	{781000, 2},
	{391000, 1}
};

/* the BCM legacy controller supports up to 8 devices */
static struct spi_board_info bcmLegSpiDevInfo[8] = {
	{
	 .modalias = "bcm_LegSpiDev0",
	 .chip_select = 0,
	 .max_speed_hz = 781000,
	 .bus_num = LEG_SPI_BUS_NUM,
	 .mode = SPI_MODE_3,
	 },
	{
	 .modalias = "bcm_LegSpiDev1",
	 .chip_select = 1,
	 .max_speed_hz = 781000,
	 .bus_num = LEG_SPI_BUS_NUM,
	 .mode = SPI_MODE_3,
	 },
	{
	 .modalias = "bcm_LegSpiDev2",
	 .chip_select = 2,
	 .max_speed_hz = 781000,
	 .bus_num = LEG_SPI_BUS_NUM,
	 .mode = SPI_MODE_3,
	 },
	{
	 .modalias = "bcm_LegSpiDev3",
	 .chip_select = 3,
	 .max_speed_hz = 781000,
	 .bus_num = LEG_SPI_BUS_NUM,
	 .mode = SPI_MODE_3,
	 },
	{
	 .modalias = "bcm_LegSpiDev4",
	 .chip_select = 4,
	 .max_speed_hz = 781000,
	 .bus_num = LEG_SPI_BUS_NUM,
	 .mode = SPI_MODE_3,
	 },
	{
	 .modalias = "bcm_LegSpiDev5",
	 .chip_select = 5,
	 .max_speed_hz = 781000,
	 .bus_num = LEG_SPI_BUS_NUM,
	 .mode = SPI_MODE_3,
	 },
	{
	 .modalias = "bcm_LegSpiDev6",
	 .chip_select = 6,
	 .max_speed_hz = 781000,
	 .bus_num = LEG_SPI_BUS_NUM,
	 .mode = SPI_MODE_3,
	 },
	{
	 .modalias = "bcm_LegSpiDev7",
	 .chip_select = 7,
	 .max_speed_hz = 781000,
	 .bus_num = LEG_SPI_BUS_NUM,
	 .mode = SPI_MODE_3,
	 },
};

static struct spi_driver bcmLegSpiDevDrv[8] = {
	{
	 .driver = {
		    .name = "bcm_LegSpiDev0",
		    .bus = &spi_bus_type,
		    .owner = THIS_MODULE,
		    },
	 },
	{
	 .driver = {
		    .name = "bcm_LegSpiDev1",
		    .bus = &spi_bus_type,
		    .owner = THIS_MODULE,
		    },
	 },
	{
	 .driver = {
		    .name = "bcm_LegSpiDev2",
		    .bus = &spi_bus_type,
		    .owner = THIS_MODULE,
		    },
	 },
	{
	 .driver = {
		    .name = "bcm_LegSpiDev3",
		    .bus = &spi_bus_type,
		    .owner = THIS_MODULE,
		    },
	 },
	{
	 .driver = {
		    .name = "bcm_LegSpiDev4",
		    .bus = &spi_bus_type,
		    .owner = THIS_MODULE,
		    },
	 },
	{
	 .driver = {
		    .name = "bcm_LegSpiDev5",
		    .bus = &spi_bus_type,
		    .owner = THIS_MODULE,
		    },
	 },
	{
	 .driver = {
		    .name = "bcm_LegSpiDev6",
		    .bus = &spi_bus_type,
		    .owner = THIS_MODULE,
		    },
	 },
	{
	 .driver = {
		    .name = "bcm_LegSpiDev7",
		    .bus = &spi_bus_type,
		    .owner = THIS_MODULE,
		    },
	 },
};

static struct spi_device *bcmLegSpiDevices[8];

static int legSpiRead(unsigned char *pRxBuf, int prependcnt, int nbytes,
		      int devId)
{
	int i;

	SPI->spiMsgCtl =
	    (HALF_DUPLEX_R << SPI_MSG_TYPE_SHIFT) | (nbytes <<
						     SPI_BYTE_CNT_SHIFT);

	for (i = 0; i < prependcnt; i++) {
		SPI->spiMsgData[i] = pRxBuf[i];
	}

	SPI->spiCmd = (SPI_CMD_START_IMMEDIATE << SPI_CMD_COMMAND_SHIFT |
		       devId << SPI_CMD_DEVICE_ID_SHIFT |
		       prependcnt << SPI_CMD_PREPEND_BYTE_CNT_SHIFT |
		       0 << SPI_CMD_ONE_BYTE_SHIFT);

	return SPI_STATUS_OK;

}

static int legSpiWriteFull(unsigned char *pTxBuf, int nbytes, int devId,
			   int opcode)
{
	int i;

	if (opcode == BCM_SPI_FULL) {
		SPI->spiMsgCtl =
		    (FULL_DUPLEX_RW << SPI_MSG_TYPE_SHIFT) | (nbytes <<
							      SPI_BYTE_CNT_SHIFT);
	} else {
		SPI->spiMsgCtl =
		    (HALF_DUPLEX_W << SPI_MSG_TYPE_SHIFT) | (nbytes <<
							     SPI_BYTE_CNT_SHIFT);
	}

	for (i = 0; i < nbytes; i++) {
		SPI->spiMsgData[i] = pTxBuf[i];
	}

	SPI->spiCmd = (SPI_CMD_START_IMMEDIATE << SPI_CMD_COMMAND_SHIFT |
		       devId << SPI_CMD_DEVICE_ID_SHIFT |
		       0 << SPI_CMD_PREPEND_BYTE_CNT_SHIFT |
		       0 << SPI_CMD_ONE_BYTE_SHIFT);

	return SPI_STATUS_OK;

}

static int legSpiTransEnd(unsigned char *rxBuf, int nbytes)
{
	int i;
	if (NULL != rxBuf) {
		for (i = 0; i < nbytes; i++) {
			rxBuf[i] = SPI->spiRxDataFifo[i];
		}
	}

	return SPI_STATUS_OK;

}

static void legSpiClearIntStatus(void)
{
	SPI->spiIntStatus = SPI_INTR_CLEAR_ALL;
}

static void legSpiEnableInt(bool bEnable)
{
	if (bEnable) {
		SPI->spiIntMask = SPI_INTR_CMD_DONE;
	} else {
		SPI->spiIntMask = 0;
	}
}

static int legSpiSetClock(int clockHz)
{
	int i;
	int clock = -1;

	for (i = 0; i < LEG_SPI_FREQ_TABLE_SIZE; i++) {
		/* look for the closest frequency that is less than the frequency passed in */
		if (legSpiClockFreq[i][0] <= clockHz) {
			clock = legSpiClockFreq[i][1];
			break;
		}
	}
	/* if no clock was found set to default */
	if (-1 == clock) {
		clock = LEG_SPI_CLOCK_DEF;
	}
	SPI->spiClkCfg = (SPI->spiClkCfg & ~SPI_CLK_MASK) | clock;

	return SPI_STATUS_OK;
}

static void legSpiNextMessage(struct bcmspi *pBcmSpi);

static void legSpiMsgDone(struct bcmspi *pBcmSpi, struct spi_message *msg,
			  int status)
{
	list_del(&msg->queue);
	msg->status = status;

	spin_unlock(&pBcmSpi->lock);
	msg->complete(msg->context);
	spin_lock(&pBcmSpi->lock);

	pBcmSpi->curTrans = NULL;

	/* continue if needed */
	if (list_empty(&pBcmSpi->queue) || pBcmSpi->stopping) {
		// disable controler ...
	} else {
		legSpiNextMessage(pBcmSpi);
	}
}

static void legSpiNextXfer(struct bcmspi *pBcmSpi, struct spi_message *msg)
{
	struct spi_transfer *xfer;
	struct spi_transfer *nextXfer;
	int length;
	int prependCnt;
	char *pTxBuf;
	char *pRxBuf;
	int opCode;

	xfer = pBcmSpi->curTrans;
	if (NULL == xfer) {
		xfer =
		    list_entry(msg->transfers.next, struct spi_transfer,
			       transfer_list);
	} else {
		xfer =
		    list_entry(xfer->transfer_list.next, struct spi_transfer,
			       transfer_list);
	}
	pBcmSpi->curTrans = xfer;

	length = xfer->len;
	prependCnt = 0;
	pRxBuf = xfer->rx_buf;
	pTxBuf = (unsigned char *)xfer->tx_buf;

	if ((NULL != pRxBuf) && (NULL != pTxBuf)) {
		opCode = BCM_SPI_FULL;
	} else if (NULL != pRxBuf) {
		opCode = BCM_SPI_READ;
	} else {
		opCode = BCM_SPI_WRITE;
	}

	if (msg->state) {
		/* this controller does not support keeping the chip select active for all transfers
		   non NULL state indicates that we need to combine the transfers */
		nextXfer =
		    list_entry(xfer->transfer_list.next, struct spi_transfer,
			       transfer_list);
		prependCnt = length;
		length = nextXfer->len;
		pRxBuf = nextXfer->rx_buf;
		opCode = BCM_SPI_READ;
		pBcmSpi->curTrans = nextXfer;
	}

	legSpiSetClock(xfer->speed_hz);

	legSpiClearIntStatus();
	legSpiEnableInt(TRUE);
	if (BCM_SPI_READ == opCode) {
		legSpiRead(pTxBuf, prependCnt, length, msg->spi->chip_select);
	} else {
		legSpiWriteFull(pTxBuf, length, msg->spi->chip_select, opCode);
	}

	return;

}

static void legSpiNextMessage(struct bcmspi *pBcmSpi)
{
	struct spi_message *msg;

	BUG_ON(pBcmSpi->curTrans);

	msg = list_entry(pBcmSpi->queue.next, struct spi_message, queue);

	/* there will always be one transfer in a given message */
	legSpiNextXfer(pBcmSpi, msg);

}

static int legSpiSetup(struct spi_device *spi)
{
	struct bcmspi *pBcmSpi;

	pBcmSpi = spi_master_get_devdata(spi->master);

	if (pBcmSpi->stopping)
		return -ESHUTDOWN;

	/* there is nothing to setup */

	return 0;
}

int legSpiTransfer(struct spi_device *spi, struct spi_message *msg)
{
	struct bcmspi *pBcmSpi = &BcmLegSpi;
	struct spi_transfer *xfer;
	struct spi_transfer *nextXfer;
	int xferCnt;
	int bCsChange;
	int xferLen;

	if (unlikely(list_empty(&msg->transfers)))
		return -EINVAL;

	if (pBcmSpi->stopping)
		return -ESHUTDOWN;

	/* make sure a completion callback is set */
	if (NULL == msg->complete) {
		return -EINVAL;
	}

	xferCnt = 0;
	bCsChange = 0;
	xferLen = 0;
	list_for_each_entry(xfer, &msg->transfers, transfer_list) {
		/* check transfer parameters */
		if (!(xfer->tx_buf || xfer->rx_buf)) {
			return -EINVAL;
		}

		/* check the clock setting - if it is 0 then set to max clock of the device */
		if (0 == xfer->speed_hz) {
			if (0 == spi->max_speed_hz) {
				return -EINVAL;
			}
			xfer->speed_hz = spi->max_speed_hz;
		}

		xferCnt++;
		xferLen += xfer->len;
		bCsChange |= xfer->cs_change;

		if (xfer->len > (sizeof(SPI->spiMsgData) & ~0x3)) {
			return -EINVAL;
		}
	}

	/* this controller does not support keeping the chip select active between
	   transfers. If a message is detected with a write transfer followed by a 
	   read transfer and cs_change is set to 0 then the two transfers need to be
	   combined. The message state is used to indicate that the transfers 
	   need to be combined */
	msg->state = NULL;
	if ((2 == xferCnt) && (0 == bCsChange)) {
		xfer =
		    list_entry(msg->transfers.next, struct spi_transfer,
			       transfer_list);
		if ((NULL != xfer->tx_buf) && (NULL == xfer->rx_buf)) {
			nextXfer =
			    list_entry(xfer->transfer_list.next,
				       struct spi_transfer, transfer_list);;
			if ((NULL == nextXfer->tx_buf)
			    && (NULL != nextXfer->rx_buf)) {
				msg->state = (void *)1;
			}
		}
	}

	msg->status = -EINPROGRESS;
	msg->actual_length = 0;

	/* disable interrupts for the SPI controller
	   using spin_lock_irqsave would disable all interrupts */
	legSpiEnableInt(FALSE);

	spin_lock(&pBcmSpi->lock);

	list_add_tail(&msg->queue, &pBcmSpi->queue);
	if (NULL == pBcmSpi->curTrans) {
		legSpiNextMessage(pBcmSpi);
	}

	spin_unlock(&pBcmSpi->lock);
	legSpiEnableInt(TRUE);

	return 0;
}

static irqreturn_t legSpiIntHandler(int irq, void *dev_id)
{
	struct bcmspi *pBcmSpi = dev_id;
	struct spi_message *msg;
	struct spi_transfer *xfer;

	if (0 == SPI->spiMaskIntStatus) {
		return IRQ_NONE;
	}

	legSpiClearIntStatus();
	legSpiEnableInt(FALSE);

	spin_lock(&pBcmSpi->lock);
	if (NULL == pBcmSpi->curTrans) {
		spin_unlock(&pBcmSpi->lock);
		return IRQ_HANDLED;
	}

	xfer = pBcmSpi->curTrans;
	msg = list_entry(pBcmSpi->queue.next, struct spi_message, queue);

	legSpiTransEnd(xfer->rx_buf, xfer->len);

	/* xfer can specify a delay before the next transfer is started 
	   this is only used for polling mode */

	/* check to see if this is the last transfer in the message */
	if (msg->transfers.prev == &xfer->transfer_list) {
		/* report completed message */
		legSpiMsgDone(pBcmSpi, msg, SPI_STATUS_OK);
	} else {
		/* Submit the next transfer */
		legSpiNextXfer(pBcmSpi, msg);
	}

	spin_unlock(&pBcmSpi->lock);

	return IRQ_HANDLED;

}

int __init legSpiIntrInit(void)
{
	int ret = 0;
	struct bcmspi *pBcmSpi = &BcmLegSpi;

	legSpiEnableInt(FALSE);
	ret =
	    request_irq(pBcmSpi->irq, legSpiIntHandler,
			(IRQF_DISABLED | IRQF_SAMPLE_RANDOM | IRQF_SHARED),
			pBcmSpi->devName, pBcmSpi);

	return ret;
}

static void legSpiCleanup(struct spi_device *spi)
{
	/* would free spi_controller memory here if any was allocated */

}

static int __init legSpiProbe(struct platform_device *pdev)
{
	int ret;
	struct spi_master *master;
	struct bcmspi *pBcmSpi;

	ret = -ENOMEM;
	master = spi_alloc_master(&pdev->dev, 0);
	if (!master)
		goto out_free;

	master->bus_num = pdev->id;
	master->num_chipselect = 8;
	master->setup = legSpiSetup;
	master->transfer = legSpiTransfer;
	master->cleanup = legSpiCleanup;
	platform_set_drvdata(pdev, master);

	spi_master_set_devdata(master, (void *)&BcmLegSpi);
	pBcmSpi = spi_master_get_devdata(master);

	INIT_LIST_HEAD(&pBcmSpi->queue);

	pBcmSpi->pdev = pdev;
	pBcmSpi->bus_num = LEG_SPI_BUS_NUM;
	pBcmSpi->num_chipselect = 8;
	pBcmSpi->curTrans = NULL;
	pBcmSpi->irq = platform_get_irq(pdev, 0);

	if (pBcmSpi->irq)
		ret = legSpiIntrInit();

	if (ret)
		goto out_free;

	/* Initialize the hardware */

	/* register and we are done */
	ret = spi_register_master(master);
	if (ret)
		goto out_free;

	return 0;

out_free:
	spi_master_put(master);

	return ret;
}

static int __exit legSpiRemove(struct platform_device *pdev)
{
	struct spi_master *master = platform_get_drvdata(pdev);
	struct bcmspi *pBcmSpi = spi_master_get_devdata(master);
	struct spi_message *msg;

	/* reset the hardware and block queue progress */
	legSpiEnableInt(FALSE);
	spin_lock(&pBcmSpi->lock);
	pBcmSpi->stopping = 1;

	/* HW shutdown */

	spin_unlock(&pBcmSpi->lock);

	/* Terminate remaining queued transfers */
	list_for_each_entry(msg, &pBcmSpi->queue, queue) {
		msg->status = -ESHUTDOWN;
		msg->complete(msg->context);
	}

	if (pBcmSpi->irq) {
		free_irq(pBcmSpi->irq, master);
	}
	spi_unregister_master(master);

	return 0;
}

//#ifdef CONFIG_PM
#if 0
static int legSpiSuspend(struct platform_device *pdev, pm_message_t mesg)
{
	struct spi_master *master = platform_get_drvdata(pdev);
	struct bcmspi *pBcmSpi = spi_master_get_devdata(master);

	return 0;
}

static int legSpiResume(struct platform_device *pdev)
{
	struct spi_master *master = platform_get_drvdata(pdev);
	struct bcmspi *pBcmSpi = spi_master_get_devdata(master);

	return 0;
}
#else
#define   legSpiSuspend   NULL
#define   legSpiResume    NULL
#endif

static struct platform_driver bcm_legspi_driver = {
	.driver = {
		   .name = "bcmleg_spi",
		   .owner = THIS_MODULE,
		   },
	.suspend = legSpiSuspend,
	.resume = legSpiResume,
	.remove = __exit_p(legSpiRemove),
};

static int __init legSpiModInit(void)
{
	return platform_driver_probe(&bcm_legspi_driver, legSpiProbe);
}

int BcmSpi_GetMaxRWSize(int busNum)
{
	int maxRWSize = 0;

	if (LEG_SPI_BUS_NUM == busNum) {
		maxRWSize = sizeof(SPI->spiMsgData);
	}

	maxRWSize &= ~0x3;

	return maxRWSize;
}

int BcmSpiReserveSlave(int busNum, int slaveId, int maxFreq)
{
	struct spi_master *pSpiMaster;
	struct spi_driver *pSpiDriver;

	if (slaveId > 7) {
		return SPI_STATUS_ERR;
	}

	if (LEG_SPI_BUS_NUM == busNum) {
		if (NULL != bcmLegSpiDevices[slaveId]) {
			printk(KERN_ERR
			       "BcmSpiReserveSlave - slaveId %d, already registerd\n",
			       slaveId);
			return SPI_STATUS_ERR;
		}

		bcmLegSpiDevInfo[slaveId].max_speed_hz = maxFreq;

		pSpiMaster = spi_busnum_to_master(busNum);
		bcmLegSpiDevices[slaveId] =
		    spi_new_device(pSpiMaster, &bcmLegSpiDevInfo[slaveId]);
		pSpiDriver = &bcmLegSpiDevDrv[slaveId];
	} else
		return SPI_STATUS_ERR;

	/* register the SPI driver */
	spi_register_driver(pSpiDriver);

	return 0;
}
EXPORT_SYMBOL(BcmSpiReserveSlave);

int BcmSpiReleaseSlave(int busNum, int slaveId)
{
	if (slaveId > 7) {
		return SPI_STATUS_ERR;
	}

	if (LEG_SPI_BUS_NUM == busNum) {
		if (NULL == bcmLegSpiDevices[slaveId]) {
			printk(KERN_ERR
			       "BcmSpiReleaseSlave - slaveId %d, already released\n",
			       slaveId);
			return SPI_STATUS_ERR;
		}

		bcmLegSpiDevInfo[slaveId].max_speed_hz = 781000;
		spi_unregister_driver(&bcmLegSpiDevDrv[slaveId]);
		spi_unregister_device(bcmLegSpiDevices[slaveId]);
		bcmLegSpiDevices[slaveId] = 0;
	} else
		return SPI_STATUS_ERR;

	return 0;
}
EXPORT_SYMBOL(BcmSpiReleaseSlave);

int BcmSpiSyncTrans(unsigned char *txBuf, unsigned char *rxBuf, int prependcnt,
		    int nbytes, int busNum, int slaveId)
{
	struct spi_message msg;
	struct spi_transfer xfer[2];
	int status;
	int maxLength;
	struct spi_device *pSpiDevice;

	maxLength = BcmSpi_GetMaxRWSize(busNum);
	if ((nbytes > maxLength) || (prependcnt > maxLength)) {
		printk(KERN_ERR
		       "ERROR BcmSpiSyncTrans: invalid length len %d, pre %d, max %d\n",
		       nbytes, prependcnt, maxLength);
		return SPI_STATUS_ERR;
	}

	if (slaveId > 7) {
		printk(KERN_ERR "ERROR BcmSpiSyncTrans: invalid slave id %d\n",
		       slaveId);
		return SPI_STATUS_ERR;
	}

	if (LEG_SPI_BUS_NUM == busNum) {
		if (NULL == bcmLegSpiDevices[slaveId]) {
			printk(KERN_ERR
			       "ERROR BcmSpiSyncTrans: device not registered\n");
			return SPI_STATUS_ERR;
		}
		pSpiDevice = bcmLegSpiDevices[slaveId];
	} else
		return SPI_STATUS_ERR;

	spi_message_init(&msg);
	memset(xfer, 0, (sizeof xfer));

	if (prependcnt) {
		xfer[0].len = prependcnt;
		xfer[0].speed_hz = pSpiDevice->max_speed_hz;
		if (txBuf) {
			xfer[0].tx_buf = txBuf;
		} else {
			xfer[0].tx_buf = rxBuf;
		}
		spi_message_add_tail(&xfer[0], &msg);
	}

	xfer[1].len = nbytes;
	xfer[1].speed_hz = pSpiDevice->max_speed_hz;
	xfer[1].rx_buf = rxBuf;

	/* for the controller to use the prepend count correctly the first operation must be a read and the second a write 
	   make sure tx is NULL for second transaction */
	if (0 == prependcnt) {
		xfer[1].tx_buf = txBuf;
	}
	spi_message_add_tail(&xfer[1], &msg);

	status = spi_sync(pSpiDevice, &msg);
	if (status >= 0) {
		status = SPI_STATUS_OK;
	} else {
		status = SPI_STATUS_ERR;
	}

	return status;
}
EXPORT_SYMBOL(BcmSpiSyncTrans);

subsys_initcall(legSpiModInit);
MODULE_LICENSE("GPL");
