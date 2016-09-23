/*
    Copyright 2000-2010 Broadcom Corporation

    Unless you and Broadcom execute a separate written software license
    agreement governing use of this software, this software is licensed
    to you under the terms of the GNU General Public License version 2
    (the GPL), available at http://www.broadcom.com/licenses/GPLv2.php,
    with the following added to such license:

        As a special exception, the copyright holders of this software give
        you permission to link this software with independent modules, and to
        copy and distribute the resulting executable under terms of your
        choice, provided that you also meet, for each linked independent
        module, the terms and conditions of the license of that module. 
        An independent module is a module which is not derived from this
        software.  The special exception does not apply to any modifications
        of the software.

    Notwithstanding the above, under no circumstances may you combine this
    software in any way with any other Broadcom software provided under a
    license other than the GPL, without Broadcom's express prior written
    consent.
*/                       

#ifndef __BCMSPIRES_H__
#define __BCMSPIRES_H__  

#define SPI_STATUS_OK                (0)
#define SPI_STATUS_INVALID_LEN      (-1)
#define SPI_STATUS_ERR              (-2)

/* legacy and HS controllers can coexist - use bus num to differentiate */
#define LEG_SPI_BUS_NUM	     0
#define HS_SPI_BUS_NUM	     1
#define LEG_SPI_CLOCK_DEF    2
#define HS_SPI_PLL_FREQ	     400000000
#define HS_SPI_CLOCK_DEF     40000000
#define HS_SPI_BUFFER_LEN    512
#define BCM_SPI_READ	     0
#define BCM_SPI_WRITE	     1
#define BCM_SPI_FULL	     2


int BcmSpiReserveSlave(int busNum, int slaveId, int maxFreq);
int BcmSpiReleaseSlave(int busNum, int slaveId);
int BcmSpiSyncTrans(unsigned char *txBuf, unsigned char *rxBuf, int prependcnt, int nbytes, int busNum, int slaveId);
int BcmSpi_SetFlashCtrl( int, int, int, int, int );
int BcmSpi_GetMaxRWSize( int );
int BcmSpi_Read(unsigned char *, int, int, int, int, int);
int BcmSpi_Write(unsigned char *, int, int, int, int);

#endif /* __BCMSPIRES_H__ */

