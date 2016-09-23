#ifndef __PKTDMA_H_INCLUDED__
#define __PKTDMA_H_INCLUDED__

/*
<:copyright-broadcom

 Copyright (c) 2007 Broadcom Corporation
 All Rights Reserved
 No portions of this material may be reproduced in any form without the
 written permission of:
          Broadcom Corporation
          5300 California Avenue
          Irvine, California 92617
 All information contained in this document is Broadcom Corporation
 company private, proprietary, and trade secret.

:>
*/

/*
 *******************************************************************************
 * File Name  : bcmPktDma.h
 *
 * Description: This file contains the Packet DMA API definition. It may be
 *              included in Kernel space only.
 *
 *******************************************************************************
 */

#include <bcmtypes.h>
#include <bcm_map_part.h>
#include <linux/nbuff.h>
#include <linux/netdevice.h>
#include <linux/ppp_channel.h>
#include "bcmenet.h"
#include "bcmxtmcfg.h"
#include "bcmxtmrt.h"
#ifndef CONFIG_BCM96816
#include "bcmxtmrtimpl.h"
#endif
#include "bcmPktDma_structs.h"
#if defined(CONFIG_BCM_FAP) || defined(CONFIG_BCM_FAP_MODULE)
#include "fap_hw.h"
#include "fap4ke_memory.h"
#endif

#define CC_BCM_PKTDMA_DEBUG

/* TX Buffer sources supported by bcmPktDma Lib */
enum { HOST_VIA_LINUX=0, HOST_VIA_DQM, HOST_VIA_DQM_4KE_FREE, FAP_XTM_RX, FAP_ETH_RX };

extern BcmEnet_devctrl *               g_pEnetDevCtrl;
#ifndef CONFIG_BCM96816
extern PBCMXTMRT_GLOBAL_INFO           g_pXtmGlobalInfo;
#endif
#ifdef RXCHANNEL_PKT_RATE_LIMIT
extern int *                           g_pEnetrxchannel_isr_enable;
#endif

#define FAP_ENET_CHAN0 (1 << 0)
#define FAP_ENET_CHAN1 (1 << 1)

#if !defined(CONFIG_BCM_FAP) && !defined(CONFIG_BCM_FAP_MODULE)
/* Most chips use the Iudma version of the bcmPkt interface */
/* Eth versions of the interface */
#define bcmPktDma_EthInitRxChan           bcmPktDma_EthInitRxChan_Iudma
#define bcmPktDma_EthInitTxChan           bcmPktDma_EthInitTxChan_Iudma
#define bcmPktDma_EthInit                 bcmPktDma_EthInit_Iudma
#define bcmPktDma_EthSelectRxIrq          bcmPktDma_EthSelectRxIrq_Iudma
#define bcmPktDma_EthClrRxIrq             bcmPktDma_EthClrRxIrq_Iudma
#define bcmPktDma_EthRecvAvailable        bcmPktDma_EthRecvAvailable_Iudma
#define bcmPktDma_EthRecv                 bcmPktDma_EthRecv_Iudma
#define bcmPktDma_EthFreeRecvBuf          bcmPktDma_EthFreeRecvBuf_Iudma
#define bcmPktDma_EthXmitAvailable        bcmPktDma_EthXmitAvailable_Iudma
//#define bcmPktDma_EthXmit                 bcmPktDma_EthXmit_Iudma
#define bcmPktDma_EthXmit                 bcmPktDma_EthXmitNoCheck_Iudma
#define bcmPktDma_EthTxEnable             bcmPktDma_EthTxEnable_Iudma
#define bcmPktDma_EthTxDisable            bcmPktDma_EthTxDisable_Iudma
#define bcmPktDma_EthRxEnable             bcmPktDma_EthRxEnable_Iudma
#define bcmPktDma_EthRxDisable            bcmPktDma_EthRxDisable_Iudma
#define bcmPktDma_EthFreeXmitBufGet       bcmPktDma_EthFreeXmitBufGet_Iudma
#define bcmPktDma_EthRxReEnable           bcmPktDma_EthRxReEnable_Iudma

/* XTM versions of the interface */
#define bcmPktDma_XtmInitRxChan           bcmPktDma_XtmInitRxChan_Iudma
#define bcmPktDma_XtmInitTxChan           bcmPktDma_XtmInitTxChan_Iudma
//#define bcmPktDma_XtmInit                 bcmPktDma_XtmInit_Iudma
#define bcmPktDma_XtmSelectRxIrq          bcmPktDma_XtmSelectRxIrq_Iudma
#define bcmPktDma_XtmClrRxIrq             bcmPktDma_XtmClrRxIrq_Iudma
#define bcmPktDma_XtmRecvAvailable        bcmPktDma_XtmRecvAvailable_Iudma
#define bcmPktDma_XtmRecv                 bcmPktDma_XtmRecv_Iudma
#define bcmPktDma_XtmFreeRecvBuf          bcmPktDma_XtmFreeRecvBuf_Iudma
#define bcmPktDma_XtmFreeXmitBuf          bcmPktDma_XtmFreeXmitBuf_Iudma
#define bcmPktDma_XtmXmitAvailable        bcmPktDma_XtmXmitAvailable_Iudma
#define bcmPktDma_XtmXmit                 bcmPktDma_XtmXmit_Iudma
#define bcmPktDma_XtmTxEnable             bcmPktDma_XtmTxEnable_Iudma
#define bcmPktDma_XtmTxDisable            bcmPktDma_XtmTxDisable_Iudma
#define bcmPktDma_XtmRxEnable             bcmPktDma_XtmRxEnable_Iudma
#define bcmPktDma_XtmFreeXmitBufGet       bcmPktDma_XtmFreeXmitBufGet_Iudma
#define bcmPktDma_XtmRxDisable            bcmPktDma_XtmRxDisable_Iudma

#define bcmPktDma_XtmCreateDevice(_devId, _encapType)
#define bcmPktDma_XtmLinkUp(_devId, _matchId)

#else /* FAP is compiled in */

/* The BCM96362 chip uses the Dqm version of the bcmPkt interface */
/* Eth versions of the interface */
#define bcmPktDma_EthInitRxChan           bcmPktDma_EthInitRxChan_Dqm
#define bcmPktDma_EthInitTxChan           bcmPktDma_EthInitTxChan_Dqm
#define bcmPktDma_EthInit                 bcmPktDma_EthInit_Dqm
#define bcmPktDma_EthSelectRxIrq          bcmPktDma_EthSelectRxIrq_Dqm
#define bcmPktDma_EthClrRxIrq             bcmPktDma_EthClrRxIrq_Dqm
#define bcmPktDma_EthRecvAvailable        bcmPktDma_EthRecvAvailable_Dqm
#define bcmPktDma_EthRecv                 bcmPktDma_EthRecv_Dqm
#define bcmPktDma_EthFreeRecvBuf          bcmPktDma_EthFreeRecvBuf_Dqm
#define bcmPktDma_EthXmitAvailable        bcmPktDma_EthXmitAvailable_Dqm
//#define bcmPktDma_EthXmit                 bcmPktDma_EthXmit_Dqm
#define bcmPktDma_EthXmit                 bcmPktDma_EthXmitNoCheck_Dqm
#define bcmPktDma_EthTxEnable             bcmPktDma_EthTxEnable_Dqm
#define bcmPktDma_EthTxDisable            bcmPktDma_EthTxDisable_Dqm
#define bcmPktDma_EthRxEnable             bcmPktDma_EthRxEnable_Dqm
#define bcmPktDma_EthRxDisable            bcmPktDma_EthRxDisable_Dqm
#define bcmPktDma_EthFreeXmitBufGet       bcmPktDma_EthFreeXmitBufGet_Dqm
#define bcmPktDma_EthRxReEnable           bcmPktDma_EthRxReEnable_Dqm

/* XTM versions of the interface */
#define bcmPktDma_XtmInitRxChan           bcmPktDma_XtmInitRxChan_Dqm
#define bcmPktDma_XtmInitTxChan           bcmPktDma_XtmInitTxChan_Dqm
#define bcmPktDma_XtmSelectRxIrq          bcmPktDma_XtmSelectRxIrq_Dqm
#define bcmPktDma_XtmClrRxIrq             bcmPktDma_XtmClrRxIrq_Dqm
#define bcmPktDma_XtmRecvAvailable        bcmPktDma_XtmRecvAvailable_Dqm
#define bcmPktDma_XtmRecv                 bcmPktDma_XtmRecv_Dqm
#define bcmPktDma_XtmFreeRecvBuf          bcmPktDma_XtmFreeRecvBuf_Dqm
#define bcmPktDma_XtmFreeXmitBuf          bcmPktDma_XtmFreeXmitBuf_Dqm
#define bcmPktDma_XtmXmitAvailable        bcmPktDma_XtmXmitAvailable_Dqm
#define bcmPktDma_XtmXmit                 bcmPktDma_XtmXmit_Dqm
#define bcmPktDma_XtmTxEnable             bcmPktDma_XtmTxEnable_Dqm
#define bcmPktDma_XtmTxDisable            bcmPktDma_XtmTxDisable_Dqm
#define bcmPktDma_XtmRxEnable             bcmPktDma_XtmRxEnable_Dqm
#define bcmPktDma_XtmRxDisable            bcmPktDma_XtmRxDisable_Dqm
#define bcmPktDma_XtmFreeXmitBufGet       bcmPktDma_XtmFreeXmitBufGet_Dqm

#define bcmPktDma_XtmCreateDevice(_devId, _encapType)   \
    bcmPktDma_XtmCreateDevice_Dqm(_devId, _encapType) 

#define bcmPktDma_XtmLinkUp(_devId, _matchId)   \
    bcmPktDma_XtmLinkUp_Dqm(_devId, _matchId)

#endif

#define MAX_ETH_RX_CHANNELS               2
#define MAX_ETH_TX_CHANNELS               2

/* enable CPU usage profiling */
//#define FAP4KE_IUDMA_PMON_ENABLE

#if defined(FAP4KE_IUDMA_PMON_ENABLE)
#define FAP4KE_IUDMA_PMON_DECLARE() FAP4KE_PMON_DECLARE()
#define FAP4KE_IUDMA_PMON_BEGIN(_pmonId) FAP4KE_PMON_BEGIN(_pmonId)
#define FAP4KE_IUDMA_PMON_END(_pmonId) FAP4KE_PMON_END(_pmonId)
#else
#define FAP4KE_IUDMA_PMON_DECLARE()
#define FAP4KE_IUDMA_PMON_BEGIN(_pmonId)
#define FAP4KE_IUDMA_PMON_END(_pmonId)
#endif

#define BCM_PKTDMA_SUCCESS 0
#define BCM_PKTDMA_ERROR   -1

#define BCM_PKTDMA_PBUF_FROM_BD(_dmaDesc_p)                     \
    ( (unsigned char *)(phys_to_virt((_dmaDesc_p)->address)) )

#define BCM_PKTDMA_LEN_FROM_BD(_dmaDesc_p)                     \
    ( (unsigned int)((_dmaDesc_p)->length) )

#if (defined(CONFIG_BCM_FAP) || defined(CONFIG_BCM_FAP_MODULE))
#if defined(COMPARE_PSM_IUDMA_PERF)
#define g_pEthRxDma ( p4kePsm->global.g_pEthRxDma )
#define g_pEthTxDma ( p4kePsm->global.g_pEthTxDma )

#define g_pXtmRxDma ( p4kePsm->global.g_pXtmRxDma )
#define g_pXtmTxDma ( p4kePsm->global.g_pXtmTxDma )
#else
#define g_pEthRxDma ( p4keDspram->global.g_pEthRxDma )
#define g_pEthTxDma ( p4keDspram->global.g_pEthTxDma )

#define g_pXtmRxDma ( p4keDspram->global.g_pXtmRxDma )
#define g_pXtmTxDma ( p4keDspram->global.g_pXtmTxDma )
#endif
#else
/* Define in DDR */
extern BcmPktDma_LocalEthRxDma *g_pEthRxDma[NUM_RXDMA_CHANNELS]; 
extern BcmPktDma_LocalEthTxDma *g_pEthTxDma[NUM_TXDMA_CHANNELS];

extern BcmPktDma_LocalXtmRxDma *g_pXtmRxDma[MAX_RECEIVE_QUEUES]; 
extern BcmPktDma_LocalXtmTxDma *g_pXtmTxDma[MAX_TRANSMIT_QUEUES];
#endif

/*
 * Inline functions
 */

#define BCM_PKTDMA_CHANNEL_TO_RXDMA(_channel) ( g_pEthRxDma[(_channel)] )
#define BCM_PKTDMA_CHANNEL_TO_RXDMA_XTM(_channel) ( g_pXtmRxDma[(_channel)] )


/* --------------------------------------------------------------------------
    Name: bcmPktDma_EthRecvAvailableGet_Iudma
 Purpose: Return 1 if a packet is available, 0 otherwise
-------------------------------------------------------------------------- */
static inline int __bcmPktDma_EthRecvAvailableGet_Iudma(BcmPktDma_LocalEthRxDma *rxdma,
                                                        DmaDesc *dmaDesc_p)
{
    FAP4KE_IUDMA_PMON_DECLARE();
    FAP4KE_IUDMA_PMON_BEGIN(FAP4KE_PMON_ID_IUDMA_RECV);

    dmaDesc_p->word0 = rxdma->rxBds[rxdma->rxHeadIndex].word0;

#if defined(RXCHANNEL_PKT_RATE_LIMIT) && defined(CONFIG_BCM96816)
    if (rxdma->enetrxchannel_isr_enable) 
#endif
    {
        if( rxdma->rxAssignedBds && ((dmaDesc_p->status & DMA_OWN) == 0) )
        {
            dmaDesc_p->address = rxdma->rxBds[rxdma->rxHeadIndex].address;
            FAP4KE_IUDMA_PMON_END(FAP4KE_PMON_ID_IUDMA_RECV);
            return 1;
        }
        else
        {
            /* FIXME: Added this for compiler warning... */
            dmaDesc_p->address = 0;
        }
    }
    
    FAP4KE_IUDMA_PMON_END(FAP4KE_PMON_ID_IUDMA_RECV);
    return 0;
}
static inline int bcmPktDma_EthRecvAvailableGet_Iudma(int channel,
                                                      DmaDesc *dmaDesc_p)
{
    BcmPktDma_LocalEthRxDma *rxdma = g_pEthRxDma[channel];

    return __bcmPktDma_EthRecvAvailableGet_Iudma(rxdma, dmaDesc_p);
}


/* --------------------------------------------------------------------------
    Name: bcmPktDma_XtmRecvAvailableGet_Iudma
 Purpose: Return 1 if a packet is available, 0 otherwise
-------------------------------------------------------------------------- */
static inline int __bcmPktDma_XtmRecvAvailableGet_Iudma(BcmPktDma_LocalXtmRxDma *rxdma,
                                                        DmaDesc *dmaDesc_p)
{
    //FAP4KE_IUDMA_PMON_DECLARE();
    //FAP4KE_IUDMA_PMON_BEGIN(FAP4KE_PMON_ID_IUDMA_RECV);

    dmaDesc_p->word0 = rxdma->rxBds[rxdma->rxHeadIndex].word0;

    if( rxdma->rxAssignedBds && ((dmaDesc_p->status & DMA_OWN) == 0) )
    {
        dmaDesc_p->address = rxdma->rxBds[rxdma->rxHeadIndex].address;
        //FAP4KE_IUDMA_PMON_END(FAP4KE_PMON_ID_IUDMA_RECV);
        return 1;
    }
    else
    {
        /* FIXME: Added this for compiler warning... */
        dmaDesc_p->address = 0;
    }
    
    //FAP4KE_IUDMA_PMON_END(FAP4KE_PMON_ID_IUDMA_RECV);
    return 0;
}
static inline int bcmPktDma_XtmRecvAvailableGet_Iudma(int channel,
                                                      DmaDesc *dmaDesc_p)
{
    BcmPktDma_LocalXtmRxDma *rxdma = g_pXtmRxDma[channel];

    return __bcmPktDma_XtmRecvAvailableGet_Iudma(rxdma, dmaDesc_p);
}

/* --------------------------------------------------------------------------
    Name: bcmPktDma_EthRecvAvailable
 Purpose: Return 1 if a packet is available, 0 otherwise
-------------------------------------------------------------------------- */
static inline int __bcmPktDma_EthRecvAvailable_Iudma(BcmPktDma_LocalEthRxDma *rxdma)
{
    if( rxdma->rxAssignedBds &&
        !(rxdma->rxBds[rxdma->rxHeadIndex].status & DMA_OWN) )
        return 1;
    
    return 0;
    
}
static inline int bcmPktDma_EthRecvAvailable_Iudma(int channel)
{
    BcmPktDma_LocalEthRxDma *rxdma = g_pEthRxDma[channel];

    return __bcmPktDma_EthRecvAvailable_Iudma(rxdma);
}

/* --------------------------------------------------------------------------
    Name: bcmPktDma_XtmRecvAvailable
 Purpose: Return 1 if a packet is available, 0 otherwise
-------------------------------------------------------------------------- */
static inline int __bcmPktDma_XtmRecvAvailable_Iudma(BcmPktDma_LocalXtmRxDma *rxdma)
{

    if( rxdma->rxAssignedBds &&
        !(rxdma->rxBds[rxdma->rxHeadIndex].status & DMA_OWN) )
        return 1;
    
    return 0;

    //return ((rxdma->pBdHead->status & DMA_OWN) ? 0 : 1);
  
}
static inline int bcmPktDma_XtmRecvAvailable_Iudma(int channel)
{
    BcmPktDma_LocalXtmRxDma *rxdma = g_pXtmRxDma[channel];

    return __bcmPktDma_XtmRecvAvailable_Iudma(rxdma);
}

/* --------------------------------------------------------------------------
    Name: bcmPktDma_EthRecvNoCheck_Iudma
 Purpose: Receive a packet on a specific channel, without checking if
          packets are available. Must be used in conjunction with
          bcmPktDma_EthRecvAvailableGet_Iudma().
-------------------------------------------------------------------------- */
static inline int __bcmPktDma_EthRecvNoCheck_Iudma(BcmPktDma_LocalEthRxDma *rxdma)
{
    FAP4KE_IUDMA_PMON_DECLARE();
    FAP4KE_IUDMA_PMON_BEGIN(FAP4KE_PMON_ID_IUDMA_RECV);

#if defined(CC_BCM_PKTDMA_DEBUG)
    if(rxdma->rxAssignedBds == 0)
    {
        return BCM_PKTDMA_ERROR;
    }
#endif

    /* If no more rx packets, we are done for this channel */
#if defined(RXCHANNEL_PKT_RATE_LIMIT) && defined(CONFIG_BCM96816)
    if (rxdma->enetrxchannel_isr_enable != 0)
#endif
    {
        /* Wrap around the rxHeadIndex */
        if (++rxdma->rxHeadIndex == rxdma->numRxBds) 
        {
            rxdma->rxHeadIndex = 0;
        }
        rxdma->rxAssignedBds--;
    }

    FAP4KE_IUDMA_PMON_END(FAP4KE_PMON_ID_IUDMA_RECV);

    return BCM_PKTDMA_SUCCESS;
}

static inline void bcmPktDma_EthRecvNoCheck_Iudma(int channel)
{
    BcmPktDma_LocalEthRxDma *rxdma = g_pEthRxDma[channel];

    __bcmPktDma_EthRecvNoCheck_Iudma(rxdma);
}

/* --------------------------------------------------------------------------
    Name: bcmPktDma_XtmRecvNoCheck_Iudma
 Purpose: Receive a packet on a specific channel, without checking if
          packets are available. Must be used in conjunction with
          bcmPktDma_XtmRecvAvailableGet_Iudma().
-------------------------------------------------------------------------- */
static inline int __bcmPktDma_XtmRecvNoCheck_Iudma(BcmPktDma_LocalXtmRxDma *rxdma)
{
    //FAP4KE_IUDMA_PMON_DECLARE();
    //FAP4KE_IUDMA_PMON_BEGIN(FAP4KE_PMON_ID_IUDMA_RECV);

#if defined(CC_BCM_PKTDMA_DEBUG)
    if(rxdma->rxAssignedBds == 0)
    {
        return BCM_PKTDMA_ERROR;
    }
#endif

    /* Wrap around the rxHeadIndex */
    if (++rxdma->rxHeadIndex == rxdma->numRxBds) 
        rxdma->rxHeadIndex = 0;

    rxdma->rxAssignedBds--;

    //FAP4KE_IUDMA_PMON_END(FAP4KE_PMON_ID_IUDMA_RECV);

    return BCM_PKTDMA_SUCCESS;
}

static inline void bcmPktDma_XtmRecvNoCheck_Iudma(int channel)
{
    BcmPktDma_LocalXtmRxDma *rxdma = g_pXtmRxDma[channel];

    __bcmPktDma_XtmRecvNoCheck_Iudma(rxdma);
}

/* --------------------------------------------------------------------------
    Name: bcmPktDma_EthClrRxIrq
 Purpose: Clear the Rx interrupt for a specific channel
-------------------------------------------------------------------------- */
static inline void __bcmPktDma_EthClrRxIrq_Iudma(BcmPktDma_LocalEthRxDma *rxdma)
{
    /* Move rxDma ptr to local context */
    rxdma->rxDma->intStat = DMA_DONE | DMA_NO_DESC | DMA_BUFF_DONE;  // clr interrupts
}
static inline void bcmPktDma_EthClrRxIrq_Iudma(int channel)
{
    BcmPktDma_LocalEthRxDma *rxdma = g_pEthRxDma[channel];

    __bcmPktDma_EthClrRxIrq_Iudma(rxdma);
}

/* --------------------------------------------------------------------------
    Name: bcmPktDma_XtmClrRxIrq
 Purpose: Clear the Rx interrupt for a specific channel
-------------------------------------------------------------------------- */
static inline void __bcmPktDma_XtmClrRxIrq_Iudma(BcmPktDma_LocalXtmRxDma *rxdma)
{
    rxdma->rxDma->intStat = DMA_DONE | DMA_NO_DESC | DMA_BUFF_DONE;
}

static inline void bcmPktDma_XtmClrRxIrq_Iudma(int channel)
{
    BcmPktDma_LocalXtmRxDma *rxdma = g_pXtmRxDma[channel];

    __bcmPktDma_XtmClrRxIrq_Iudma(rxdma);
}


/* --------------------------------------------------------------------------
    Name: bcmPktDma_EthFreeXmitBufGet
 Purpose: Gets a TX buffer to free by caller
-------------------------------------------------------------------------- */
static inline BOOL bcmPktDma_EthFreeXmitBufGet_Iudma(int channel, uint32 *pKey,
                                                     int *pTxSource, uint32 *pTxAddr)
{
    BcmPktDma_LocalEthTxDma *txdma;
    BOOL ret = FALSE;
    int  bdIndex;

    FAP4KE_IUDMA_PMON_DECLARE();
    FAP4KE_IUDMA_PMON_BEGIN(FAP4KE_PMON_ID_IUDMA_FREEXMITBUFGET);

    txdma = g_pEthTxDma[channel];
    bdIndex = txdma->txHeadIndex;
    *pKey = 0;
#if defined(CONFIG_BCM_FAP) || defined(CONFIG_BCM_FAP_MODULE)
    /* TxSource & TxAddr not required in non-FAP applications */ 
    *pTxSource = 0;
    *pTxAddr   = 0;
#endif

    /* Reclaim transmitted buffers */
    if (txdma->txFreeBds < NR_TX_BDS)
    {
        if (txdma->txBds[bdIndex].status & DMA_OWN)
        {
            /* Do Nothing */
        }
        else 
        {
           *pKey = (uint32) txdma->pKeyPtr[bdIndex];
#if defined(CONFIG_BCM_FAP) || defined(CONFIG_BCM_FAP_MODULE)
           /* TxSource & TxAddr not required in non-FAP applications */ 
           *pTxSource = txdma->pTxSource[bdIndex];
           *pTxAddr   = txdma->pTxAddress[bdIndex];
#endif
        
           if (++txdma->txHeadIndex == NR_TX_BDS)
               txdma->txHeadIndex = 0;

           txdma->txFreeBds++;
           ret = TRUE;
        }
    }

    FAP4KE_IUDMA_PMON_END(FAP4KE_PMON_ID_IUDMA_FREEXMITBUFGET);

    return ret;
}

/* --------------------------------------------------------------------------
    Name: bcmPktDma_XtmFreeXmitBufGet
 Purpose: Gets a TX buffer to free by caller
-------------------------------------------------------------------------- */
static inline BOOL bcmPktDma_XtmFreeXmitBufGet_Iudma(int channel, uint32 *pKey,
                                                     int *pTxSource, uint32 *pTxAddr)
{
    BcmPktDma_LocalXtmTxDma *txdma;
    BOOL ret = FALSE;
    int  bdIndex;

    //FAP4KE_IUDMA_PMON_DECLARE();
    //FAP4KE_IUDMA_PMON_BEGIN(FAP4KE_PMON_ID_IUDMA_FREEXMITBUFGET);

    txdma = g_pXtmTxDma[channel];
    bdIndex = txdma->txHeadIndex;
    *pKey = 0;
#if defined(CONFIG_BCM_FAP) || defined(CONFIG_BCM_FAP_MODULE)
    /* TxSource & TxAddr not required in non-FAP applications */ 
    *pTxSource = 0;
    *pTxAddr   = 0;
#endif

    /* Reclaim transmitted buffers */
    if (txdma->txFreeBds < NR_TX_BDS)
    {
        if (txdma->txBds[bdIndex].status & DMA_OWN)
        {
            /* Do Nothing */
        }
        else 
        {
           *pKey = (uint32) txdma->pKeyPtr[bdIndex];
#if defined(CONFIG_BCM_FAP) || defined(CONFIG_BCM_FAP_MODULE)
           /* TxSource & TxAddr not required in non-FAP applications */ 
           *pTxSource = txdma->pTxSource[bdIndex];
           *pTxAddr   = txdma->pTxAddress[bdIndex];
#endif        
           if (++txdma->txHeadIndex == NR_TX_BDS)
               txdma->txHeadIndex = 0;

           txdma->txFreeBds++;
           txdma->ulNumTxBufsQdOne--;
#if !defined(CONFIG_BCM96816) && !defined(CONFIG_BCM63XX_CPU_6362)
           // FIXME - Which chip uses more then one TX queue?
           g_pXtmGlobalInfo->ulNumTxBufsQdAll--;
#endif

           ret = TRUE;
        }
    }

    //FAP4KE_IUDMA_PMON_END(FAP4KE_PMON_ID_IUDMA_FREEXMITBUFGET);

    return ret;
}


/* --------------------------------------------------------------------------
    Name: bcmPktDma_EthFreeRecvBuf
 Purpose: Free a single RX buffer
-------------------------------------------------------------------------- */
static inline int bcmPktDma_EthFreeRecvBuf_Iudma(int channel, unsigned char * pBuf)
{
    BcmPktDma_LocalEthRxDma *    rxdma;
    volatile DmaDesc * rxBd;
    DmaDesc            dmaDesc;
    int                tail_idx;

    FAP4KE_IUDMA_PMON_DECLARE();
    FAP4KE_IUDMA_PMON_BEGIN(FAP4KE_PMON_ID_IUDMA_FREERECVBUF);

    rxdma = g_pEthRxDma[channel];

#if defined(CC_BCM_PKTDMA_DEBUG)
    if(rxdma->rxAssignedBds == rxdma->numRxBds)
    {
        return BCM_PKTDMA_ERROR;
    }
#endif

    tail_idx = rxdma->rxTailIndex;
    rxBd = &rxdma->rxBds[tail_idx];

    /* assign packet, prepare descriptor, and advance pointer */
    dmaDesc.length = RX_BUF_LEN;

    if (tail_idx == (rxdma->numRxBds - 1)) {
        dmaDesc.status = DMA_OWN | DMA_WRAP;
        rxdma->rxTailIndex = 0;
    } else {
        dmaDesc.status = DMA_OWN;
        rxdma->rxTailIndex = tail_idx + 1;
    }
    
    rxBd->address = (uint32)VIRT_TO_PHY(pBuf);
    rxBd->word0 = dmaDesc.word0;

    rxdma->rxAssignedBds++;
    if(rxdma->rxEnabled)
    {   /* Do not reenable if Host MIPs has shut the interface down */
        rxdma->rxDma->cfg = DMA_ENABLE;
    }

    FAP4KE_IUDMA_PMON_END(FAP4KE_PMON_ID_IUDMA_FREERECVBUF);

    return BCM_PKTDMA_SUCCESS;
}

/* --------------------------------------------------------------------------
    Name: bcmPktDma_XtmFreeRecvBuf
 Purpose: Free a single RX buffer
-------------------------------------------------------------------------- */
static inline int bcmPktDma_XtmFreeRecvBuf_Iudma(int channel, unsigned char *pBuf)
{
    BcmPktDma_LocalXtmRxDma *rxdma;
    volatile DmaDesc        *rxBd;
    DmaDesc                  dmaDesc;
    int                      tail_idx;

    //printk("bcmPktDma_XtmFreeRecvBuf_Iudma ch: %d pBuf: %p\n", channel, pBuf);

    //FAP4KE_IUDMA_PMON_DECLARE();
    //FAP4KE_IUDMA_PMON_BEGIN(FAP4KE_PMON_ID_IUDMA_FREERECVBUF);

    rxdma = g_pXtmRxDma[channel];

    tail_idx = rxdma->rxTailIndex;
    rxBd = &rxdma->rxBds[tail_idx];

    /* assign packet, prepare descriptor, and advance pointer */
    dmaDesc.length = RX_BUF_LEN;

    if (tail_idx == (rxdma->numRxBds - 1)) {
        dmaDesc.status = DMA_OWN | DMA_WRAP;
        rxdma->rxTailIndex = 0;
    } else {
        dmaDesc.status = DMA_OWN;
        rxdma->rxTailIndex = tail_idx + 1;
    }
    
    rxBd->address = (uint32)VIRT_TO_PHY(pBuf);
    rxBd->word0 = dmaDesc.word0;

    rxdma->rxAssignedBds++;
    if(rxdma->rxEnabled)
    {   /* Do not reenable if Host MIPs has shut the interface down */
        rxdma->rxDma->cfg = DMA_ENABLE;
    }

    //FAP4KE_IUDMA_PMON_END(FAP4KE_PMON_ID_IUDMA_FREERECVBUF);

    return BCM_PKTDMA_SUCCESS;
}

/* --------------------------------------------------------------------------
    Name: bcmPktDma_EthXmit
 Purpose: Xmit an NBuff
   Notes: param1 = gemid;   param2 = port_id; param3 = egress_queue 
  Return: 1 on success; 0 otherwise
-------------------------------------------------------------------------- */
static inline int bcmPktDma_EthXmit_Iudma(int channel, uint8 *pBuf, uint16 len,
                                          int bufSource, uint16 dmaStatus, uint32 key,
                                          int param1)
{
    BcmPktDma_LocalEthTxDma *  txdma;
    DmaDesc          dmaDesc;
#if (defined(CONFIG_BCM96816) && defined(DBL_DESC))
    volatile DmaDesc16 *txBd;
#else
    volatile DmaDesc *  txBd;
#endif
    int                 txIndex;
    
    FAP4KE_IUDMA_PMON_DECLARE();
    FAP4KE_IUDMA_PMON_BEGIN(FAP4KE_PMON_ID_IUDMA_XMIT);

    txdma = g_pEthTxDma[channel];

    if(txdma->txFreeBds == 0 ) return 0;   /* No free tx BDs. Return Fail */

    txIndex = txdma->txTailIndex;

#if (defined(CONFIG_BCM96816) && defined(DBL_DESC))
    if(param1 != -1)
    {
        /* There are no other fields in the control, so keep it simple */
        txdma->txBds[txIndex].control = param1;
    }
#endif

    dmaDesc.length = len;

    /* Decrement total BD count */
    txdma->txFreeBds--;

    txdma->pKeyPtr[txIndex]   = key;
#if defined(CONFIG_BCM_FAP) || defined(CONFIG_BCM_FAP_MODULE)
    /* TxSource & TxAddr not required in non-FAP applications */ 
    txdma->pTxSource[txIndex] = bufSource;
    txdma->pTxAddress[txIndex] = (uint32)pBuf;
#endif
    
    /* Note that the Tx BD has only 2 bits for priority. This means only one
       the first 4 egress queues can be selected using this priority. */
    dmaDesc.status = dmaStatus;
    txBd = &txdma->txBds[txIndex];

    /* advance BD pointer to next in the chain. */
    if (txIndex == (NR_TX_BDS - 1))
    {
        dmaDesc.status = dmaDesc.status | DMA_WRAP;
        txdma->txTailIndex = 0;
#if defined(ENABLE_BCMPKTDMA_IUDMA_ERROR_CHECKING)
        BCM_ENET_TX_DEBUG("Tx BD: dma_status: 0x%04x \n", dmaDesc.status);
#endif
    }
    else
    {
        txdma->txTailIndex++;
#if defined(ENABLE_BCMPKTDMA_IUDMA_ERROR_CHECKING)
        BCM_ENET_TX_DEBUG("Tx BD: dma_status: 0x%04x \n", dmaDesc.status);
#endif
    }

    txBd->address = (uint32)VIRT_TO_PHY(pBuf);
    txBd->word0 = dmaDesc.word0;

#if defined(ENABLE_BCMPKTDMA_IUDMA_ERROR_CHECKING)
    BCM_ENET_TX_DEBUG("key: 0x%08x\n", (int)pNBuff);
    BCM_ENET_TX_DEBUG("TX BD: address=0x%08x\n", (int)VIRT_TO_PHY(pBuf) );
    BCM_ENET_TX_DEBUG("Tx BD: length=%u\n", len);
    BCM_ENET_TX_DEBUG("Tx BD: word0=0x%04x \n", dmaDesc.word0);

    BCM_ENET_TX_DEBUG("Enabling Tx DMA \n");
#endif

    /* Enable DMA for this channel */
    if(txdma->txEnabled)
        /* Do not reenable if Host MIPs has shut the interface down */
        txdma->txDma->cfg = DMA_ENABLE;

    FAP4KE_IUDMA_PMON_END(FAP4KE_PMON_ID_IUDMA_XMIT);

    return 1;
}

/* --------------------------------------------------------------------------
    Name: bcmPktDma_EthXmitNoCheck
 Purpose: Xmit an NBuff; not necessary to check for space available.
        : Already done by call to bcmPktDma_EthXmitAvailable.
   Notes: param1 = gemid;   param2 = port_id; param3 = egress_queue 
  Return: 1 on success; 0 otherwise
-------------------------------------------------------------------------- */
static inline int bcmPktDma_EthXmitNoCheck_Iudma(int channel, uint8 *pBuf, uint16 len,
                                          int bufSource, uint16 dmaStatus, uint32 key,
                                          int param1)
{
    BcmPktDma_LocalEthTxDma *  txdma;
    DmaDesc          dmaDesc;
#if (defined(CONFIG_BCM96816) && defined(DBL_DESC))
    volatile DmaDesc16 *txBd;
#else
    volatile DmaDesc *  txBd;
#endif
    int                 txIndex;
    
    FAP4KE_IUDMA_PMON_DECLARE();
    FAP4KE_IUDMA_PMON_BEGIN(FAP4KE_PMON_ID_IUDMA_XMIT);

    txdma = g_pEthTxDma[channel];

    txIndex = txdma->txTailIndex;

#if (defined(CONFIG_BCM96816) && defined(DBL_DESC))
    if(param1 != -1)
    {
        /* There are no other fields in the control, so keep it simple */
        txdma->txBds[txIndex].control = param1;
    }
#endif

    dmaDesc.length = len;

    /* Decrement total BD count */
    txdma->txFreeBds--;

    txdma->pKeyPtr[txIndex]   = key;
#if defined(CONFIG_BCM_FAP) || defined(CONFIG_BCM_FAP_MODULE)
    /* TxSource & TxAddr not required in non-FAP applications */ 
    txdma->pTxSource[txIndex] = bufSource;
    txdma->pTxAddress[txIndex] = (uint32)pBuf;
#endif
    
    /* Note that the Tx BD has only 2 bits for priority. This means only one
       the first 4 egress queues can be selected using this priority. */
    dmaDesc.status = dmaStatus;
    txBd = &txdma->txBds[txIndex];

    /* advance BD pointer to next in the chain. */
    if (txIndex == (NR_TX_BDS - 1))
    {
        dmaDesc.status = dmaDesc.status | DMA_WRAP;
        txdma->txTailIndex = 0;
#if defined(ENABLE_BCMPKTDMA_IUDMA_ERROR_CHECKING)
        BCM_ENET_TX_DEBUG("Tx BD: dma_status: 0x%04x \n", dmaDesc.status);
#endif
    }
    else
    {
        txdma->txTailIndex++;
#if defined(ENABLE_BCMPKTDMA_IUDMA_ERROR_CHECKING)
        BCM_ENET_TX_DEBUG("Tx BD: dma_status: 0x%04x \n", dmaDesc.status);
#endif
    }

    txBd->address = (uint32)VIRT_TO_PHY(pBuf);
    txBd->word0 = dmaDesc.word0;

#if defined(ENABLE_BCMPKTDMA_IUDMA_ERROR_CHECKING)
    BCM_ENET_TX_DEBUG("key: 0x%08x\n", (int)pNBuff);
    BCM_ENET_TX_DEBUG("TX BD: address=0x%08x\n", (int)VIRT_TO_PHY(pBuf) );
    BCM_ENET_TX_DEBUG("Tx BD: length=%u\n", len);
    BCM_ENET_TX_DEBUG("Tx BD: word0=0x%04x \n", dmaDesc.word0);

    BCM_ENET_TX_DEBUG("Enabling Tx DMA \n");
#endif

    /* Enable DMA for this channel */
    if(txdma->txEnabled)
        /* Do not reenable if Host MIPs has shut the interface down */
        txdma->txDma->cfg = DMA_ENABLE;

    FAP4KE_IUDMA_PMON_END(FAP4KE_PMON_ID_IUDMA_XMIT);

    return 1;
}

/* --------------------------------------------------------------------------
    Name: bcmPktDma_XtmXmit
 Purpose: Xmit an NBuff
   Notes: param1 = gemid;   param2 = port_id; param3 = egress_queue 
  Return: 1 on success; 0 otherwise
-------------------------------------------------------------------------- */
static inline int bcmPktDma_XtmXmit_Iudma(int channel, uint8 *pBuf, uint16 len,
                                          int bufSource, uint16 dmaStatus, uint32 key,
                                          int param1)
{
    BcmPktDma_LocalXtmTxDma *txdma;
    DmaDesc                  dmaDesc;
    volatile DmaDesc        *txBd;
    int                      txIndex;
    
    //FAP4KE_IUDMA_PMON_DECLARE();
    //FAP4KE_IUDMA_PMON_BEGIN(FAP4KE_PMON_ID_IUDMA_XMIT);

    txdma = g_pXtmTxDma[channel];

    if (txdma->txFreeBds == 0) return 0;   /* No free tx BDs. Return Fail */

    txIndex = txdma->txTailIndex;

    dmaDesc.length = len;

    /* Decrement total BD count */
    txdma->txFreeBds--;
    txdma->ulNumTxBufsQdOne++;
#if !defined(CONFIG_BCM96816) && !defined(CONFIG_BCM63XX_CPU_6362)
       // FIXME - Which chip uses more then one TX queue?
    g_pXtmGlobalInfo->ulNumTxBufsQdAll++;
#endif

    txdma->pKeyPtr[txIndex]   = key;
#if defined(CONFIG_BCM_FAP) || defined(CONFIG_BCM_FAP_MODULE)
    /* TxSource & TxAddr not required in non-FAP applications */ 
    txdma->pTxSource[txIndex] = bufSource;
    txdma->pTxAddress[txIndex] = (uint32)pBuf;
#endif
    
    /* Note that the Tx BD has only 2 bits for priority. This means only one
       the first 4 egress queues can be selected using this priority. */
    dmaDesc.status = dmaStatus;

    txBd = &txdma->txBds[txIndex];

    /* advance BD pointer to next in the chain. */
    if (txIndex == (NR_TX_BDS - 1))
    {
        dmaDesc.status = dmaDesc.status | DMA_WRAP;
        txdma->txTailIndex = 0;
#if defined(ENABLE_BCMPKTDMA_IUDMA_ERROR_CHECKING)
        BCM_XTM_TX_DEBUG("Tx BD: dma_status: %x\n", dmaDesc.status);
#endif
    }
    else
    {
        txdma->txTailIndex++;
#if defined(ENABLE_BCMPKTDMA_IUDMA_ERROR_CHECKING)
        BCM_XTM_TX_DEBUG("Tx BD: dma_status: %x idx: %d\n", dmaDesc.status, txdma->txTailIndex);
#endif
    }

    txBd->address = (uint32)VIRT_TO_PHY(pBuf);
    txBd->word0 = dmaDesc.word0;


#if defined(ENABLE_BCMPKTDMA_IUDMA_ERROR_CHECKING)
    BCM_XTM_TX_DEBUG("key: 0x%08x\n", (int)key);
    BCM_XTM_TX_DEBUG("TX BD: address=0x%08x\n", (int)VIRT_TO_PHY(pBuf) );
    BCM_XTM_TX_DEBUG("Tx BD: length=%u\n", len);
    BCM_XTM_TX_DEBUG("Tx BD: word0=%ld \n", dmaDesc.word0);

    BCM_XTM_TX_DEBUG("Enabling Tx DMA \n\n");
#endif


    /* Enable DMA for this channel */
    if (txdma->txEnabled)
        txdma->txDma->cfg = DMA_ENABLE;

    //FAP4KE_IUDMA_PMON_END(FAP4KE_PMON_ID_IUDMA_XMIT);

    return 1;
}


static inline int bcmPktDma_EthXmitFreeCount_Iudma(int channel) 
{
    BcmPktDma_LocalEthTxDma *txdma = g_pEthTxDma[channel];

    return txdma->txFreeBds;
}

static inline int bcmPktDma_XtmXmitFreeCount_Iudma(int channel) 
{
    BcmPktDma_LocalXtmTxDma *txdma = g_pXtmTxDma[channel];

    return txdma->txFreeBds;
}

static inline int bcmPktDma_XtmRecvEnabled_Iudma(int channel) 
{
    BcmPktDma_LocalXtmRxDma *rxdma = g_pXtmRxDma[channel];

    return rxdma->rxEnabled;
}


/* Prototypes for interface */
/* IUDMA versions */
int	bcmPktDma_EthInitRxChan_Dqm( uint32 channel,
                                 uint32 bufDescrs,
                                 BcmPktDma_LocalEthRxDma *pEthRxDma);

int	bcmPktDma_EthInitTxChan_Dqm( uint32 channel,
                                 uint32 bufDescrs,
                                 BcmPktDma_LocalEthTxDma *pEthTxDma);
                                 
int bcmPktDma_EthInitRxChan_Iudma( uint32 channel,
                                   uint32 bufDescrs,
                                   BcmPktDma_LocalEthRxDma *pEthRxDma);

int bcmPktDma_EthInitTxChan_Iudma( uint32 channel,
                                   uint32 bufDescrs,
                                   BcmPktDma_LocalEthTxDma *pEthTxDma);

int bcmPktDma_XtmInitRxChan_Iudma( uint32 channel,
                                   uint32 bufDescrs,
                                   BcmPktDma_LocalXtmRxDma *pXtmRxDma);

int bcmPktDma_XtmInitRxChan_Dqm( uint32 channel,
                                 uint32 bufDescrs,
                                 BcmPktDma_LocalXtmRxDma *pXtmRxDma);

int bcmPktDma_XtmInitTxChan_Iudma( uint32 channel,
                                   uint32 bufDescrs,
                                   BcmPktDma_LocalXtmTxDma *pXtmTxDma);

int bcmPktDma_XtmInitTxChan_Dqm( uint32 channel,
                                   uint32 bufDescrs,
                                   BcmPktDma_LocalXtmTxDma *pXtmTxDma);

int bcmPktDma_XtmCreateDevice_Dqm(uint32 devId, uint32 encapType);
int bcmPktDma_XtmLinkUp_Dqm(uint32 devId, uint32 matchId);
  
int bcmPktDma_EthInit_Dqm( BcmPktDma_LocalEthRxDma **pEthRxDma,
                             BcmPktDma_LocalEthTxDma **pEthTxDma,
                             uint32 rxChannels,
                             uint32 txChannels,
                             uint32 rxBufDescs,
                             uint32 txBufDescs );
int	bcmPktDma_EthInit_Iudma( BcmPktDma_LocalEthRxDma **pEthRxDma,
                             BcmPktDma_LocalEthTxDma **pEthTxDma,
                             uint32 rxChannels,
                             uint32 txChannels,
                             uint32 rxBufDescs,
                             uint32 txBufDescs );

int     bcmPktDma_EthSelectRxIrq_Iudma(int channel);
int     bcmPktDma_XtmSelectRxIrq_Iudma(int channel);

void	bcmPktDma_XtmClrRxIrq_Iudma(int channel);

int     bcmPktDma_XtmRecvAvailable_Iudma(int channel);

uint32  bcmPktDma_EthRecv_Iudma(int channel, unsigned char **pBuf, int * pLen);
uint32  bcmPktDma_XtmRecv_Iudma(int channel, unsigned char **pBuf, int * pLen);

void    bcmPktDma_XtmFreeXmitBuf_Iudma(int channel, int index);

int     bcmPktDma_EthXmitAvailable_Iudma(int channel);
int     bcmPktDma_XtmXmitAvailable_Iudma(int channel);

int     bcmPktDma_EthXmit_Iudma(int channel, uint8 *pBuf, uint16 len, int bufSource, uint16 dmaStatus, uint32 key, int param1);
int     bcmPktDma_XtmXmit_Iudma(int channel, uint8 *pBuf, uint16 len, int bufSource, uint16 dmaStatus, uint32 key, int param1);

int     bcmPktDma_EthTxEnable_Iudma(int channel);
int     bcmPktDma_XtmTxEnable_Iudma(int channel);

int     bcmPktDma_EthTxDisable_Iudma(int channel);
int     bcmPktDma_XtmTxDisable_Iudma(int channel);

int     bcmPktDma_EthRxEnable_Iudma(int channel);
int     bcmPktDma_XtmRxEnable_Iudma(int channel);

int     bcmPktDma_EthRxDisable_Iudma(int channel);
int     bcmPktDma_XtmRxDisable_Iudma(int channel);

int     bcmPktDma_EthRxReEnable_Iudma(int channel);

/* DQM versions */
int     bcmPktDma_EthSelectRxIrq_Dqm(int channel);
int     bcmPktDma_XtmSelectRxIrq_Dqm(int channel);

void	bcmPktDma_EthClrRxIrq_Dqm(int channel);
void	bcmPktDma_XtmClrRxIrq_Dqm(int channel);

int     bcmPktDma_EthRecvAvailable_Dqm(int channel);
int     bcmPktDma_XtmRecvAvailable_Dqm(int channel);

uint32  bcmPktDma_EthRecv_Dqm(int channel, unsigned char **pBuf, int * pLen);
uint32  bcmPktDma_XtmRecv_Dqm(int channel, unsigned char **pBuf, int * pLen);

void    bcmPktDma_EthFreeRecvBuf_Dqm(int channel, unsigned char * pBuf);
void    bcmPktDma_XtmFreeRecvBuf_Dqm(int channel, unsigned char * pBuf);

void    bcmPktDma_EthFreeXmitBuf_Dqm(int channel, int index);
void    bcmPktDma_XtmFreeXmitBuf_Dqm(int channel, int index);

int     bcmPktDma_EthXmitAvailable_Dqm(int channel) ;
int     bcmPktDma_XtmXmitAvailable_Dqm(int channel) ;

int     bcmPktDma_EthXmit_Dqm(int channel, uint8 *pBuf, uint16 len, int bufSource, uint16 dmaStatus, uint32 key, int param1);
void    bcmPktDma_EthXmitNoCheck_Dqm(int channel, uint8 *pBuf, uint16 len, int bufSource, uint16 dmaStatus,  uint32 key, int param1);

int     bcmPktDma_XtmXmit_Dqm(int channel, uint8 *pBuf, uint16 len, int bufSource, uint16 dmaStatus, uint32 key, int param1);

int     bcmPktDma_EthTxEnable_Dqm(int channel);
int     bcmPktDma_XtmTxEnable_Dqm(int channel);

int     bcmPktDma_EthTxDisable_Dqm(int channel);
int     bcmPktDma_XtmTxDisable_Dqm(int channel);

int     bcmPktDma_EthRxEnable_Dqm(int channel);
int     bcmPktDma_XtmRxEnable_Dqm(int channel);

int     bcmPktDma_EthRxDisable_Dqm(int channel);
int     bcmPktDma_XtmRxDisable_Dqm(int channel);

BOOL    bcmPktDma_EthFreeXmitBufGet_Dqm(int channel, uint32 *pKey, 
                                        int *pTxSource, uint32 *pAddr);
BOOL    bcmPktDma_XtmFreeXmitBufGet_Dqm(int channel, uint32 *pKey, 
                                        int *pTxSource, uint32 *pAddr);
int     bcmPktDma_EthRxReEnable_Dqm(int channel);

void bcm63xx_enet_dqmhandler(unsigned long channel);
void bcm63xx_enet_xmit_free_handler(unsigned long channel);

void bcm63xx_xtm_dqmhandler(unsigned long channel);
void bcm63xx_xtm_xmit_free_handler(unsigned long channel);

/* Used by both iudma and dqm versions */
#if (defined(CONFIG_BCM96816) && defined(DBL_DESC))
DmaDesc16 * bcmPktDma_EthAllocTxBds(int numBds);
#else
DmaDesc * bcmPktDma_EthAllocTxBds(int numBds);
#endif

DmaDesc * bcmPktDma_EthAllocRxBds(int channel, int numBds);

DmaDesc * bcmPktDma_XtmAllocTxBds(int numBds, int totalBds);
DmaDesc * bcmPktDma_XtmAllocRxBds(int numBds, int totalBds);


#endif  /* defined(__PKTDMA_H_INCLUDED__) */
