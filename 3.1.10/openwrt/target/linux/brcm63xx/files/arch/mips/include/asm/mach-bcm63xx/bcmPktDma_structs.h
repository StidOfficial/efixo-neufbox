#ifndef __PKTDMASTRUCTS_H_INCLUDED__
#define __PKTDMASTRUCTS_H_INCLUDED__

#include <bcm_map.h>

typedef struct BcmPktDma_LocalEthRxDma
{
   int      enetrxchannel_isr_enable;
   volatile DmaChannelCfg *rxDma;
   volatile DmaDesc *rxBds;
   int      rxAssignedBds;
   int      rxHeadIndex;
   int      rxTailIndex;
   int      numRxBds;
   volatile int  rxEnabled;
} BcmPktDma_LocalEthRxDma;
                        
typedef struct BcmPktDma_LocalEthTxDma
{
   int      txFreeBds; /* # of free transmit bds */
   int      txHeadIndex;
   int      txTailIndex;
   volatile DmaChannelCfg *txDma; /* location of transmit DMA register set */
#if (defined(CONFIG_BCM96816) && defined(DBL_DESC))
    volatile DmaDesc16 *txBds; /* Memory location of tx Dma BD ring */
#else
    volatile DmaDesc *txBds;   /* Memory location of tx Dma BD ring */
#endif
   uint32   *   pKeyPtr;
   int      *   pTxSource;   /* HOST_VIA_LINUX, HOST_VIA_DQM, FAP_XTM_RX, FAP_ETH_RX per BD */
   uint32   *   pTxAddress;  /* Shadow copy of virtual TxBD address to be used in free of tx buffer */
   volatile int txEnabled;
} BcmPktDma_LocalEthTxDma;

typedef struct BcmPktDma_LocalXtmRxDma
{
   int                     xtmrxchannel_isr_enable;
   volatile DmaChannelCfg *rxDma;
   volatile DmaDesc       *rxBds;
   int                     rxAssignedBds;
   int                     rxHeadIndex;
   int                     rxTailIndex;
   int                     numRxBds;
   volatile int            rxEnabled;
} BcmPktDma_LocalXtmRxDma;

typedef struct BcmPktDma_LocalXtmTxDma
{
    UINT32 ulPort;
    UINT32 ulPtmPriority;
    UINT32 ulSubPriority;
    UINT32 ulQueueSize;
    UINT32 ulDmaIndex;
    UINT32 ulNumTxBufsQdOne;

    int                     txFreeBds; 
    int                     txHeadIndex;
    int                     txTailIndex;
    volatile DmaChannelCfg *txDma;
    volatile DmaDesc       *txBds;
    uint32                 *pKeyPtr;
    int                    *pTxSource;
    uint32                 *pTxAddress;
    volatile int            txEnabled;
} BcmPktDma_LocalXtmTxDma;


#endif
