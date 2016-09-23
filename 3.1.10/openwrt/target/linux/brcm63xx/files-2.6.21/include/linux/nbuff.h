#ifndef __NBUFF_H_INCLUDED__
#define __NBUFF_H_INCLUDED__

/*
<:copyright-gpl

 Copyright 2009 Broadcom Corp. All Rights Reserved.

 This program is free software; you can distribute it and/or modify it
 under the terms of the GNU General Public License (Version 2) as
 published by the Free Software Foundation.

 This program is distributed in the hope it will be useful, but WITHOUT
 ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 for more details.

 You should have received a copy of the GNU General Public License along
 with this program; if not, write to the Free Software Foundation, Inc.,
 59 Temple Place - Suite 330, Boston MA 02111-1307, USA.

:>
*/

/*
 *******************************************************************************
 *
 * File Name  : nbuff.h
 * Description: Definition of a network buffer to support various forms of
 *      network buffer, to include Linux socket buff (SKB), lightweight
 *      fast kernel buff (FKB), BRCM Free Pool buffer (FPB), and traffic
 *      generator support buffer (TGB)
 *
 *      nbuff.h may also be used to provide an interface to common APIs 
 *      available on other OS (in particular BSD style mbuf).
 *
 * Common APIs provided: pushing, pulling, reading, writing, cloning, freeing
 *
 * Implementation Note:
 *
 * One may view NBuff as a base class from which other buff types are derived.
 * Examples of derived network buffer types are sk_buff, fkbuff, fpbuff, tgbuff
 *
 * A pointer to a buffer is converted to a pointer to a special (derived) 
 * network buffer type by encoding the type into the least significant 2 bits
 * of a word aligned buffer pointer. pBuf points to the real network 
 * buffer and pNBuff refers to pBuf ANDed with the Network Buffer Type.
 * C++ this pointer to a virtual class (vtable based virtual function thunks).
 *
 * Thunk functions to redirect the calls to the appropriate buffer type, e.g.
 * skb or fkb uses the Network Buffer Pointer type information.
 *
 * This file also implements the Fast Kernel Buffer API. The fast kernel buffer
 * carries a minimal context of the received buffer and associated buffer
 * recycling information.
 *
 ******************************************************************************* */

#include <linux/autoconf.h>
#include <linux/types.h>            /* include ISO C99 inttypes.h             */
#include <linux/skbuff.h>           /* include corresponding BSD style mbuf   */
#include <linux/blog.h>

/* Engineering Constants for Fast Kernel Buffer Global Pool (used for clones) */
#define SUPPORT_FKB_EXTEND
#define FKB_EXTEND_SIZE_ENGG        32      /* Number of FkBuf_t per extension*/
#define FKB_EXTEND_MAX_ENGG         16      /* Maximum extensions allowed     */

/* Conditional compile of inline fkb functions */
#define CC_CONFIG_FKB_FN_INLINE
#ifdef CC_CONFIG_FKB_FN_INLINE
#define DEFINE_FKB_FN(fn_signature, body)                                      \
static inline fn_signature { body; }
#else
#define DEFINE_FKB_FN(fn_signature, body)                                      \
extern fn_signature;
#endif

/* LAB ONLY: Design development */
// #define CC_CONFIG_FKB_COLOR
// #define CC_CONFIG_FKB_DEBUG
#if defined(CC_CONFIG_FKB_DEBUG)
#define fkb_dbg(fmt, arg...) \
    printk( "FKB %s :" fmt "\n", __FUNCTION__, ##arg )
#else
#define fkb_dbg(fmt, arg...)      do {} while(0)
#endif

/*
 * For BSD style mbuf with FKB : 
 * generate nbuff.h by replacing "SKBUFF" to "BCMMBUF", and,
 * use custom arg1 and arg2 instead of mark and priority, respectively.
 */

struct sk_buff;
struct blog_t;
struct net_device;
typedef int (*HardStartXmitFuncP) (struct sk_buff *skb,
                                   struct net_device *dev);

struct fkbuff;
typedef struct fkbuff FkBuff_t;

/* virtual network buffer pointer to SKB|FPB|TGB|FKB  */
typedef void * pNBuff_t;
#define PNBUFF_NULL     ((pNBuff_t)NULL)

#define MUST_BE_ZERO            0
typedef enum NBuffPtrType
{
    SKBUFF_PTR = MUST_BE_ZERO,      /* Default Linux networking socket buffer */
    FPBUFF_PTR,                     /* Experimental BRCM IuDMA freepool buffer*/
    TGBUFF_PTR,                     /* LAB Traffic generated network buffer   */
    FKBUFF_PTR,                     /* Lightweight fast kernel network buffer */
    /* Do not add new ptr types */
} NBuffPtrType_t;

                                    /* 2lsbits in pointer encode NbuffType_t  */
#define NBUFF_TYPE_MASK             0x3u
#define NBUFF_PTR_MASK              (~NBUFF_TYPE_MASK)
#define NBUFF_PTR_TYPE(pNBuff)      ((uint32_t)(pNBuff) & NBUFF_TYPE_MASK)


#define IS_SKBUFF_PTR(pNBuff)       ( NBUFF_PTR_TYPE(pNBuff) == SKBUFF_PTR )
#define IS_FPBUFF_PTR(pNBuff)       ( NBUFF_PTR_TYPE(pNBuff) == FPBUFF_PTR )
#define IS_TGBUFF_PTR(pNBuff)       ( NBUFF_PTR_TYPE(pNBuff) == TGBUFF_PTR )
#define IS_FKBUFF_PTR(pNBuff)       ( NBUFF_PTR_TYPE(pNBuff) == FKBUFF_PTR )

/*
 *------------------------------------------------------------------------------
 *
 * Pointer conversion between pBuf and pNBuff encoded buffer pointers
 * uint8_t * pBuf;
 * pNBuff_t  pNBuff;
 * ...
 * // overlays FKBUFF_PTR into pointer to build a virtual pNBuff_t
 * pNBuff = PBUF_2_PNBUFF(pBuf,FKBUFF_PTR);
 * ...
 * // extracts a real uint8_t * from a virtual pNBuff_t
 * pBuf = PNBUFF_2_PBUF(pNBuff);
 *
 *------------------------------------------------------------------------------
 */
#define PBUF_2_PNBUFF(pBuf,realType) \
            ( (pNBuff_t) ((uint32_t)(pBuf)   | (uint32_t)(realType)) )
#define PNBUFF_2_PBUF(pNBuff)       \
            ( (uint8_t*) ((uint32_t)(pNBuff) & (uint32_t)NBUFF_PTR_MASK) )

#if (MUST_BE_ZERO != 0)
#error  "Design assumption SKBUFF_PTR == 0"
#endif
#define PNBUFF_2_SKBUFF(pNBuff)     ((struct sk_buff *)(pNBuff))

#define SKBUFF_2_PNBUFF(skb)        ((pNBuff_t)(skb)) /* see MUST_BE_ZERO */
#define FKBUFF_2_PNBUFF(fkb)        PBUF_2_PNBUFF(fkb,FKBUFF_PTR)

/*
 *------------------------------------------------------------------------------
 *
 * Cast from/to virtual "pNBuff_t" to/from real typed pointers
 *
 *  pNBuff_t pNBuff2Skb, pNBuff2Fkb;    // "void *" with NBuffPtrType_t
 *  struct sk_buff * skb_p;
 *  struct fkbuff  * fkb_p;
 *  ...
 *  pNBuff2Skb = CAST_REAL_TO_VIRT_PNBUFF(skb_p,SKBUFF_PTR);
 *  pNBuff2Fkb = CAST_REAL_TO_VIRT_PNBUFF(fkb_p,FKBUFF_PTR);
 *  ...
 *  skb_p = CAST_VIRT_TO_REAL_PNBUFF(pNBuff2Skb, struct sk_buff *);
 *  fkb_p = CAST_VIRT_TO_REAL_PNBUFF(pNBuff2Fkb, struct fkbuff  *);
 * or,
 *  fkb_p = PNBUFF_2_FKBUFF(pNBuff2Fkb);  
 *------------------------------------------------------------------------------
 */

#define CAST_REAL_TO_VIRT_PNBUFF(pRealNBuff,realType) \
            ( (pNBuff_t) (PBUF_2_PNBUFF((pRealNBuff),(realType))) )

#define CAST_VIRT_TO_REAL_PNBUFF(pVirtNBuff,realType) \
            ( (realType) PNBUFF_2_PBUF(pVirtNBuff) )

#define PNBUFF_2_FKBUFF(pNBuff) CAST_VIRT_TO_REAL_PNBUFF((pNBuff),struct fkbuff*)

/*
 *------------------------------------------------------------------------------
 *  FKB: Fast Kernel Buffers placed directly into Rx DMA Buffer
 *  May be used ONLY for common APIs such as those available in BSD-Style mbuf
 *------------------------------------------------------------------------------
 */

struct fkbuff
{
    union {
        FkBuff_t  * list;           /* SLL of free FKBs for cloning           */
        FkBuff_t  * master_p;       /* Clone FKB to point to master FKB       */
        atomic_t  users;            /* (private) # of references to FKB       */
    };
    union {
        struct blog_t *blog_p;      /* Pointer to a blog                      */
        uint8_t   * dirty;          /* Pointer to end of L2 R/W dirty         */
    };
    uint8_t       * data;           /* Pointer to packet data                 */
    uint32_t      len;              /* Packet length                          */

    uint32_t      mark;             /* Custom arg1, e.g. tag or mark field    */
    uint32_t      priority;         /* Custom arg2, packet priority, tx info  */
    RecycleFuncP  recycle_hook;     /* Nbuff recycle handler                  */
    uint32_t      recycle_context;  /* Rx network device/channel or pool      */

} __packed ____cacheline_aligned;   /* 2 cache lines wide */

#define FKB_NULL                    ((FkBuff_t *)NULL)
#define IS_FKB_CLONE(fkb_p)         ((uint32_t)((fkb_p)->master_p) > 0x0FFFFFFF)

/*
 *------------------------------------------------------------------------------
 * Placement of a FKB object in the Rx DMA buffer:
 *
 * RX DMA Buffer:   |----- FKB ----|--- reserve headroom ---|---...... 
 *                  ^              ^                        ^
 *                pFkb           pHead                    pData
 *                pBuf
 *------------------------------------------------------------------------------
 */
#define PFKBUFF_PHEAD_OFFSET        sizeof(FkBuff_t)
#define PFKBUFF_TO_PHEAD(pFkb)      ((uint8_t*)((FkBuff_t*)(pFkb) + 1))
#define PDATA_TO_PFKBUFF(pData,headroom)    \
            (FkBuff_t *)((uint8_t*)(pData)-(headroom)-PFKBUFF_PHEAD_OFFSET)
#define PFKBUFF_TO_PDATA(pFkb,headroom)     \
            (uint8_t*)((uint8_t*)(pFkb) + PFKBUFF_PHEAD_OFFSET + (headroom))

extern FkBuff_t * fkb_alloc(void);
extern void fkb_free(FkBuff_t * fkb_p);

/*
 * Pre-initialization of FKB object that is placed into rx buffer descriptors
 * when they are created. FKB objects preceeds the reserved headroom.
 */
static inline void fkb_preinit(uint8_t * pBuf, RecycleFuncP recycle_hook,
                               uint32_t recycle_context)
{
    FkBuff_t * fkb_p = (FkBuff_t *)pBuf;
    fkb_p->recycle_hook = recycle_hook;         /* never modified */
    fkb_p->recycle_context = recycle_context;   /* never modified */

    fkb_p->data = fkb_p->dirty = (uint8_t*)NULL;
    fkb_p->len  = fkb_p->mark  = fkb_p->priority = 0;
    atomic_set(&fkb_p->users, 0);
}

/* Clear any references to an FKB */
static inline void _fkb_clr(FkBuff_t * fkb_p)
{
    atomic_set(&fkb_p->users, 0);
}
DEFINE_FKB_FN( void fkb_clr(FkBuff_t * fkb_p), _fkb_clr(fkb_p) )

/* Initialize the FKB context for a received packet */
static inline FkBuff_t * _fkb_init(uint8_t * pBuf, uint32_t headroom,
                                   uint8_t * pData, uint32_t len)
{
    FkBuff_t * fkb_p = PDATA_TO_PFKBUFF(pBuf, headroom);
    fkb_dbg("fkb_p<0x%08x> pBuf<0x%08x> headroom<%u> pData<0x%08x> len<%d>",
            (int)fkb_p, (int)pBuf, (int)headroom, (int)pData, len);
    fkb_p->data      = pData;
    fkb_p->len       = len;
    fkb_p->blog_p    = BLOG_NULL;
    atomic_set(&fkb_p->users, 1);

    return fkb_p;
}
DEFINE_FKB_FN( 
    FkBuff_t * fkb_init(uint8_t * pBuf, uint32_t headroom,
                        uint8_t * pData, uint32_t len),
    return _fkb_init(pBuf, headroom, pData, len) )

/* Initialize the FKB context for a received packet, specifying recycle queue */
static inline FkBuff_t * _fkb_qinit(uint8_t * pBuf, uint32_t headroom,
                    uint8_t * pData, uint32_t len, uint32_t qcontext)
{
    FkBuff_t * fkb_p = PDATA_TO_PFKBUFF(pBuf, headroom);
    fkb_dbg("fkb_p<0x%08x> pBuf<0x%08x> headroom<%u>"
            " pData<0x%08x> len<%d> context<0x%08x>",
            (int)fkb_p, (int)pBuf, headroom, (int)pData, len, qcontext);
    fkb_p->data      = pData;
    fkb_p->len       = len;
    fkb_p->blog_p    = BLOG_NULL;
    fkb_p->recycle_context = qcontext;
    atomic_set(&fkb_p->users, 1);

    return fkb_p;
}
DEFINE_FKB_FN(
    FkBuff_t * fkb_qinit(uint8_t * pBuf, uint32_t headroom,
                         uint8_t * pData, uint32_t len, uint32_t qcontext),
    return _fkb_qinit(pBuf, headroom, pData, len, qcontext) )

/* Release any associated blog */
void blog_put(struct blog_t * blog_p);
static inline void _fkb_release(FkBuff_t * fkb_p)
{
    fkb_dbg("fkb_p<0x%08x> fkb_p->blog_p<0x%08x>",
            (int)fkb_p, (int)fkb_p->blog_p);
    if (fkb_p->blog_p != BLOG_NULL)
        blog_put(fkb_p->blog_p);
    fkb_p->blog_p = BLOG_NULL;
    atomic_set(&fkb_p->users, 0);
}
DEFINE_FKB_FN( void fkb_release(FkBuff_t * fkb_p), _fkb_release(fkb_p) )

static inline int _fkb_headroom(const FkBuff_t *fkb_p)
{
    return (int)( (uint32_t)(fkb_p->data) - (uint32_t)(fkb_p+1) );
}
DEFINE_FKB_FN( int fkb_headroom(const FkBuff_t *fkb_p),
               return _fkb_headroom(fkb_p) )

/* Prepare space for data at head of buffer pointed by FKB */
static inline uint8_t * _fkb_push(FkBuff_t * fkb_p, uint32_t len)
{
    fkb_p->len  += len;
    fkb_p->data -= len;
    return fkb_p->data;
}
DEFINE_FKB_FN( uint8_t * fkb_push(FkBuff_t * fkb_p, uint32_t len),
               return _fkb_push(fkb_p, len) )

/* Delete data from head of buffer pointed by FKB */
static inline uint8_t * _fkb_pull(FkBuff_t * fkb_p, uint32_t len)
{
    fkb_p->len  -= len;
    fkb_p->data += len;
    return fkb_p->data;
}
DEFINE_FKB_FN( uint8_t * fkb_pull(FkBuff_t * fkb_p, uint32_t len),
               return _fkb_pull(fkb_p, len) )

/* Prepare space for data at tail of buffer pointed by FKB */
static inline uint8_t * _fkb_put(FkBuff_t * fkb_p, uint32_t len)
{
    uint8_t * tail = fkb_p->data + fkb_p->len; 
    fkb_p->len  += len;
    return tail;
}
DEFINE_FKB_FN( uint8_t * fkb_put(FkBuff_t * fkb_p, uint32_t len),
               return _fkb_put(fkb_p, len) )

static inline uint32_t _fkb_pad(FkBuff_t * fkb_p, uint32_t len)
{
    fkb_p->len  += len;
    return fkb_p->len;
}
DEFINE_FKB_FN( uint32_t fkb_pad(FkBuff_t * fkb_p, uint32_t len),
               return _fkb_pad(fkb_p, len) )


static inline uint32_t _fkb_len(FkBuff_t * fkb_p)
{
    return fkb_p->len;
}
DEFINE_FKB_FN( uint32_t fkb_len(FkBuff_t * fkb_p),
               return _fkb_len(fkb_p) )

static inline uint8_t * _fkb_data(FkBuff_t * fkb_p)
{
    return fkb_p->data;
}
DEFINE_FKB_FN( uint8_t * fkb_data(FkBuff_t * fkb_p),
               return _fkb_data(fkb_p) )

static inline struct blog_t * _fkb_blog(FkBuff_t * fkb_p)
{
    return fkb_p->blog_p;
}
DEFINE_FKB_FN( struct blog_t * fkb_blog(FkBuff_t * fkb_p),
               return _fkb_blog(fkb_p) )

/* Clone a Master FKB into a fkb from a pool */
static inline FkBuff_t * _fkb_clone(FkBuff_t * fkbM_p)
{
    FkBuff_t * fkbC_p;

    fkb_dbg(">> fkbM_p<0x%08x>", (int)fkbM_p);
    fkbC_p = fkb_alloc();         /* Allocate an FKB */

    if ( unlikely(fkbC_p != FKB_NULL) )
    {
        atomic_inc(&fkbM_p->users);
        fkbC_p->master_p   = fkbM_p;

        fkbC_p->data       = fkbM_p->data;
        fkbC_p->len        = fkbM_p->len;
    }

    fkb_dbg("<< fkbC_p<0x%08x>", (int)fkbC_p);
    return fkbC_p;       /* May be null */
}
DEFINE_FKB_FN( FkBuff_t * fkb_clone(FkBuff_t * fkbM_p),
               return _fkb_clone(fkbM_p) )


/*
 *------------------------------------------------------------------------------
 * Virtual accessors to common members of network kernel buffer
 *------------------------------------------------------------------------------
 */

#define __BUILD_NBUFF_SET_ACCESSOR( TYPE, MEMBER )                             \
static inline void nbuff_set_##MEMBER(pNBuff_t pNBuff, TYPE MEMBER) \
{                                                                              \
    void * pBuf = PNBUFF_2_PBUF(pNBuff);                                       \
    if ( IS_SKBUFF_PTR(pNBuff) )                                               \
        ((struct sk_buff *)pBuf)->MEMBER = MEMBER;                             \
    /* else if IS_FPBUFF_PTR, else if IS_TGBUFF_PTR */                         \
    else                                                                       \
        ((FkBuff_t *)pBuf)->MEMBER = MEMBER;                                   \
}

#define __BUILD_NBUFF_GET_ACCESSOR( TYPE, MEMBER )                             \
static inline TYPE nbuff_get_##MEMBER(pNBuff_t pNBuff)                         \
{                                                                              \
    void * pBuf = PNBUFF_2_PBUF(pNBuff);                                       \
    if ( IS_SKBUFF_PTR(pNBuff) )                                               \
        return (TYPE)(((struct sk_buff *)pBuf)->MEMBER);                       \
    /* else if IS_FPBUFF_PTR, else if IS_TGBUFF_PTR */                         \
    else                                                                       \
        return (TYPE)(((FkBuff_t *)pBuf)->MEMBER);                             \
}

/* Common accessor of base network buffer: */
__BUILD_NBUFF_SET_ACCESSOR(uint8_t *, data) 
__BUILD_NBUFF_SET_ACCESSOR(uint32_t, len) 
__BUILD_NBUFF_SET_ACCESSOR(uint32_t, mark)      /* Custom network buffer arg1 */
__BUILD_NBUFF_SET_ACCESSOR(uint32_t, priority)  /* Custom network buffer arg2 */

__BUILD_NBUFF_GET_ACCESSOR(uint8_t *, data)
__BUILD_NBUFF_GET_ACCESSOR(uint32_t, len)
__BUILD_NBUFF_GET_ACCESSOR(uint32_t, mark)      /* Custom network buffer arg1 */
__BUILD_NBUFF_GET_ACCESSOR(uint32_t, priority)  /* Custom network buffer arg2 */

static inline void * nbuff_get_context(pNBuff_t pNBuff,
                                     uint8_t ** data_p, uint32_t *len_p)
{
    void * pBuf = PNBUFF_2_PBUF(pNBuff);
    if ( pBuf == (void*) NULL )
        return pBuf;
    fkb_dbg(">> pNBuff<0x%08x>", (int)pNBuff);
    if ( IS_SKBUFF_PTR(pNBuff) )
    {
        *data_p     = ((struct sk_buff *)pBuf)->data;
        *len_p      = ((struct sk_buff *)pBuf)->len;
    }
    else
    {
        *data_p     = ((FkBuff_t *)pBuf)->data;
        *len_p      = ((FkBuff_t *)pBuf)->len;
    }
    fkb_dbg("<< pBuf<0x%08x> data_p<0x%08x>", (int)pBuf, (int)*data_p);
    return pBuf;
}

static inline void * nbuff_get_params(pNBuff_t pNBuff,
                                     uint8_t ** data_p, uint32_t *len_p,
                                     uint32_t * mark_p, uint32_t *priority_p)
{
    void * pBuf = PNBUFF_2_PBUF(pNBuff);
    if ( pBuf == (void*) NULL )
        return pBuf;
    fkb_dbg(">> pNBuff<0x%08x>", (int)pNBuff);
    if ( IS_SKBUFF_PTR(pNBuff) )
    {
        *data_p     = ((struct sk_buff *)pBuf)->data;
        *len_p      = ((struct sk_buff *)pBuf)->len;
        *mark_p     = ((struct sk_buff *)pBuf)->mark;
        *priority_p = ((struct sk_buff *)pBuf)->priority;
    }
    else
    {
        *data_p     = ((FkBuff_t *)pBuf)->data;
        *len_p      = ((FkBuff_t *)pBuf)->len;
        *mark_p     = ((FkBuff_t *)pBuf)->mark;
        *priority_p = ((FkBuff_t *)pBuf)->priority;
    }
    fkb_dbg("<< pBuf<0x%08x> data_p<0x%08x>", (int)pBuf, (int)*data_p);
    return pBuf;
}
    
/*
 *------------------------------------------------------------------------------
 * Virtual common functional apis of a network kernel buffer
 *------------------------------------------------------------------------------
 */

/* Make space at the start of a network buffer */
static inline uint8_t * nbuff_push(pNBuff_t pNBuff, uint32_t len)
{
    uint8_t * data;
    void * pBuf = PNBUFF_2_PBUF(pNBuff);
    fkb_dbg(">> pNBuff<0x%08x> pBuf<0x%08x> len<%d>",
              (int)pNBuff,(int)pBuf, len);
    if ( IS_SKBUFF_PTR(pNBuff) )
        data = skb_push(((struct sk_buff *)pBuf), len);
    /* else if IS_FPBUFF_PTR, else if IS_TGBUFF_PTR */
    else
        data = fkb_push((FkBuff_t*)pBuf, len);
    fkb_dbg("<< data<0x%08x> len<%u>", (int)data, len);
    return data;
}

/* Delete data from start of a network buffer */
static inline uint8_t * nbuff_pull(pNBuff_t pNBuff, uint32_t len)
{
    uint8_t * data;
    void * pBuf = PNBUFF_2_PBUF(pNBuff);
    fkb_dbg(">> pNBuff<0x%08x> pBuf<0x%08x> len<%d>",
            (int)pNBuff,(int)pBuf, len);
    if ( IS_SKBUFF_PTR(pNBuff) )
        data = skb_pull(((struct sk_buff *)pBuf), len);
    /* else if IS_FPBUFF_PTR, else if IS_TGBUFF_PTR */
    else
        data = fkb_pull((FkBuff_t *)pBuf, len);
    fkb_dbg("<< data<0x%08x> len<%u>", (int)data, len);
    return data;
}

static inline uint8_t * nbuff_put(pNBuff_t pNBuff, uint32_t len)
{
    uint8_t * tail;
    void * pBuf = PNBUFF_2_PBUF(pNBuff);
    fkb_dbg(">> pNBuff<0x%08x> pBuf<0x%08x> len<%d>",
            (int)pNBuff,(int)pBuf, len);
    if ( IS_SKBUFF_PTR(pNBuff) )
        tail = skb_put(((struct sk_buff *)pBuf), len);
    /* else if IS_FPBUFF_PTR, else if IS_TGBUFF_PTR */
    else
        tail = fkb_put((FkBuff_t *)pBuf, len);
    fkb_dbg("<< tail<0x%08x> len<%u>", (int)tail, len);
    return tail;
}

/* Free|Recycle a network buffer and associated data */
extern void dev_kfree_skb_any(struct sk_buff *skb);
static inline void nbuff_free(pNBuff_t pNBuff)
{
    void * pBuf;
    pBuf = PNBUFF_2_PBUF(pNBuff);
    fkb_dbg(">> pNBuff<0x%08x> pBuf<0x%08x>", (int)pNBuff,(int)pBuf);
    if ( IS_SKBUFF_PTR(pNBuff) )
        dev_kfree_skb_any((struct sk_buff *)pBuf);
    /* else if IS_FPBUFF_PTR, else if IS_TGBUFF_PTR */
    else
        fkb_free(pBuf);
    fkb_dbg("<<");
}

/* OS Specific Section Begin */
#if defined(__KERNEL__)     /* Linux MIPS Cache Specific */
/*
 *------------------------------------------------------------------------------
 * common cache operations:
 *
 * - addr is rounded down to the cache line
 * - end is rounded up to cache line.
 *
 * - if ((addr == end) and (addr was cache aligned before rounding))
 *       no operation is performed.
 *   else
 *       flush data cache line UPTO but NOT INCLUDING rounded up end.
 *
 * Note:
 * if before rounding, (addr == end)  AND addr was not cache aligned,
 *      we would flush at least one line.
 *
 * Uses: L1_CACHE_BYTES
 *------------------------------------------------------------------------------
 */
#include <asm/cache.h>
#include <asm/r4kcache.h>

/*
 * Macros to round down and up, an address to a cachealigned address
 */
#define ADDR_ALIGN_DN(addr, align)  ( (addr) & ~((align) - 1) )
#define ADDR_ALIGN_UP(addr, align)  ( ((addr) + (align) - 1) & ~((align) - 1) )

/*
 *------------------------------------------------------------------------------
 * Writeback flush, then invalidate a region demarcated by addr to end.
 * Cache line following rounded up end is not flushed.
 *------------------------------------------------------------------------------
 */
static inline void cache_flush_region(void *addr, void *end)
{
    unsigned long a = ADDR_ALIGN_DN( (unsigned long)addr, L1_CACHE_BYTES );
    unsigned long e = ADDR_ALIGN_UP( (unsigned long)end, L1_CACHE_BYTES );
    while ( a < e )
    {
        flush_dcache_line(a);   /* Hit_Writeback_Inv_D */
        a += L1_CACHE_BYTES;    /* next cache line base */
    }
}

/*
 *------------------------------------------------------------------------------
 * Writeback flush, then invalidate a region given an address and a length.
 * The demarcation end is computed by applying length to address before
 * rounding down address. End is rounded up.
 * Cache line following rounded up end is not flushed.
 *------------------------------------------------------------------------------
 */
static inline void cache_flush_len(void *addr, int len)
{
    unsigned long a = ADDR_ALIGN_DN( (unsigned long)addr, L1_CACHE_BYTES );
    unsigned long e = ADDR_ALIGN_UP( ((unsigned long)addr + len),
                                     L1_CACHE_BYTES );
    while ( a < e )
    {
        flush_dcache_line(a);   /* Hit_Writeback_Inv_D */
        a += L1_CACHE_BYTES;    /* next cache line base */
    }
}

#endif  /* defined(__KERNEL__) Linux MIPS Cache Specific */
/* OS Specific Section End */


static inline void nbuff_flush(pNBuff_t pNBuff, uint8_t * data, int len)
{
    fkb_dbg(">> pNBuff<0x%08x> data<0x%08x> len<%d>",
            (int)pNBuff, (int)data, len);
    if ( IS_SKBUFF_PTR(pNBuff) )
        cache_flush_len(data, len);
    else
    {   /* Flush on L1 dirty cache lines */
        FkBuff_t * fkb_p = (FkBuff_t *)PNBUFF_2_PBUF(pNBuff);
        cache_flush_region(data, fkb_p->dirty);
    }
    fkb_dbg("<<");
}

static inline void u16cpy( void * dst_p, const void * src_p, uint32_t bytes )
{
    uint16_t * dst16_p = (uint16_t*)dst_p;
    uint16_t * src16_p = (uint16_t*)src_p;
    do { // assuming: (bytes % sizeof(uint16_t) == 0 !!!
        *dst16_p++ = *src16_p++;
    } while ( bytes -= sizeof(uint16_t) );
}

static inline int u16cmp( void * dst_p, const void * src_p,
                          uint32_t bytes )
{
    uint16_t * dst16_p = (uint16_t*)dst_p;
    uint16_t * src16_p = (uint16_t*)src_p;
    do { // assuming: (bytes % sizeof(uint16_t) == 0 !!!
        if ( *dst16_p++ != *src16_p++ )
            return -1;
    } while ( bytes -= sizeof(uint16_t) );

    return 0;
}

#ifdef DUMP_DATA
/* dumpHexData dump out the hex base binary data */
static inline void dumpHexData(uint8_t *pHead, uint32_t len)
{
    uint32_t i;
    uint8_t *c = pHead;
    for (i = 0; i < len; ++i) {
        if (i % 16 == 0)
            printk("\n");
        printk("0x%02X, ", *c++);
    }
    printk("\n");
}

inline void dump_pkt(const char * fname, uint8_t * pBuf, uint32_t len)
{
    int dump_len = ( len < 64) ? len : 64;
    printk("%s: data<0x%08x> len<%u>", fname, (int)pBuf, len);
    dumpHexData(pBuf, dump_len);
    cache_flush_len((void*)pBuf, dump_len);
}
#define DUMP_PKT(pBuf,len)      dump_pkt(__FUNCTION__, (pBuf), (len))
#else   /* !defined(DUMP_DATA) */
#define DUMP_PKT(pBuf,len)      do {} while(0)
#endif

#endif  /* defined(__NBUFF_H_INCLUDED__) */
