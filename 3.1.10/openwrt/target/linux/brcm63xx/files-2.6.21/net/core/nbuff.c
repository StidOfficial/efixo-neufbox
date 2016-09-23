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

#include <linux/init.h>
#include <linux/slab.h>
#include <linux/nbuff.h>

#ifdef CC_CONFIG_FKB_FN_INLINE
#define DECLARE_FKB_FN(fn_identifier, fn_signature, body)
#else
#define DECLARE_FKB_FN(fn_identifier, fn_signature, body)                     \
fn_signature { body; }                                                        \
EXPORT_SYMBOL(fn_identifier);
#endif

#ifdef CC_CONFIG_FKB_COLOR
#define COLOR(clr_code)     clr_code
#else
#define COLOR(clr_code)
#endif
#define CLRb                COLOR("\e[0;34m")       /* blue */
#define CLRc                COLOR("\e[0;36m")       /* cyan */
#define CLRn                COLOR("\e[0m")          /* normal */
#define CLRerr              COLOR("\e[0;33;41m")    /* yellow on red */
#define CLRN                CLRn"\n"                /* normal newline */

#if defined(CC_CONFIG_FKB_DEBUG)
#define fkb_print(fmt, arg...)                                          \
    printk( CLRc "FKB %s :" fmt CLRN, __FUNCTION__, ##arg )
#define fkb_assertv(cond)                                               \
    if ( !cond ) {                                                      \
        printk( CLRerr "FKB ASSERT %s : " #cond CLRN, __FUNCTION__ );   \
        return;                                                         \
    }
#define fkb_assertr(cond, rtn)                                          \
    if ( !cond ) {                                                      \
        printk( CLRerr "FKB ASSERT %s : " #cond CLRN, __FUNCTION__ );   \
        return rtn;                                                     \
    }
#define FKB_DBG(debug_code)     do { debug_code } while(0)
#else
#define fkb_print(fmt, arg...)  NULL_STMT
#define fkb_assertv(cond)       NULL_STMT
#define fkb_assertr(cond, rtn)  NULL_STMT
#define FKB_DBG(debug_code)     NULL_STMT
#endif


/* Global pointer to the free pool of FKBs */
static FkBuff_t * fkb_list_gp = FKB_NULL;
static int fkb_extends = 0;
#if defined(CC_CONFIG_FKB_DEBUG)
static int fkb_cnt_free = 0;        /* Number of FKB objects that are free    */
static int fkb_cnt_used = 0;        /* Number of in use FKB objects           */
static int fkb_cnt_hwm  = 0;        /* In use high water mark for engineering */
static int fkb_cnt_fails = 0;

void fkb_stats(void)
{
    printk("\textends<%d> free<%d> used<%d> HWM<%d> fails<%d>\n",
           fkb_extends, fkb_cnt_free, fkb_cnt_used, fkb_cnt_hwm, fkb_cnt_fails);
}
#else
#define fkb_stats()             NULL_STMT
#endif

/*
 *------------------------------------------------------------------------------
 * Function   : fkb_construct
 * Description: Create a pool of FKB objects. When a pool is exhausted
 *              this function may be invoked to extend the pool. The pool is
 *              identified by a global pointer, fkb_list_gp. All objects in
 *              the pool chained together in a single linked list.
 * Parameters :
 *   num      : Number of FKB objects to be allocated.
 * Returns    : Number of FKB objects allocated in pool.
 *------------------------------------------------------------------------------
 */
static uint32_t fkb_construct(uint32_t num)
{
    register int i;
    register FkBuff_t * list;

    fkb_print( "fkb_construct %u", num );

    list = (FkBuff_t *) kmalloc( num * sizeof(FkBuff_t), GFP_ATOMIC);
    if ( list == FKB_NULL )
    {
#if defined(CC_CONFIG_FKB_DEBUG)
        fkb_cnt_fails++;    /* Failure may also be due to in_interrupt alloc */
#endif
        fkb_print( "WARNING: Failure to initialize %d FKB objects", num );
        return 0;
    }
    fkb_extends++;

    /* memset( (void *)list, 0, (sizeof(FkBuff_t) * num ) ); */
    for ( i = 0; i < num; i++ )
        list[i].list = &list[i+1];

    local_irq_disable();
    list[num-1].list = fkb_list_gp; /* chain last FKB object */
    fkb_list_gp = list;               /* head of list */
    local_irq_enable();

    FKB_DBG( fkb_cnt_free += num; );

    return num;
}

/*
 *------------------------------------------------------------------------------
 * Function     : fkb_alloc
 * Description  : Allocate an FKB from the free list
 * Returns      : Pointer to an FKB or NULL, on depletion.
 *------------------------------------------------------------------------------
 */
FkBuff_t * fkb_alloc(void)
{
    register FkBuff_t * fkb_p;

    fkb_dbg(">> fkb_list_gp<0x%08x>", (int)fkb_list_gp);
    if ( fkb_list_gp == FKB_NULL )
    {
#ifdef SUPPORT_FKB_EXTEND
        if ( (fkb_extends >= FKB_EXTEND_MAX_ENGG)  /* Try extending free pool */
          || (fkb_construct( FKB_EXTEND_SIZE_ENGG ) != FKB_EXTEND_SIZE_ENGG) )
        {
            fkb_print( "WARNING: free list exhausted" );
            return FKB_NULL;
        }
#else
        if ( fkb_construct( FKB_EXTEND_SIZE_ENGG ) == 0 )
        {
            fkb_print( "WARNING: out of memory" );
            return FKB_NULL;
        }
#endif
    }
    FKB_DBG(
        fkb_cnt_free--;
        if ( ++fkb_cnt_used > fkb_cnt_hwm )
            fkb_cnt_hwm = fkb_cnt_used;
        );

    local_irq_disable();
    fkb_p = fkb_list_gp;
    fkb_list_gp = fkb_list_gp->list;
    local_irq_enable();

    atomic_set(&fkb_p->users, 0);
    fkb_dbg("<< fkb_p<0x%08x>", (int)fkb_p);

    return fkb_p;
}

void fkb_free(FkBuff_t * fkb_p)
{
    FkBuff_t * fkbM_p;

    fkb_assertv( (fkb_p!=FKB_NULL) );
    fkb_dbg(">> fkb_p<0x%08x>", (int)fkb_p);

    if ( IS_FKB_CLONE(fkb_p) )
        fkbM_p = fkb_p->master_p;
    else
        fkbM_p = fkb_p;

    fkb_assertv( (atomic_read(&fkbM_p->users) > 0) );

    if ( atomic_dec_and_test(&fkbM_p->users) )
    {
        fkbM_p->recycle_hook(FKBUFF_2_PNBUFF(fkbM_p),
                             fkbM_p->recycle_context, 0);
    }
    fkb_dbg("<< fkbM_p<0x%08x>", (int)fkbM_p);
}

DECLARE_FKB_FN( fkb_clr,
    void fkb_clr(FkBuff_t * fkb_p),
    _fkb_clr(fkb_p) )

DECLARE_FKB_FN( fkb_init,
    FkBuff_t * fkb_init(uint8_t * pBuf, uint32_t headroom,
                        uint8_t * pData, uint32_t len),
    return _fkb_init(pBuf, headroom, pData, len) )

DECLARE_FKB_FN( fkb_qinit,
    FkBuff_t * fkb_qinit(uint8_t * pBuf, uint32_t headroom,
                        uint8_t * pData, uint32_t len, uint32_t qcontext),
    return _fkb_qinit(pBuf, headroom, pData, len, qcontext) )


DECLARE_FKB_FN( fkb_release,
    void fkb_release(FkBuff_t * fkb_p),
    _fkb_release(fkb_p) )

DECLARE_FKB_FN( fkb_headroom,
    int fkb_headroom(const FkBuff_t *fkb_p),
    return _fkb_headroom(fkb_p) )

DECLARE_FKB_FN( fkb_push,
    uint8_t * fkb_push(FkBuff_t * fkb_p, uint32_t len),
    return _fkb_push(fkb_p, len) )

DECLARE_FKB_FN( fkb_pull,
    uint8_t * fkb_pull(FkBuff_t * fkb_p, uint32_t len),
    return _fkb_pull(fkb_p, len) )

DECLARE_FKB_FN( fkb_put,
    uint8_t * fkb_put(FkBuff_t * fkb_p, uint32_t len),
    return _fkb_put(fkb_p, len) )

DECLARE_FKB_FN( fkb_pad,
    uint32_t fkb_pad(FkBuff_t * fkb_p, uint32_t len),
    return _fkb_pad(fkb_p, len) )

DECLARE_FKB_FN( fkb_len,
    uint32_t fkb_len(FkBuff_t * fkb_p),
    return _fkb_len(fkb_p) )

DECLARE_FKB_FN( fkb_data,
    uint8_t * fkb_data(FkBuff_t * fkb_p),
    return _fkb_data(fkb_p) )

DECLARE_FKB_FN( fkb_blog,
    struct blog_t * fkb_blog(FkBuff_t * fkb_p),
    return _fkb_blog(fkb_p) )
DECLARE_FKB_FN( fkb_clone,
    FkBuff_t * fkb_clone(FkBuff_t * fkbM_p),
    return _fkb_clone(fkbM_p) )

EXPORT_SYMBOL(fkb_alloc);
EXPORT_SYMBOL(fkb_free);
