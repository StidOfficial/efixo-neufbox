/***********************license start***************
 * Copyright (c) 2003-2008  Cavium Networks (support@cavium.com). All rights
 * reserved.
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *
 *     * Neither the name of Cavium Networks nor the names of
 *       its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written
 *       permission.
 *
 * This Software, including technical data, may be subject to U.S.  export
 * control laws, including the U.S.  Export Administration Act and its
 * associated regulations, and may be subject to export or import regulations
 * in other countries.  You warrant that You will comply strictly in all
 * respects with all such regulations and acknowledge that you have the
 * responsibility to obtain licenses to export, re-export or import the
 * Software.
 *
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
 * AND WITH ALL FAULTS AND CAVIUM NETWORKS MAKES NO PROMISES, REPRESENTATIONS
 * OR WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH
 * RESPECT TO THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY
 * REPRESENTATION OR DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT
 * DEFECTS, AND CAVIUM SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES
 * OF TITLE, MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR
 * PURPOSE, LACK OF VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET
 * POSSESSION OR CORRESPONDENCE TO DESCRIPTION.  THE ENTIRE RISK ARISING OUT
 * OF USE OR PERFORMANCE OF THE SOFTWARE LIES WITH YOU.
 *
 *
 * For any questions regarding licensing please contact marketing@caviumnetworks.com
 *
 ***********************license end**************************************/






/**
 * @file
 *
 * Interface to the PCIe DMA engines. These are only avialable
 * on chips with PCIe.
 *
 * <hr>$Revision: 33485 $<hr>
 */
#include "executive-config.h"
#include "cvmx-config.h"
#include "cvmx.h"
#include "cvmx-cmd-queue.h"
#include "cvmx-dma-engine.h"

#ifdef CVMX_ENABLE_PKO_FUNCTIONS

/**
 * Return the number of DMA engimes supported by this chip
 *
 * @return Number of DMA engines
 */
static int __cvmx_dma_get_num_engines(void)
{
    if (OCTEON_IS_MODEL(OCTEON_CN56XX))
        return 5;
    else if (OCTEON_IS_MODEL(OCTEON_CN52XX))
        return 4;
    else
        return 0;
}

/**
 * Initialize the DMA engines for use
 *
 * @return Zero on success, negative on failure
 */
int cvmx_dma_engine_initialize(void)
{
    cvmx_npei_dma_control_t dma_control;
    cvmx_npei_dmax_ibuff_saddr_t dmax_ibuff_saddr;
    int engine;

    for (engine=0; engine < __cvmx_dma_get_num_engines(); engine++)
    {
        cvmx_cmd_queue_result_t result;
        result = cvmx_cmd_queue_initialize(CVMX_CMD_QUEUE_DMA(engine),
                                           0, CVMX_FPA_OUTPUT_BUFFER_POOL,
                                           CVMX_FPA_OUTPUT_BUFFER_POOL_SIZE);
        if (result != CVMX_CMD_QUEUE_SUCCESS)
            return -1;
        dmax_ibuff_saddr.u64 = 0;
        dmax_ibuff_saddr.s.saddr = cvmx_ptr_to_phys(cvmx_cmd_queue_buffer(CVMX_CMD_QUEUE_DMA(engine))) >> 7;
        cvmx_write_csr(CVMX_PEXP_NPEI_DMAX_IBUFF_SADDR(engine), dmax_ibuff_saddr.u64);
    }

    dma_control.u64 = 0;
    if (__cvmx_dma_get_num_engines() >= 5)
        dma_control.s.dma4_enb = 1;
    dma_control.s.dma3_enb = 1;
    dma_control.s.dma2_enb = 1;
    dma_control.s.dma1_enb = 1;
    dma_control.s.dma0_enb = 1;
    //dma_control.s.dwb_denb = 1;
    //dma_control.s.dwb_ichk = CVMX_FPA_OUTPUT_BUFFER_POOL_SIZE/128;
    dma_control.s.fpa_que = CVMX_FPA_OUTPUT_BUFFER_POOL;
    dma_control.s.csize = CVMX_FPA_OUTPUT_BUFFER_POOL_SIZE/8;
    cvmx_write_csr(CVMX_PEXP_NPEI_DMA_CONTROL, dma_control.u64);

    return 0;
}


/**
 * Shutdown all DMA engines. The engeines must be idle when this
 * function is called.
 *
 * @return Zero on success, negative on failure
 */
int cvmx_dma_engine_shutdown(void)
{
    cvmx_npei_dma_control_t dma_control;
    int engine;

    for (engine=0; engine < __cvmx_dma_get_num_engines(); engine++)
    {
        if (cvmx_cmd_queue_length(CVMX_CMD_QUEUE_DMA(engine)))
        {
            cvmx_dprintf("ERROR: cvmx_dma_engine_shutdown: Engine not idle.\n");
            return -1;
        }
    }

    dma_control.u64 = cvmx_read_csr(CVMX_PEXP_NPEI_DMA_CONTROL);
    if (__cvmx_dma_get_num_engines() >= 5)
        dma_control.s.dma4_enb = 0;
    dma_control.s.dma3_enb = 0;
    dma_control.s.dma2_enb = 0;
    dma_control.s.dma1_enb = 0;
    dma_control.s.dma0_enb = 0;
    cvmx_write_csr(CVMX_PEXP_NPEI_DMA_CONTROL, dma_control.u64);
    /* Make sure the disable completes */
    cvmx_read_csr(CVMX_PEXP_NPEI_DMA_CONTROL);

    for (engine=0; engine < __cvmx_dma_get_num_engines(); engine++)
    {
        cvmx_cmd_queue_shutdown(CVMX_CMD_QUEUE_DMA(engine));
        cvmx_write_csr(CVMX_PEXP_NPEI_DMAX_IBUFF_SADDR(engine), 0);
    }

    return 0;
}


/**
 * Submit a series of DMA comamnd to the DMA engines.
 *
 * @param engine  Engine to submit to (0-4)
 * @param header  Command header
 * @param num_buffers
 *                The number of data pointers
 * @param buffers Comamnd data pointers
 *
 * @return Zero on success, negative on failure
 */
int cvmx_dma_engine_submit(int engine, cvmx_dma_engine_header_t header, int num_buffers, cvmx_dma_engine_buffer_t buffers[])
{
    cvmx_cmd_queue_result_t result;
    int cmd_count = 1;
    uint64_t cmds[num_buffers + 1];

    cmds[0] = header.u64;
    while (num_buffers--)
    {
        cmds[cmd_count++] = buffers->u64;
        buffers++;
    }

    result = cvmx_cmd_queue_write(CVMX_CMD_QUEUE_DMA(engine), 1, cmd_count, cmds);
    /* DMA doorbells are 32bit writes in little endian space. This means we need to xor the address with 4 */
    if (result == CVMX_CMD_QUEUE_SUCCESS)
        cvmx_write64_uint32(CVMX_PEXP_NPEI_DMAX_DBELL(engine)^4, cmd_count);
    return result;
}

#endif
