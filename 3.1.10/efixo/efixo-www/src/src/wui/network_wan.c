#include <ewf/ewf.h>
#include <ewf/ewf_page.h>
#include <ewf/ewf_hdf.h>
#include <ewf/ewf_utils.h>

#include "webapp.h"

#include "nbl.h"
#include "nbd.h"
#include "dbl.h"

PAGE_DF("/network/wan", EWF_ACCESS_PRIVATE);

DISPLAY_HANDLER
{
        STATUS_TO_HDF("net_data_access");

        if(has_net_infra_bridge())
        {
                NV_TO_HDF("net_mode");
        }

        NV_TO_HDF("ppp_login");
        NV_TO_HDF("ppp_password");
        NV_TO_HDF("ipv6_enable");
        return;
}

FORM_HANDLER
{
        struct trx trx;
        const char *net_mode = NULL,
                *ppp_login = NULL, *ppp_password = NULL, *ipv6_enable = NULL;
        int reboot = 0;

        NV_TRX_INIT(trx);

        EWF_HDF_GET_DEFAULT(net_mode, "router");
        EWF_HDF_GET(ppp_login);
        EWF_HDF_GET(ppp_password);
        EWF_HDF_GET_DEFAULT(ipv6_enable, "off");

        /* only set net_mode if bridge infra is supported */
        if(has_net_infra_bridge()
           && nbd_user_config_set("net_mode", net_mode) == NV_SET_SUCCESS)
        {
                /* net_mode has changed ! */
                nbd_nv_commit("user");
                reboot = 1;
        }

        NV_SET_WTRX(trx, "ppp_login", ppp_login);
        NV_SET_WTRX(trx, "ppp_password", ppp_password);
        NV_SET_WTRX(trx, "ipv6_enable", ipv6_enable);

        if(NV_TRX_XCOMMIT(trx) == NV_COMMIT_SUCCESS)
        {
                nbd_sys_async_run(PPP_START_STOP, "reload");
                nbd_sys_async_run(IPV6_START_STOP, "reload");
        }

        if(reboot)
        {
                ewf_utils_redirect(WEBAPP_URI_REBOOT);
        }
}
