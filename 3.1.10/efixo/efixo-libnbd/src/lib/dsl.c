/*
 * dsl.c
 *
 * Copyright 2007 Miguel GAIO <miguel.gaio@efixo.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * $Id: dsl.c 18304 2010-11-04 10:15:09Z mgo $
 */

#include <string.h>

#include "core.h"
#include "nvram.h"

int nbd_dsl_start(void)
{
	return nbd_set("dsl", "start");
}

int nbd_dsl_stop(void)
{
	return nbd_set("dsl", "stop");
}

int nbd_dsl_restart(void)
{
	return nbd_set("dsl", "restart");
}

int nbd_dsl_diag_start(void)
{
	return nbd_set("dsl", "diag", "start");
}

int nbd_dsl_diag_stop(void)
{
	return nbd_set("dsl", "diag", "stop");
}

int nbd_dsl_get(const char *name, char *buf, size_t buf_size)
{
	return nbd_get(buf, buf_size, "dsl", "get", name);
}

int nbd_dsl_mod_set(char const *mod)
{
	return nbd_user_config_set("adsl_userprofile_mod", mod);
}

int nbd_dsl_mod_get(char *mod, size_t len)
{
	return nbd_user_config_get("adsl_userprofile_mod", mod, len);
}

int nbd_dsl_lpair_set(char const *lpair)
{
	return nbd_user_config_set("adsl_userprofile_lpair", lpair);
}

int nbd_dsl_lpair_get(char *lpair, size_t len)
{
	return nbd_user_config_get("adsl_userprofile_lpair", lpair, len);
}

int nbd_dsl_trellis_set(char const *trellis)
{
	return nbd_user_config_set("adsl_userprofile_trellis", trellis);
}

int nbd_dsl_trellis_get(char *trellis, size_t len)
{
	return nbd_user_config_get("adsl_userprofile_trellis", trellis, len);
}

int nbd_dsl_snr_set(char const *snr)
{
	return nbd_user_config_set("adsl_userprofile_snr", snr);
}

int nbd_dsl_snr_get(char *snr, size_t len)
{
	return nbd_user_config_get("adsl_userprofile_snr", snr, len);
}

int nbd_dsl_bitswap_set(char const *bitswap)
{
	return nbd_user_config_set("adsl_userprofile_bitswap", bitswap);
}

int nbd_dsl_bitswap_get(char *bitswap, size_t len)
{
	return nbd_user_config_get("adsl_userprofile_bitswap", bitswap, len);
}

int nbd_dsl_sesdrop_set(char const *sesdrop)
{
	return nbd_user_config_set("adsl_userprofile_sesdrop", sesdrop);
}

int nbd_dsl_sesdrop_get(char *sesdrop, size_t len)
{
	return nbd_user_config_get("adsl_userprofile_sesdrop", sesdrop, len);
}

int nbd_dsl_sra_set(char const *sra)
{
	return nbd_user_config_set("adsl_userprofile_sra", sra);
}

int nbd_dsl_sra_get(char *sra, size_t len)
{
	return nbd_user_config_get("adsl_userprofile_sra", sra, len);
}

int nbd_dsl_rate_up_get(char *data, size_t len)
{
	return nbd_get(data, len, "dsl", "get", "adsl_rate_up");
}

int nbd_dsl_rate_down_get(char *data, size_t len)
{
	return nbd_get(data, len, "dsl", "get", "adsl_rate_down");
}

int nbd_dsl_noise_up_get(char *data, size_t len)
{
	return nbd_get(data, len, "dsl", "get", "adsl_noise_up");
}

int nbd_dsl_noise_down_get(char *data, size_t len)
{
	return nbd_get(data, len, "dsl", "get", "adsl_noise_down");
}

int nbd_dsl_attenuation_up_get(char *data, size_t len)
{
	return nbd_get(data, len, "dsl", "get", "adsl_attenuation_up");
}

int nbd_dsl_attenuation_down_get(char *data, size_t len)
{
	return nbd_get(data, len, "dsl", "get", "adsl_attenuation_down");
}

int nbd_dsl_linemode_get(char *data, size_t len)
{
	return nbd_get(data, len, "dsl", "get", "adsl_linemode");
}

int nbd_dsl_crc_get(char *data, size_t len)
{
	return nbd_get(data, len, "dsl", "get", "adsl_crc");
}

int nbd_dsl_plugtest(char **xml, size_t * xml_size)
{
	return nbd_get_new(xml, xml_size, "dsl", "plugtest");
}
