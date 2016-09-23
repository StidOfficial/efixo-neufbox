/*!
 * \file plugins/sfp.h
 *
 * \brief  Declare sfp interface
 *
 * \author Copyright 2007 Miguel GAIO <miguel.gaio@efixo.com>
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
 * $Id: sfp.h 17865 2010-09-30 14:45:34Z mgo $
 */

#ifndef _PLUGINS_SFP_H_
#define _PLUGINS_SFP_H_

/* POSIX */
#include <sys/types.h>

#include "lib/xml.h"

struct xml sfp_xml_ref;

static inline char const *sfp_txt_safe(char const *key)
{
	extern int sfp_update(void);

	sfp_update();

	return xml_txt_safe(&sfp_xml_ref, key);
}

static inline int sfp_set(char const *key, char const *buf)
{
	return xml_set(&sfp_xml_ref, key, buf);
}

#endif /* _PLUGINS_SFP_H_ */
