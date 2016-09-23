/*!
 * \file plugins/dsl.h
 *
 * \brief  Declare dsl interface
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
 * $Id: dsl.h 17865 2010-09-30 14:45:34Z mgo $
 */

#ifndef _PLUGINS_DSL_H_
#define _PLUGINS_DSL_H_

char const *dsl_info_txt(char const *key);

static inline char const *dsl_info_txt_safe(char const *key)
{
	char const *p = dsl_info_txt(key);

	return p ? p : "";
}

int dsl_info_list(struct seq_file *m);

#endif /* _PLUGINS_DSL_H_ */
