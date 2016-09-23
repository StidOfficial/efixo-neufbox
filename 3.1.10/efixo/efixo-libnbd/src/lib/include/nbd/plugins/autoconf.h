/*!
 * \file plugins/autoconf.h
 *
 * \brief  Declare NvRam interface
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
 * $Id: autoconf.h 17865 2010-09-30 14:45:34Z mgo $
 */

#ifndef _PLUGINS_AUTOCONF_H_
#define _PLUGINS_AUTOCONF_H_

/* POSIX */
#include <sys/types.h>

#include <lib/xml.h>

struct seq_file;

extern struct xml autoconf_xml_ref;

static inline int autoconf_init(void)
{
	return xml_init(&autoconf_xml_ref);
}

static inline void autoconf_cleanup(void)
{
	xml_cleanup(&autoconf_xml_ref);
}

static inline char const *autoconf_txt(char const *key)
{
	return xml_txt(&autoconf_xml_ref, key);
}

static inline char const *autoconf_txt_safe(char const *key)
{
	return xml_txt_safe(&autoconf_xml_ref, key);
}

static inline int autoconf_get(char const *key, char *buf, size_t len)
{
	return xml_get(&autoconf_xml_ref, key, buf, len);
}

static inline int autoconf_set(char const *key, char const *buf)
{
	return xml_set(&autoconf_xml_ref, key, buf);
}

static inline int autoconf_add(char const *key, char const *new,
			       char const *buf)
{
	return xml_add(&autoconf_xml_ref, key, new, buf);
}

static inline int autoconf_del(char const *key)
{
	return xml_del(&autoconf_xml_ref, key);
}

static inline int autoconf_list(char const *key, struct seq_file *m)
{
	return xml_list(&autoconf_xml_ref, key, m);
}

static inline int autoconf_list_long(char const *key, struct seq_file *m)
{
	return xml_list_long(&autoconf_xml_ref, key, m);
}

static inline int autoconf_list_contains(char const *key, char const *buf)
{
	return xml_list_contains(&autoconf_xml_ref, key, buf);
}

static inline int autoconf_list_count(char const *key)
{
	return xml_list_count(&autoconf_xml_ref, key);
}

static inline int autoconf_list_flush(char const *key)
{
	return xml_list_flush(&autoconf_xml_ref, key);
}

static inline int autoconf_show(struct seq_file *m)
{
	return xml_show(&autoconf_xml_ref, m);
}

static inline char *autoconf_xml(char const *key)
{
	return xml_xml(&autoconf_xml_ref, key);
}

static inline void *autoconf_node(char const *key)
{
	return xml_node(&autoconf_xml_ref, key);
}

static inline int autoconf_test(char const *key)
{
	return xml_test(&autoconf_xml_ref, key);
}

/*! \def autoconf_matches(char const *key, value)
 *  \brief Compare xml data to value
 *  \param key Key
 *  \param value Data to be compare to
 */
#define autoconf_matches(key, value) \
	xml_matches(&autoconf_xml_ref, key, value)

#endif
