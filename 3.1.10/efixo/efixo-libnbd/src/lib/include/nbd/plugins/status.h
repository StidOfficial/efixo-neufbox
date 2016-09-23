/*!
 * \file plugins/status.h
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
 * $Id: status.h 18041 2010-10-11 09:05:02Z mgo $
 */

#ifndef _PLUGINS_STATUS_H_
#define _PLUGINS_STATUS_H_

/* POSIX */
#include <sys/types.h>

#include <lib/xml.h>

struct seq_file;

extern struct xml status_xml_ref;

static inline int status_init(void)
{
	return xml_init(&status_xml_ref);
}

static inline void status_cleanup(void)
{
	xml_cleanup(&status_xml_ref);
}

static inline char const *status_txt(char const *key)
{
	return xml_txt(&status_xml_ref, key);
}

static inline char const *status_txt_safe(char const *key)
{
	return xml_txt_safe(&status_xml_ref, key);
}

static inline int status_get(char const *key, char *buf, size_t len)
{
	return xml_get(&status_xml_ref, key, buf, len);
}

static inline int status_set_node(void *node, char const *buf)
{
	return xml_set_node(&status_xml_ref, node, buf);
}

static inline int status_set(char const *key, char const *buf)
{
	return xml_set(&status_xml_ref, key, buf);
}

static inline int status_add(char const *key, char const *new, char const *buf)
{
	return xml_add(&status_xml_ref, key, new, buf);
}

static inline int status_del(char const *key)
{
	return xml_del(&status_xml_ref, key);
}

static inline int status_list(char const *key, struct seq_file *m)
{
	return xml_list(&status_xml_ref, key, m);
}

static inline int status_list_long(char const *key, struct seq_file *m)
{
	return xml_list_long(&status_xml_ref, key, m);
}

static inline int status_list_contains(char const *key, char const *buf)
{
	return xml_list_contains(&status_xml_ref, key, buf);
}

static inline int status_list_count(char const *key)
{
	return xml_list_count(&status_xml_ref, key);
}

static inline int status_list_flush(char const *key)
{
	return xml_list_flush(&status_xml_ref, key);
}

static inline int status_show(struct seq_file *m)
{
	return xml_show(&status_xml_ref, m);
}

static inline char *status_xml(char const *key)
{
	return xml_xml(&status_xml_ref, key);
}

static inline void *status_node(char const *key)
{
	return xml_node(&status_xml_ref, key);
}

static inline int status_test(char const *key)
{
	return xml_test(&status_xml_ref, key);
}

/*! \def status_matches(char const *key, value)
 *  \brief Compare xml data to value
 *  \param key Key
 *  \param value Data to be compare to
 */
#define status_matches(key, value) \
	xml_matches(&status_xml_ref, key, value)

/*! \def xml_for_each_status_node(node, key)
 *  \brief Iterate over xml node.
 */
#define xml_for_each_status_node(node, key) \
	xml_for_each_node(node, &status_xml_ref, key)

/*! \def xml_for_each_status_node_safe(node, key)
 *  \brief Iterate over xml node.
 */
#define xml_for_each_status_node_safe(node, next, key) \
	xml_for_each_node_safe(node, next, &status_xml_ref, key)

#endif
