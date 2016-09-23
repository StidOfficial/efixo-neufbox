/*!
 * \file plugins/nvram.h
 *
 * \brief  Declare NvRam interface(nvram_s)
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
 * $Id: nvram.h 18041 2010-10-11 09:05:02Z mgo $
 */

#ifndef _PLUGINS_NVRAM_H_
#define _PLUGINS_NVRAM_H_

/* POSIX */
#include <unistd.h>
#include <sys/types.h>

#include <lib/xml.h>

struct seq_file;

extern struct xml system_xml_ref;
extern struct xml user_xml_ref;

static inline int system_config_init(void)
{
	return xml_init(&system_xml_ref);
}

static inline void system_config_cleanup(void)
{
	xml_cleanup(&system_xml_ref);
}

static inline char const *system_config_txt(char const *key)
{
	return xml_txt(&system_xml_ref, key);
}

static inline char const *system_config_txt_safe(char const *key)
{
	return xml_txt_safe(&system_xml_ref, key);
}

static inline int system_config_get(char const *key, char *buf, size_t len)
{
	return xml_get(&system_xml_ref, key, buf, len);
}

static inline int system_config_set_node(void *node, char const *buf)
{
	return xml_set_node(&system_xml_ref, node, buf);
}

static inline int system_config_set(char const *key, char const *buf)
{
	return xml_set(&system_xml_ref, key, buf);
}

static inline int system_config_check(char const *key, char const *buf)
{
	return xml_check(&system_xml_ref, key, buf);
}

static inline int system_config_add(char const *key, char const *new,
				    char const *buf)
{
	return xml_add(&system_xml_ref, key, new, buf);
}

static inline int system_config_del(char const *key)
{
	return xml_del(&system_xml_ref, key);
}

static inline int system_config_list(char const *key, struct seq_file *m)
{
	return xml_list(&system_xml_ref, key, m);
}

static inline int system_config_list_long(char const *key, struct seq_file *m)
{
	return xml_list_long(&system_xml_ref, key, m);
}

static inline int system_config_list_contains(char const *key, char const *buf)
{
	return xml_list_contains(&system_xml_ref, key, buf);
}

static inline int system_config_list_count(char const *key)
{
	return xml_list_count(&system_xml_ref, key);
}

static inline int system_config_list_flush(char const *key)
{
	return xml_list_flush(&system_xml_ref, key);
}

static inline int system_config_show(struct seq_file *m)
{
	return xml_show(&system_xml_ref, m);
}

static inline void system_config_reload(void)
{
	xml_cleanup(&system_xml_ref);
	xml_init(&system_xml_ref);
}

static inline int system_config_commit(void)
{
	return xml_commit(&system_xml_ref, false);
}

static inline int system_config_erase(void)
{
	return xml_erase(&system_xml_ref);
}

static inline int system_config_export(char const *file)
{
	return xml_export(&system_xml_ref, file);
}

static inline int system_config_import(char const *file)
{
	return xml_import(&system_xml_ref, file);
}

static inline char *system_config_xml(char const *key)
{
	return xml_xml(&system_xml_ref, key);
}

static inline void *system_config_node(char const *key)
{
	return xml_node(&system_xml_ref, key);
}

static inline int system_config_test(char const *key)
{
	return xml_test(&system_xml_ref, key);
}

/*! \def system_config_matches(char const *key, value)
 *  \brief Compare xml data to value
 *  \param key Key
 *  \param value Data to be compare to
 */
#define system_config_matches(key, value) \
	xml_matches(&system_xml_ref, key, value)

/*! \def xml_for_each_system_config_node(node, key)
 *  \brief Iterate over xml node.
 */
#define xml_for_each_system_config_node(node, key) \
	xml_for_each_node(node, &system_xml_ref, key)

/*! \def xml_for_each_system_config_node_safe(node, key)
 *  \brief Iterate over xml node.
 */
#define xml_for_each_system_config_node_safe(node, next, key) \
	xml_for_each_node_safe(node, next, &system_xml_ref, key)

static inline int user_config_init(void)
{
	return xml_init(&user_xml_ref);
}

static inline void user_config_cleanup(void)
{
	xml_cleanup(&user_xml_ref);
}

static inline char const *user_config_txt(char const *key)
{
	return xml_txt(&user_xml_ref, key);
}

static inline char const *user_config_txt_safe(char const *key)
{
	return xml_txt_safe(&user_xml_ref, key);
}

static inline int user_config_get(char const *key, char *buf, size_t len)
{
	return xml_get(&user_xml_ref, key, buf, len);
}

static inline int user_config_set_node(void *node, char const *buf)
{
	return xml_set_node(&user_xml_ref, node, buf);
}

static inline int user_config_set(char const *key, char const *buf)
{
	return xml_set(&user_xml_ref, key, buf);
}

static inline int user_config_check(char const *key, char const *buf)
{
	return xml_check(&user_xml_ref, key, buf);
}

static inline int user_config_add(char const *key, char const *new,
				  char const *buf)
{
	return xml_add(&user_xml_ref, key, new, buf);
}

static inline int user_config_del(char const *key)
{
	return xml_del(&user_xml_ref, key);
}

static inline int user_config_list(char const *key, struct seq_file *m)
{
	return xml_list(&user_xml_ref, key, m);
}

static inline int user_config_list_long(char const *key, struct seq_file *m)
{
	return xml_list_long(&user_xml_ref, key, m);
}

static inline int user_config_list_contains(char const *key, char const *buf)
{
	return xml_list_contains(&user_xml_ref, key, buf);
}

static inline int user_config_list_count(char const *key)
{
	return xml_list_count(&user_xml_ref, key);
}

static inline int user_config_list_flush(char const *key)
{
	return xml_list_flush(&user_xml_ref, key);
}

static inline int user_config_show(struct seq_file *m)
{
	return xml_show(&user_xml_ref, m);
}

static inline void user_config_reload(void)
{
	xml_cleanup(&user_xml_ref);
	xml_init(&user_xml_ref);
}

int user_config_commit(bool);

static inline int user_config_erase(void)
{
	xml_erase(&user_xml_ref);
	sync();

	return 0;
}

static inline int user_config_export(char const *file)
{
	return xml_export(&user_xml_ref, file);
}

static inline int user_config_import(char const *file)
{
	return xml_import(&user_xml_ref, file);
}

static inline char *user_config_xml(char const *key)
{
	return xml_xml(&user_xml_ref, key);
}

static inline void *user_config_node(char const *key)
{
	return xml_node(&user_xml_ref, key);
}

static inline int user_config_test(char const *key)
{
	return xml_test(&user_xml_ref, key);
}

static inline unsigned int user_config_cursor_new(void)
{
	return xml_cursor_add(&user_xml_ref);
}

static inline void user_config_cursor_list(struct seq_file *m)
{
	return xml_cursor_list(&user_xml_ref, m);
}

static inline unsigned int user_config_cursor_commit(unsigned int cid)
{
	return xml_cursor_commit(&user_xml_ref, cid);
}

static inline unsigned int user_config_cursor_close(unsigned int cid)
{
	return xml_cursor_close(&user_xml_ref, cid);
}

static inline unsigned int user_config_cursor_revert(unsigned int cid)
{
	return xml_cursor_revert(&user_xml_ref, cid);
}

static inline unsigned int user_config_cset(unsigned int cid,
					    char const *key, char const *buf)
{
	return xml_cset(&user_xml_ref, cid, key, buf);
}

/*! \def user_config_matches(char const *key, value)
 *  \brief Compare xml data to value
 *  \param key Key
 *  \param value Data to be compare to
 */
#define user_config_matches(key, value) \
	xml_matches(&user_xml_ref, key, value)

/*! \def xml_for_each_user_config_node(node, key)
 *  \brief Iterate over xml node.
 */
#define xml_for_each_user_config_node(node, key) \
	xml_for_each_node(node, &user_xml_ref, key)

/*! \def xml_for_each_user_config_node_safe(node, key)
 *  \brief Iterate over xml node.
 */
#define xml_for_each_user_config_node_safe(node, next, key) \
	xml_for_each_node_safe(node, next, &user_xml_ref, key)

#endif
