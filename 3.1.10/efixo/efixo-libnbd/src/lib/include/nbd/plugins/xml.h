/*!
 * \file lib/plugin_xml_query.h
 *
 * \brief  Implement NvRam interface (struct xml)
 *
 * \author Copyright 2006 Miguel GAIO <miguel.gaio@efixo.com>
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
 * $Id: xml.h 17878 2010-10-01 07:23:02Z mgo $
 */

#ifndef _LIB_PLUGIN_XML_QUERY_H_
#define _LIB_PLUGIN_XML_QUERY_H_

#include <lib/xml.h>
#include <client.h>
#include <query.h>

#include <etk/log.h>
#include <etk/seq_file.h>

static inline int plugin_query_xml_get(struct plugin *plugin,
				       struct xml const *xml,
				       struct query *query)
{
	char const *const key = query->argv[2];
	char const *txt;

	if (!key) {
		return query_send_usage(query, plugin);
	}

	txt = xml_txt(xml, key);

	if (!txt) {
		err(QUERY_FMT, QUERY_ARG(query));
		return query_send_failed(query);
	}

	return query_send_str(query, txt);

}

static inline int plugin_query_xml_set(struct plugin *plugin,
				       struct xml *xml, struct query *query)
{
	char const *const key = query->argv[2];
	char const *const data = query->argv[3] ? query->argv[3] : "";
	int ret = query_status_failed;

	if (!key) {
		return query_send_usage(query, plugin);
	}

	ret = xml_set(xml, key, data);

	return query_send_status(query, ret);
}

static inline int plugin_query_xml_attr(struct plugin *plugin,
					struct xml const *xml,
					struct query *query)
{
	char const *const key = query->argv[2];
	char const *const attr = query->argv[3];
	char const *txt;

	if (!key || !attr) {
		return query_send_usage(query, plugin);
	}

	txt = xml_attr(xml, key, attr);

	if (!txt) {
		err(QUERY_FMT, QUERY_ARG(query));
		return query_send_failed(query);
	}

	return query_send_str(query, txt);

}

static inline int plugin_query_xml_add(struct plugin *plugin,
				       struct xml *xml, struct query *query)
{
	char const *const key = query->argv[2];
	char const *const data = query->argv[3];
	char *new;
	int ret;

	if (!key) {
		return query_send_usage(query, plugin);
	}

	new = strrchr(key, '_');
	if (!new) {
		err("invalid key:%s", key);
		return query_send_failed(query);
	}

	*new = '\0';
	++new;

	ret = xml_add(xml, key, new, data);

	return query_send_status(query, ret);
}

static inline int plugin_query_xml_del(struct plugin *plugin,
				       struct xml *xml, struct query *query)
{
	char const *const key = query->argv[2];
	int ret;

	if (!key) {
		return query_send_usage(query, plugin);
	}

	ret = xml_del(xml, key);

	return query_send_status(query, ret);
}

static inline int plugin_query_xml_list(struct plugin *plugin,
					struct xml const *xml,
					struct query *query)
{
	char const *const key = query->argv[2];
	DEFINE_SEQFILE(m, cache, CACHELEN);

	if (!key) {
		return query_send_usage(query, plugin);
	}

	xml_list(xml, key, &m);

	if (seq_empty(&m)) {
		return query_send_failed(query);
	} else {
		return query_send_seq_file(query, &m);
	}
}

static inline int plugin_query_xml_list_long(struct plugin *plugin,
					     struct xml const *xml,
					     struct query *query)
{
	char const *const key = query->argv[2];
	DEFINE_SEQFILE(m, cache, CACHELEN);

	if (!key) {
		return query_send_usage(query, plugin);
	}

	xml_list_long(xml, key, &m);

	return query_send_seq_file(query, &m);
}

static inline int plugin_query_xml_list_contains(struct plugin *plugin,
						 struct xml const *xml,
						 struct query *query)
{
	char const *const key = query->argv[2];
	char const *const data = query->argv[3];
	int ret;

	if ((!key) || (!data)) {
		return query_send_usage(query, plugin);
	}

	ret = xml_list_contains(xml, key, data);

	return query_send_status(query, ret);
}

static inline int plugin_query_xml_list_count(struct plugin *plugin,
					      struct xml const *xml,
					      struct query *query)
{
	char const *const key = query->argv[2];
	DEFINE_SEQFILE(m, cache, CACHELEN);
	unsigned count;

	if (!key) {
		return query_send_usage(query, plugin);
	}

	count = xml_list_count(xml, key);

	seq_printf(&m, "%u", count);

	return query_send_seq_file(query, &m);
}

static inline int plugin_query_xml_list_flush(struct plugin *plugin,
					      struct xml *xml,
					      struct query *query)
{
	char const *const key = query->argv[2];
	int ret;

	if (!key) {
		return query_send_usage(query, plugin);
	}

	ret = xml_list_flush(xml, key);

	return query_send_status(query, ret);
}

static inline int plugin_query_xml_show(struct plugin *plugin UNUSED,
					struct xml const *xml,
					struct query *query)
{
	DEFINE_SEQFILE(m, cache, CACHELEN);

	xml_show(xml, &m);

	return query_send_seq_file(query, &m);
}

static inline int plugin_query_xml_xml(struct plugin *plugin,
				       struct xml const *xml,
				       struct query *query)
{
	char const *const key = query->argv[2];
	char *out;
	int ret;

	if (!key) {
		return query_send_usage(query, plugin);
	}

	out = xml_xml(xml, key);
	if (out == NULL) {
		return query_send_failed(query);
	}

	ret = query_send_str(query, out);

	free(out);

	return ret;
}

#endif /* _LIB_PLUGIN_XML_QUERY_H_ */
