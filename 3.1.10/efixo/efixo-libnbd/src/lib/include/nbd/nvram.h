/*!
 * \file nvram.h
 *
 * \note Copyright 2007 Miguel GAIO <miguel.gaio@efixo.com>
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
 * $Id: nvram.h 17865 2010-09-30 14:45:34Z mgo $
 */

#ifndef _NVRAM_H_
#define _NVRAM_H_

#include <stddef.h>

#define NV_SET_INVALID_VALUE -4
#define NV_SET_ERROR -1
#define NV_SET_SUCCESS 0
#define NV_SET_UNCHANGED 1

#define NV_COMMIT_ERROR -1
#define NV_COMMIT_SUCCESS 0
#define NV_COMMIT_UNCHANGED 1

#ifndef NBD_USE_DEPRECATED_API
#define __deprecated __attribute__ ((deprecated))
#else
#define __deprecated
#endif

/*! \fn int nbd_*_get (char const *key, char *data, size_t len)
    \brief Get NvRam Data.
    \param key Entry name.
    \param data Buffer to write into.
    \param len max size.
    \return: 0: success  -1: failure
 */
int nbd_nv_get(char const *key, char *data, size_t len) __deprecated;
int nbd_system_config_get(char const *key, char *data, size_t len);
int nbd_user_config_get(char const *key, char *data, size_t len);

/*! \fn int nbd_*_set (char const *key, char const *data)
    \brief Add NvRam entry.
    \param key Entry name.
    \param data New value.
    \return: 0: success  1: unchanged -1: failure
 */
int nbd_nv_set(char const *key, char const *data) __deprecated;
int nbd_system_config_set(char const *key, char const *data);
int nbd_user_config_set(char const *key, char const *data);

/*! \fn int nbd_*_add (char const *key, char const *data)
    \brief Add NvRam entry.
    \param key Entry name.
    \param data New value.
    \return: 0: success  -1: failure
 */
int nbd_user_config_add(char const *key, char const *data);

/*! \fn int nbd_*_del (char const *key)
    \brief Del NvRam entry.
    \param key Entry name.
    \return: 0: success  -1: failure
 */
int nbd_user_config_del(char const *key);

/*! \fn int nbd_*_list (char const *list, char *data, size_t len)
    \brief Get list of NvRam Data.
    \param list Entry name.
    \param data Buffer to write into.
    \param len max size.
    \return: 0: success  -1: failure
 */
int nbd_system_config_list(char const *list, char *data, size_t len);
int nbd_user_config_list(char const *list, char *data, size_t len);

/*! \fn int nbd_*_list_long (char const *list, char *data, size_t len)
    \brief Get list of NvRam Data: format [key=value].
    \param list Entry name.
    \param data Buffer to write into.
    \param len max size.
    \return: 0: success  -1: failure
 */
int nbd_system_config_list_long(char const *list, char *data, size_t len);
int nbd_user_config_list_long(char const *list, char *data, size_t len);

/*! \fn int nbd_*_list_flush (char const *list)
    \brief Flush element from list.
    \param list Entry name.
    \param idx Index.
    \return: 0: success  -1: failure
 */
int nbd_user_config_list_flush(char const *list);

/*! \fn int nbd_*_list_contains (char const *list, char const *key)
    \brief Contains element into.
    \param list List.
    \param key Entry.
    \return: 0: success  -1: failure
 */
int nbd_user_config_list_contains(char const *list, char const *key);

/*! \fn int nbd_*_list_count (char const *list)
    \brief Get list element count.
    \param list Entry name.
    \return: element count: success  -1: failure
 */
int nbd_system_config_list_count(char const *list);
int nbd_user_config_list_count(char const *list);

/*! \fn int nbd_*_commit (char const *xml)
    \brief Commit NvRam data.
    \param xml Nvram section.
    \return: 0: success  -1: failure
 */
int nbd_nv_commit(char const *xml) __deprecated;
int nbd_system_config_commit(void);
int nbd_user_config_commit(void);

/*! \fn int nbd_*_erase (char const *xml)
    \brief Erase NvRam data.
    \param xml Nvram section.
    \return: 0: success  -1: failure
 */
int nbd_system_config_erase(void);
int nbd_user_config_erase(void);

/*! \fn int nbd_*_export (char const *xml, char const *file)
    \brief Get list of NvRam Data: format [key=value].
    \param xml Nvram section.
    \param file data.
    \return: 0: success  -1: failure
 */
int nbd_system_config_export(char const *file);
int nbd_user_config_export(char const *file);

/*! \fn int nbd_*_import (char const *xml, char const *file)
    \brief Get list of NvRam Data: format [key=value].
    \param xml Nvram section.
    \param file data.
    \return: 0: success  -1: failure
 */
int nbd_system_config_import(char const *file);
int nbd_user_config_import(char const *file);

/*! \fn char* nbd_*_xml(char const *key)
 *  \brief Give Xml structure
 *  \param key Entry name.
 */
int nbd_system_config_xml(const char *key, char **xml, size_t * len);
int nbd_user_config_xml(const char *key, char **xml, size_t * len);

/*! \fn int nbd_user_config_cursor_new(void)
 *  \brief Create a cursor
 *  \return cursor id
 */
unsigned int nbd_user_config_cursor_new(void);

/*! \fn int nbd_user_config_cursor_close(unsigned int cid)
 *  \brief Close a cursor
 *  \param cid cursor id
 *  \return 0 if success, -1 otherwise
 */
int nbd_user_config_cursor_close(unsigned int cid);

/*! \fn int nbd_user_config_cursor_revert(unsigned int cid)
 *  \brief Cleanup all modifications do in a cursor
 *  \param cid cursor id
 *  \return 0 if success, -1 otherwise
 */
int nbd_user_config_cursor_revert(unsigned int cid);

/*! \fn int nbd_user_config_cursor_revert(unsigned int cid)
 *  \brief Commit all modifications do in a cursor and commit nvram data
 *  \param cid cursor id
 *  \return 0 if success, -1 otherwise
 */
int nbd_user_config_cursor_commit(unsigned int cid);

/*! \fn int nbd_user_config_cset (unsigned int cid, char const *key, char const *data)
    \brief Set NvRam entry in a cursor
 *  \param cid cursor id
    \param key Entry name.
    \param data New value.
    \return: 0: success  1: unchanged -1: failure, -4: invalid format
 */
int nbd_user_config_cset(unsigned int cid, char const *key, char const *data);

/*! \fn int nbd_*_matches (char const *key, char const *data)
    \brief Compare a nvram value to a given string.
    \param key Entry name.
    \param ref String to compare.
    \return: 0: strings are not equal  1: they are equal
 */
#define nbd_nv_matches(key, c_str) \
({ \
	const char __dummy[] = c_str; \
	char __s[sizeof(c_str)]; \
	\
	(void)(&__dummy); \
	(nbd_nv_get(key, __s, sizeof(__s)) < 0) ? \
		0 : (memcmp(__s, c_str, sizeof(c_str)) == 0); \
})
#define nbd_system_config_matches(key, c_str) \
({ \
	const char __dummy[] = c_str; \
	char __s[sizeof(c_str)]; \
	\
	(void)(&__dummy); \
	(nbd_system_config_get(key, __s, sizeof(__s)) < 0) ? \
		0 : (memcmp(__s, c_str, sizeof(c_str)) == 0); \
})
#define nbd_user_config_matches(key, c_str) \
({ \
	const char __dummy[] = c_str; \
	char __s[sizeof(c_str)]; \
	\
	(void)(&__dummy); \
	(nbd_user_config_get(key, __s, sizeof(__s)) < 0) ? \
		0 : (memcmp(__s, c_str, sizeof(c_str)) == 0); \
})

/* admin system access exceptions */
int nbd_system_xml_privateport(char **xml, size_t * len);

#endif
