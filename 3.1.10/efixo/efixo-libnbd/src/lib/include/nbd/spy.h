/*!
 * \file spy.h
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
 * $Id: spy.h 14598 2010-02-04 13:46:30Z mgo $
 */

#ifndef _LIBNBD_SPY_H_
#define _LIBNBD_SPY_H_

extern int nbd_spy_error(const char *error);
extern int nbd_spy_event(const char *event);
extern int nbd_spy_log(void);

#endif
