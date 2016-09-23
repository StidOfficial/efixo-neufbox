/*!
 * \file core.h
 *
 * \note Copyright 2006 Miguel GAIO <miguel.gaio@efixo.com>
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
 * $Id: core.h 9487 2008-11-19 08:19:46Z mgo $
 */

#ifndef _GPIO_H_
#define _GPIO_H_

void gpio_direction_input(int gpio);
void gpio_direction_output(int gpio);
int gpio_get_value(int gpio);
void gpio_set_value(int gpio, int value);

#endif /* _GPIO_H_ */
