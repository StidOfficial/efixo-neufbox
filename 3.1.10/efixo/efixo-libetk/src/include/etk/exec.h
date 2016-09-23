/*!
 * \file etk/exec.h
 *
 * \author Copyright 2010 Miguel GAIO <miguel.gaio@efixo.com>
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
 */

#ifndef _ETK_EXEC_H_
#define _ETK_EXEC_H_ 1

int fork_and_exec(char const *const argv[], int nowait);

/*! \fn simple task exec wait
 */
#define exec(...) \
({ \
	char const *__argv[] = { __VA_ARGS__, NULL }; \
	\
	fork_and_exec(__argv, 0 /* nowait */); \
})

#endif
