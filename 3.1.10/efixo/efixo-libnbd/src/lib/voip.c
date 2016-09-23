/*
 * voip.c
 *
 * Copyright 2008 Pierre-Lucas MORICONI <pierre-lucas.moriconi@efixo.com>
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
 * $Id: voip.c 18316 2010-11-05 09:17:32Z pmi $
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sys/types.h>
#include <syslog.h>

#include "voip.h"
#include "core.h"
#include "nvram.h"
#include "status.h"
#include "autoconf.h"		/* for sip case */
#include "event.h"

typedef struct call_log {
	unsigned short type;	/* NBD_PHONE_CALL_PSTN or NBD_PHONE_CALL_VOIP */
	unsigned short direction;	/* NBD_PHONE_CALL_INCOMING or NBD_PHONE_CALL_OUTGOING */
	char number[NUMBER_MAX];	/* phone number of the interlocutor */
	time_t length;		/* length of the call (in seconds) */
	time_t date;		/* date of the call */

	time_t start;		/* start of the call */
	time_t finish;		/* end of the call */

	/* call_log* next_call; *//* pointer to the next call in the list */

} call_log;

static call_log new_call = {
	NBD_PHONE_CALL_UNINIT,
	NBD_PHONE_CALL_UNINIT,
	"",
	-1,
	-1,
	0,
	0
};

int nbd_voip_start(void)
{
	return nbd_set("voip", "start");
}

int nbd_voip_stop(void)
{
	return nbd_set("voip", "stop");
}

int nbd_voip_restart(void)
{
	return nbd_set("voip", "restart");
}

int nbd_voip_callhistory_flush(void)
{
	return nbd_set("voip", "history_reset");
}

int nbd_voip_reg_init(void)
{
	return nbd_set("voip", "regInit");
}

int nbd_get_reg_wui(char const *key, char const *data, unsigned int *reg)
{
	return nbd_get(reg, sizeof(unsigned int), "voip", "getRegWui",
		       key, data);
}

int nbd_voip_get_line_voltage(int8_t * volt)
{
	unsigned int reg;
	int retVal;

	retVal =
	    nbd_get(&reg, sizeof(unsigned int), "voip", "getRegWui", "daa",
		    "29");

	if (retVal)
		return retVal;

	/* if vodsl down (endpoint driver not initialized)
	 * reg == ~0x0 */

	if (reg == ~0x0u)
		return -1;

	*volt = (reg & 0xFF);
	if (reg & 0x80)		/* negative value */
		*volt = ~(*volt) + 1;

	return retVal;
}

/* ---------------------------------------------------------------- */
/* ---------------------CALLHISTORY-------------------------------- */
/* ---------------------------------------------------------------- */

static void nbd_voip_upgrade(void);

static int resetCall(call_log * call)
{
	call->type = NBD_PHONE_CALL_UNINIT;
	call->direction = NBD_PHONE_CALL_UNINIT;
	memset(&(call->number), '\0', NUMBER_MAX);
	call->length = -1;
	call->date = -1;
	call->start = 0;
	call->finish = 0;

	return 0;
}

/* List of neufbox calls */

int nbd_voip_io_call(unsigned short io_call)
{
	/* Initialization of the list */
	time(&(new_call.date));
	// call in progress
	if ((new_call.length == 0) && (new_call.type != NBD_PHONE_CALL_PSTN)) {
		new_call.type = NBD_PHONE_CALL_COMPLEX;
	} else if (new_call.length == 0 && new_call.type == NBD_PHONE_CALL_PSTN) {
	} else {
		new_call.direction = io_call;
		new_call.length = -1;
		new_call.start = new_call.finish = 0;
		memset(new_call.number, '\0', NUMBER_MAX);
		new_call.type = NBD_PHONE_CALL_VOIP;
	}

	nbd_voip_upgrade();

	return 0;
}

int nbd_voip_number_call(char *number_called, int num)
{
	int i = 0;

	// if the call has already begun, do not register the call number
	if (new_call.length == -1) {
		// knowing that Voip_pstn_call function
		if ((new_call.direction == NBD_PHONE_CALL_INCOMING
		     && (new_call.type == NBD_PHONE_CALL_VOIP
			 || new_call.type == NBD_PHONE_CALL_3G)
		     && num == -1)
		    || (new_call.direction == NBD_PHONE_CALL_INCOMING
			&& new_call.type == NBD_PHONE_CALL_PSTN && num == -1)) {
			// is called before this function it's ok
			while ((number_called[i] == '#'
				|| number_called[i] == '*'
				|| number_called[i] == '+'
				|| (number_called[i] >= '0'
				    && number_called[i] <= '9')))
				i++;
			if (number_called)
				strncpy(new_call.number, number_called, i);	// copy the number calling
		} else		// both pstn or voip emiting call
		{
			if (new_call.direction ==
			    NBD_PHONE_CALL_OUTGOING && number_called == NULL) {
				while (new_call.number[i] != '\0')
					i++;
				if (num < 10)	// num is a number
					snprintf(new_call.number + i,
						 NUMBER_MAX, "%d", num);
				else {
					if (num == 10)	// num is '*'
						new_call.number[i] = '*';
					else
						new_call.number[i] = '#';
				}
			}
			// set complete dialstring at once:
			else if (new_call.direction ==
				 NBD_PHONE_CALL_OUTGOING
				 && number_called != NULL && num == -1) {

				while ((number_called[i] == '#'
					|| number_called[i] == '*'
					|| number_called[i] == '+'
					|| (number_called[i] >= '0'
					    && number_called[i] <= '9')))
					i++;
				strncpy(new_call.number, number_called, i);	// copy called number
			}
		}
	}
	// case of an incoming call while calling
	else {
	}
	return 0;
}

int nbd_voip_type_call(unsigned short type_call)
{
	if (new_call.type != NBD_PHONE_CALL_COMPLEX && new_call.length == -1)
		new_call.type = type_call;

#ifndef NB5
	/* hookflash case when having a call */
	if (type_call == NBD_PHONE_CALL_COMPLEX && new_call.length == 0) {
		memset(new_call.number, '\0', NUMBER_MAX);
		new_call.type = type_call;
	}
#endif

	nbd_voip_upgrade();

	return 0;
}

/* Timer is managed here */

int nbd_voip_duration_call(int start_stop_call)
{
	if (start_stop_call == NBD_PHONE_START_CALL && new_call.length == -1) {
		time(&(new_call.start));
		new_call.length = 0;
#ifndef NB5
		if (strncmp
		    (new_call.number, "999", sizeof new_call.number) == 0)
			new_call.type = NBD_PHONE_CALL_PSTN;
#endif
	}
	// case of NB4 end of call
	else if (start_stop_call == NBD_PHONE_STOP_CALL && new_call.length == 0) {
		time(&(new_call.finish));
		new_call.length = new_call.finish - new_call.start;
		if (nbd_voip_register_call("stop_call") != 0) {
			return -1;
		}
	} else if (start_stop_call == NBD_PHONE_STOP_CALL
		   && new_call.length == -1) {
		if (nbd_voip_register_call("ring_stop") != 0) {
			return -1;
		}
	}
#ifdef NB5
	/* case of a conf call NB5 */
	else if (start_stop_call == NBD_PHONE_START_CALL
		 && new_call.length == 0) {
		new_call.type = NBD_PHONE_CALL_COMPLEX;
	}
#endif

	nbd_voip_upgrade();

	return 0;
}

int nbd_voip_register_call(char *call)
{
	call_log my_call;

	/* "ring_stop" means that the phone has stopped ringing if length
	 * is equal to -1, the call has been missed, and we register it
	 * "stop_call" means that the call is over, so we register the call if it has been started */
#ifdef NB5
	memcpy(&my_call, &new_call, sizeof(call_log));
	resetCall(&new_call);

	if ((my_call.length == -1 &&
	     (my_call.direction == NBD_PHONE_CALL_INCOMING
	      || my_call.direction == NBD_PHONE_CALL_OUTGOING)
	     && strncmp(call, "ring_stop", strlen("ring_stop")) == 0)
	    || (my_call.length >= 0
		&& strncmp(call, "stop_call", strlen("stop_call")) == 0)) {
#else
	if ((new_call.length == -1
	     && new_call.direction == NBD_PHONE_CALL_INCOMING
	     && strncmp(call, "ring_stop", strlen("ring_stop")) == 0)
	    || (new_call.length >= 0
		&& strncmp(call, "stop_call", strlen("stop_call")) == 0)
	    || (new_call.length >= 0 &&
		new_call.direction == NBD_PHONE_CALL_OUTGOING
		&& strncmp(call, "ring_stop", strlen("ring_stop")) == 0)) {

		memcpy(&my_call, &new_call, sizeof(call_log));
		resetCall(&new_call);
#endif

		nbd_voip_upgrade();

		if (nbd_user_config_matches("voip_callhistory", "on")) {
			char type[32];
			char direction[32];
			char number[32];
			char length[32];
			char _date[32];

			// Warning: COMPLEX call is not taken into account here
			if (my_call.type != NBD_PHONE_CALL_COMPLEX
			    && my_call.type != NBD_PHONE_CALL_UNINIT)
				snprintf(type, sizeof(type), "%hu",
					 my_call.type);
			else
				snprintf(type, sizeof(type), "%hu",
					 NBD_PHONE_CALL_VOIP);

			if (my_call.direction != NBD_PHONE_CALL_OUTGOING)
				snprintf(direction, sizeof(direction), "%hu",
					 NBD_PHONE_CALL_INCOMING);
			else
				snprintf(direction, sizeof(direction), "%hu",
					 my_call.direction);

			/* Remove number if this is the result of a double call
			 * or a conference */
			if (my_call.type == NBD_PHONE_CALL_COMPLEX) {
				memset(my_call.number, '\0', NUMBER_MAX);
			}
			strcpy(number, my_call.number);

			snprintf(length, sizeof(length), "%ld", my_call.length);

			if (my_call.date == -1)
				time(&(my_call.date));
			snprintf(_date, sizeof(_date), "%ld", my_call.date);

			/* add a call to the list */
			if (nbd_set("voip", "history_call_add",
				    type, direction, number, length,
				    _date) != 0)
				return -1;
		}
	}

	/* PMI 29/02/2008 missed incoming call -> setting green led blinking */
	if (my_call.direction == NBD_PHONE_CALL_INCOMING
	    && my_call.length == -1) {
		nbd_set("voip", "misscalls", NULL);
	}

	return 0;
}

static void nbd_voip_upgrade(void)
{
	if (new_call.length == -1
	    && new_call.direction != NBD_PHONE_CALL_INCOMING) {
		/* upgrade authorized */
		nbd_status_set("voip_upgrade", "ok");
		return;
	} else {
		/* otherwise, upgrade not authorized because phone already in a com or ringing */
		nbd_status_set("voip_upgrade", "ko");
		return;
	}
}

void nbd_voip_manage_missed_calls(void)
{
	nbd_set("voip", "stopmisscalls", NULL);
}
