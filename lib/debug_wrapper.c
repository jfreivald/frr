/*
 * debug_wrapper.h
 * Copyright (C) 2018 AT&T Inc., Joseph Freivald
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "debug_wrapper.h"
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

static uint32_t logger_modules = 0xFFFFFFFF;
static uint32_t logger_eigrp_flags =
		LOGGER_EIGRP_HELLO 		|
		LOGGER_EIGRP_UPDATE 	|
		LOGGER_EIGRP_QUERY 		|
		LOGGER_EIGRP_FSM 		|
		LOGGER_EIGRP_ZEBRA 		|
		LOGGER_EIGRP_TOPOLOGY 	|
		LOGGER_EIGRP_INTERFACE 	|
		LOGGER_EIGRP_LISTS 		|
		LOGGER_EIGRP_TABLES 	|
		LOGGER_EIGRP_NEIGHBOR 	|
		LOGGER_EIGRP_PACKET 	|
		LOGGER_EIGRP_NETWORK 	|
		LOGGER_EIGRP_REPLY 		|
		LOGGER_EIGRP_TRACE 		|
		LOGGER_NO_EIGRP
;
static uint32_t logger_zebra_flags = 0xFFFFFFFF;
static uint32_t logger_lib_flags = 0x0;

static inline int _logger_check_flags(uint32_t module, uint32_t flags) {
	int retval = 0;
	if (module & logger_modules) {
		switch (module) {
		case LOGGER_LIB:
			if ((flags & logger_lib_flags))
				retval = 1;
			break;
		case LOGGER_ZEBRA:
			if ((flags & logger_zebra_flags))
				retval = 1;
			break;
		case LOGGER_EIGRP:
			if ((flags & logger_eigrp_flags))
				retval = 1;
			break;
		case LOGGER_NO_MODULE:
			break;
		default:
			break;
		}
	}
	return retval;
}

void _logger(void (logfunc(const char *format, ...)), uint32_t module, uint32_t flags, const char *file, const char *func, int line, int e, const char *fmt, ...) {
	char msgbuf[LOGGER_BUFFER_SIZE];

	if (_logger_check_flags(module, flags)) {
		/*Store the file, line and system error message for the log call*/
		snprintf(msgbuf, LOGGER_BUFFER_SIZE, "[%s:%d] %s: ", file, line, func);

		/*Slurp the format and arguments passed by the user and put them at the
		 * end of the error message */
		va_list ap;
		va_start(ap, fmt);
		vsnprintf(&msgbuf[strnlen(msgbuf, LOGGER_BUFFER_SIZE)], LOGGER_BUFFER_SIZE - strnlen(msgbuf, LOGGER_BUFFER_SIZE), fmt, ap);
		va_end(ap);

		/* Make sure the buffer is NULL terminated */
		msgbuf[LOGGER_BUFFER_SIZE-1] = 0;

		logfunc("%s", msgbuf);
	}
}

void _logger_backtrace(void (logfunc(const char *format, ...)), uint32_t module, uint32_t flags, const char *file, const char *func, int line, int e, const char *fmt, ...) {

	if (_logger_check_flags(module, flags)) {
		char msgbuf[LOGGER_BUFFER_SIZE];
#ifndef LOGGER_BT_W_VALGRIND
		int n;
		void *bt[LOGGER_BT_SIZE];
#endif

		/*Store the file, line and system error message for the log call*/
		snprintf(msgbuf, LOGGER_BUFFER_SIZE, "[%s:%d] %s: ", file, line, func);

		/*Slurp the format and arguments passed by the user and put them at the
		 * end of the error message */

		va_list ap;
		va_start(ap, fmt);
		vsnprintf(&msgbuf[strnlen(msgbuf, LOGGER_BUFFER_SIZE)], LOGGER_BUFFER_SIZE - strnlen(msgbuf, LOGGER_BUFFER_SIZE), fmt, ap);
		va_end(ap);

		/* Make sure the buffer is NULL terminated */
		msgbuf[LOGGER_BUFFER_SIZE-1] = 0;

		logfunc("%s", msgbuf);

		/* Append Backtrace */
#ifdef LOGGER_BT_W_VALGRIND
		VALGRIND_PRINTF_BACKTRACE("Backtrace:");
#else
		n = backtrace(bt,LOGGER_BT_SIZE);
		backtrace_symbols_fd(bt, n, STDERR_FILENO);
#endif
		fflush(stderr);
	}
}
