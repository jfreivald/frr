#ifndef DEBUG_PREFIX_H
#define DEBUG_PREFIX_H

#define LOGGER_BUFFER_SIZE		8192
#define LOGGER_BT_SIZE			32

#define LOGGER_BT_W_VALGRIND

#ifdef LOGGER_BT_W_VALGRIND
#include <valgrind/valgrind.h>
#else
#include <execinfo.h>
#endif

#include <stdint.h>

#define LOGGER_NO_MODULE 			(0)
#define LOGGER_LIB					(1)
#define LOGGER_ZEBRA				(2)
#define LOGGER_EIGRP				(3)

#define LOGGER_NO_LIB				(0)
#define LOGGER_LIB_LIST				(0x0001)
#define LOGGER_LIB_PREFIX			(0x0002)

#define LOGGER_NO_ZEBRA				(0)
#define LOGGER_ZEBRA_ROUTES			(0x0001)
#define LOGGER_ZEBRA_API			(0x0002)
#define LOGGER_ZEBRA_INTERFACE		(0x0004)

#define LOGGER_NO_EIGRP 			(0)
#define LOGGER_EIGRP_HELLO 			(0x0001)
#define LOGGER_EIGRP_UPDATE 		(0x0002)
#define LOGGER_EIGRP_QUERY 			(0x0004)
#define LOGGER_EIGRP_FSM 			(0x0008)
#define LOGGER_EIGRP_ZEBRA	 		(0x0010)
#define LOGGER_EIGRP_TOPOLOGY 		(0x0020)
#define LOGGER_EIGRP_INTERFACE 		(0x0040)
#define LOGGER_EIGRP_LISTS	 		(0x0080)
#define LOGGER_EIGRP_TABLES 		(0x0100)
#define LOGGER_EIGRP_NEIGHBOR		(0x0200)
#define LOGGER_EIGRP_PACKET			(0x0400)
#define LOGGER_EIGRP_NETWORK		(0x0800)
#define LOGGER_EIGRP_REPLY			(0x1000)
#define LOGGER_EIGRP_TRACE			(0x8000)

#define L(logfunc,m,f,...)     _logger(logfunc,m,f,__FILE__,__PRETTY_FUNCTION__,__LINE__,errno,__VA_ARGS__)
void _logger(void (logfunc(const char *format, ...)), uint32_t module, uint32_t flags, const char *file, const char *func, int line, int e, const char *fmt, ...);

#define LBT(logfunc,m,f,...)   _logger_backtrace(logfunc,m,f,__FILE__,__PRETTY_FUNCTION__,__LINE__,errno,__VA_ARGS__)
void _logger_backtrace(void (logfunc(const char *format, ...)), uint32_t module, uint32_t flags, const char *file, const char *func, int line, int e, const char *fmt, ...);

#endif //DEBUG_PREFIX_H
