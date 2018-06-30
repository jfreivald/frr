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

#define L(logfunc,...)     _logger(logfunc,__FILE__,__PRETTY_FUNCTION__,__LINE__,errno,__VA_ARGS__)
void _logger(void (logfunc(const char *format, ...)), const char *file, const char *func, int line, int e, const char *fmt, ...);

#define LBT(logfunc,...)   _logger_backtrace(logfunc,__FILE__,__PRETTY_FUNCTION__,__LINE__,errno,__VA_ARGS__)
void _logger_backtrace(void (logfunc(const char *format, ...)), const char *file, const char *func, int line, int e, const char *fmt, ...);

#ifdef LOGGER_TRACE
#define LT(logfunc,...)		_logger(logfunc,__FILE__,__PRETTY_FUNCTION__,__LINE__,errno,__VA_ARGS__)
#else
#define LT(...)
#endif //LOGGER_TRACE

#endif //DEBUG_PREFIX_H
