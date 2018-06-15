#ifndef DEBUG_PREFIX_H
#define DEBUG_PREFIX_H

#define LOGGER_BUFFER_SIZE	2048

#define L(logfunc,...)     _logger(logfunc,__FILE__,__PRETTY_FUNCTION__,__LINE__,errno,__VA_ARGS__)
void _logger(void (logfunc(const char *format, ...)), const char *file, const char *func, int line, int e, const char *fmt, ...);

#endif
