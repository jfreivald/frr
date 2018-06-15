#ifndef DEBUG_PREFIX_H
#define DEBUG_PREFIX_H

#define LOGGER_BUFFER_SIZE	2048

#define P(...)     _logger(logfunc,level,__FILE__,__PRETTY_FUNCTION__,__LINE__,errno,__VA_ARGS__)

#endif
