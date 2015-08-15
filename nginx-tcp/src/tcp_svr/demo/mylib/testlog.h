#ifndef __TESTlog_H__
#define __TESTlog_H__
#include <stdio.h>
#include <sys/time.h>

#ifndef NGX_TCP_SERVER
#define NLOG_DEBUG(format, args...); printf("DEBUG %s:%d "format"\n", __FILE__,__LINE__,##args);
#define NLOG_INFO(format, args...);    printf("INFO  %s:%d "format"\n", __FILE__,__LINE__,##args);
#define NLOG_WARN(format, args...);  printf("WARN  %s:%d "format"\n", __FILE__,__LINE__,##args);
#define NLOG_ERROR(format, args...); printf("ERROR %s:%d "format"\n", __FILE__,__LINE__,##args);
#endif
inline double second(void) {
    struct timeval tv;
    gettimeofday(&tv,NULL); 
    return tv.tv_sec+tv.tv_usec/1000000.0;
}

#endif

