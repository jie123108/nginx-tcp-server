#ifndef __TESTLOG_H__
#define __TESTLOG_H__
#include <stdio.h>
 #include <sys/time.h>

 #ifndef __NGX_TCP_LOG_H__
#define LOG_DEBUG(format, args...); printf("DEBUG %s:%d "format"\n", __FILE__,__LINE__,##args);
#define LOG_INFO(format, args...);    printf("INFO  %s:%d "format"\n", __FILE__,__LINE__,##args);
#define LOG_WARN(format, args...);  printf("WARN  %s:%d "format"\n", __FILE__,__LINE__,##args);
#define LOG_ERROR(format, args...); printf("ERROR %s:%d "format"\n", __FILE__,__LINE__,##args);
#endif
inline double second(void) {
    struct timeval tv;
    gettimeofday(&tv,NULL); 
    return tv.tv_sec+tv.tv_usec/1000000.0;
}

#endif

