#ifndef __NGX_LOG_MOD_H__
#define __NGX_LOG_MOD_H__
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <string.h>
}
typedef enum NLOG_LEVEL{
	NL_NONE=-1,
	NL_ERROR =0,
	NL_WARN,
	NL_INFO,
	NL_DEBUG,
	NL_DEBUG2,
	NL_ALL
}NLOG_LEVEL;

extern NLOG_LEVEL g_NlogLevel;

typedef void (*NLogCb)(const char* log, int size);

void NWriteLog(const char* log, int size);
void NWriteDebugLog(const char* log, int size);

void NPrint(NLogCb LogCb,const char* LEVEL, const char* funcName, 
			const char* fileName, int line,  const char* format,  ...);
void NPrintBig(NLogCb LogCb,const char* LEVEL, const char* funcName, 
			const char* fileName, int line,  const char* format,  ...);

const char* NGetFileName(const char* fullname);

#define NLFILE NGetFileName(__FILE__)

/*
 * supported formats:
 *    %[0][width][x][X]O        off_t
 *    %[0][width]T              time_t
 *    %[0][width][u][x|X]z      ssize_t/size_t
 *    %[0][width][u][x|X]d      int/u_int
 *    %[0][width][u][x|X]l      long
 *    %[0][width|m][u][x|X]i    ngx_int_t/ngx_uint_t
 *    %[0][width][u][x|X]D      int32_t/uint32_t
 *    %[0][width][u][x|X]L      int64_t/uint64_t
 *    %[0][width|m][u][x|X]A    ngx_atomic_int_t/ngx_atomic_uint_t
 *    %[0][width][.width]f      double, max valid number fits to %18.15f
 *    %P                        ngx_pid_t
 *    %M                        ngx_msec_t
 *    %r                        rlim_t
 *    %p                        void *
 *    %V                        ngx_str_t *
 *    %v                        ngx_variable_value_t *
 *    %s                        null-terminated string
 *    %*s                       length and string
 *    %Z                        '\0'
 *    %N                        '\n'
 *    %c                        char
 *    %%                        %
 *
 *  reserved:
 *    %t                        ptrdiff_t
 *    %S                        null-terminated wchar string
 *    %C                        wchar
 */


#define NLOG_DEBUG(format, args...) \
		if(g_NlogLevel>=NL_DEBUG)NPrint(NWriteDebugLog,"DEBUG", __FUNCTION__, NLFILE, __LINE__, format, ##args)
#define NLOG_DEBUG2(format, args...) \
		if(g_NlogLevel>=NL_DEBUG2)NPrint(NWriteDebugLog,"DEBUG2", __FUNCTION__, NLFILE, __LINE__, format, ##args)
#define NLOG_DEBUG2_BIG(format, args...) \
		if(g_NlogLevel>=NL_DEBUG2)NPrintBig(NWriteDebugLog,"DEBUG2", __FUNCTION__, NLFILE, __LINE__, format, ##args)
#define NLOG_INFO(format, args...) \
		if(g_NlogLevel>=NL_INFO)NPrint(NWriteLog," INFO", __FUNCTION__, NLFILE, __LINE__, format, ##args)
#define NLOG_WARN(format, args...) \
		if(g_NlogLevel>=NL_WARN)NPrint(NWriteLog," WARN", __FUNCTION__, NLFILE, __LINE__, format, ##args)
#define NLOG_ERROR(format, args...) \
		if(g_NlogLevel>=NL_ERROR)NPrint(NWriteLog,"ERROR", __FUNCTION__, NLFILE, __LINE__, format, ##args)

#define NLOG(format, args...) NPrint(NWriteLog,"LOG", __FUNCTION__, NLFILE, __LINE__, format, ##args)

//#define TEST_LOG 1
#ifdef TEST_LOG
#define NLOG_TEST(format, args...) \
		NPrint(NWriteLog,"TEST", __FUNCTION__, NLFILE, __LINE__, format, ##args)
#else
#define NLOG_TEST(format, args...) 
#endif

#define CONF_ERROR(format, args...);{\
	u_char buf[1024*4];\
	ngx_memset(buf,0,sizeof(buf));\
	ngx_sprintf(buf,"ERROR: %s:%d"format"\n",__FILE__,__LINE__,##args);\
	printf((const char*)buf);}

#define CONF_INFO(format, args...); {\
	u_char buf[1024*4];\
	ngx_memset(buf,0,sizeof(buf));\
	ngx_sprintf(buf,"INFO : %s:%d"format"\n",__FILE__,__LINE__,##args);\
	printf((const char*)buf);}

extern ngx_open_file_t* g_biz_logger;
extern ngx_open_file_t* g_biz_debuger;

#endif

