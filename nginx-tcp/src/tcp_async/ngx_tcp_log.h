#ifndef __NGX_TCP_LOG_H__
#define __NGX_TCP_LOG_H__
#include <ngx_config.h>
#include <ngx_core.h>
#include <string.h>

typedef enum LOG_LEVEL{
	NL_NONE=-1,
	NL_ERROR =0,
	NL_WARN,
	NL_INFO,
	NL_DEBUG,
	NL_DEBUG2,
	NL_ALL
}LOG_LEVEL;

extern LOG_LEVEL g_NlogLevel;

typedef void (*NLogCb)(const char* log, int size);

extern void NWriteLog(const char* log, int size);
extern void NWriteDebugLog(const char* log, int size);

extern void NPrint(NLogCb LogCb,const char* LEVEL, const char* funcName, 
			const char* fileName, int line,  const char* format,  ...);
extern void NPrintBig(NLogCb LogCb,const char* LEVEL, const char* funcName, 
			const char* fileName, int line,  const char* format,  ...);

extern const char* NGetFileName(const char* fullname);

#define NLFILE NGetFileName(__FILE__)

#define LOG_DEBUG(format, args...) \
		if(g_NlogLevel>=NL_DEBUG)NPrint(NWriteDebugLog,"DEBUG", __FUNCTION__, NLFILE, __LINE__, format, ##args)
#define LOG_DEBUG2(format, args...) \
		if(g_NlogLevel>=NL_DEBUG2)NPrint(NWriteDebugLog,"DEBUG2", __FUNCTION__, NLFILE, __LINE__, format, ##args)
#define LOG_DEBUG2_BIG(format, args...) \
		if(g_NlogLevel>=NL_DEBUG2)NPrintBig(NWriteDebugLog,"DEBUG2", __FUNCTION__, NLFILE, __LINE__, format, ##args)
#define LOG_INFO(format, args...) \
		if(g_NlogLevel>=NL_INFO)NPrint(NWriteLog," INFO", __FUNCTION__, NLFILE, __LINE__, format, ##args)
#define LOG_WARN(format, args...) \
		if(g_NlogLevel>=NL_WARN)NPrint(NWriteLog," WARN", __FUNCTION__, NLFILE, __LINE__, format, ##args)
#define LOG_ERROR(format, args...) \
		if(g_NlogLevel>=NL_ERROR)NPrint(NWriteLog,"ERROR", __FUNCTION__, NLFILE, __LINE__, format, ##args)

#define LOG(format, args...) NPrint(NWriteLog,"LOG", __FUNCTION__, NLFILE, __LINE__, format, ##args)

extern ngx_open_file_t* g_biz_logger;
extern ngx_open_file_t* g_biz_debuger;

#define CONF_ERROR(format, args...);{\
	u_char buf[1024*4];\
	memset((char*)buf,0,sizeof(buf));\
	ngx_sprintf(buf,"ERROR: %s:%d "format"\n",__FILE__,__LINE__,##args);\
	fprintf(stderr, (char*)buf);}

#define CONF_INFO(format, args...); {\
	u_char buf[1024*4];\
	memset((char*)buf,0,sizeof(buf));\
	ngx_sprintf(buf,"INFO : %s:%d "format"\n",__FILE__,__LINE__,##args);\
	fprintf(stderr, (char*)buf);}

LOG_LEVEL NInt2LogLevel(int logLevel);
ngx_int_t  ngx_tcp_bizlog_init_process(ngx_cycle_t *cycle);
#endif

