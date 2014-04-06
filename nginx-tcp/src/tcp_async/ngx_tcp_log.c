//#line 2 "ngx_bizlog_mod.c"
#include <sys/stat.h>
#include <unistd.h>

#include "ngx_tcp_log.h"
 
typedef struct {
	ngx_flag_t enable;
	ngx_str_t logfile;
	ngx_str_t debugfile;
	ngx_int_t log_level;
} bizlog_svr_conf_t;
 
LOG_LEVEL g_NlogLevel = NL_NONE;

ngx_open_file_t* g_biz_logger = NULL;
ngx_open_file_t* g_biz_debuger = NULL;

LOG_LEVEL NInt2LogLevel(int logLevel){
	LOG_LEVEL level;
	if(logLevel <= NL_NONE){
		level = NL_NONE;
	}else if(logLevel >= NL_ALL){
		level = NL_ALL;
	}else{
		level = (LOG_LEVEL)logLevel;
	}

	return level;
}

const char* NGetFileName(const char* fullname)
{
	const char* pFilename = strrchr((char*)fullname, '/');
	if(pFilename == NULL){
		pFilename = fullname;
	}else{	
		pFilename++;
	}

	return pFilename;	
}

inline void NWriteLog(const char* log, int size){
	if(g_biz_logger!=NULL && g_biz_logger->fd > 0){
		ngx_write_fd(g_biz_logger->fd, (void*)log,size);
	}
}

inline void NWriteDebugLog(const char* log, int size){
	if(g_biz_debuger!=NULL && g_biz_debuger->fd > 0){
		ngx_write_fd(g_biz_debuger->fd, (void*)log,size);
	}
}
 
ngx_int_t  ngx_tcp_bizlog_init_process(ngx_cycle_t *cycle)
{
	if(g_biz_logger != NULL){
		dup2(g_biz_logger->fd, fileno(stderr));
	}
	if(g_biz_debuger != NULL){
		dup2(g_biz_debuger->fd, fileno(stdout));	
	}
	
	return 0;
}


#define LOG_TF "%02d-%02d %02d:%02d:%02d "
#define LOG_BUF_LEN (1024*2)

void NPrint(NLogCb LogCb,const char* LEVEL, const char* funcName, 
			const char* fileName, int line,  const char* format,  ...){
#define buf_rest(buf, p) (buf+LOG_BUF_LEN-p-1)
	u_char logbuf[LOG_BUF_LEN];	
	memset(logbuf, 0, LOG_BUF_LEN);
	u_char* p = logbuf; 
	//不显示日志时间。
	time_t timep;
	struct tm *ptm, mytm;
	timep = ngx_time();
	ptm = localtime_r(&timep, &mytm); 
	
	p = ngx_snprintf(p, buf_rest(logbuf, p), LOG_TF "%s:%s[%s:%d] ", 
			1+ptm->tm_mon, ptm->tm_mday,  
			ptm->tm_hour, ptm->tm_min, ptm->tm_sec, 
			LEVEL, funcName, fileName, line); 

	va_list   args;
	va_start(args,format); 
	p = ngx_vslprintf(p ,  logbuf+LOG_BUF_LEN-2, format, args);
	va_end(args); 
	if(buf_rest(logbuf, p) > 0){ 
 		p = ngx_snprintf(p, buf_rest(logbuf, p), "\n");
	}
	logbuf[LOG_BUF_LEN-1] = 0;
	if(LogCb == NULL){
		fprintf(stderr, "%.*s", (int)(p-logbuf), logbuf);
	}else{
 		LogCb((const char*)logbuf, p-logbuf);
 	}
}

 
void NPrintBig(NLogCb LogCb,const char* LEVEL, const char* funcName, 
			const char* fileName, int line,  const char* format,  ...){
#define LOG_BIGBUF_LEN (1024*32)
#define big_buf_rest(buf, p) (buf+LOG_BIGBUF_LEN-p-1)
	u_char logbuf[LOG_BIGBUF_LEN];	
	memset(logbuf, 0, LOG_BIGBUF_LEN);
	u_char* p = logbuf; 
	//不显示日志时间。
	time_t timep;
	struct tm *ptm, mytm;
	timep = ngx_time();
	ptm = localtime_r(&timep, &mytm); 
	
	p = ngx_snprintf(p, big_buf_rest(logbuf, p), LOG_TF "%s:%s[%s:%d] ", 
			1+ptm->tm_mon, ptm->tm_mday,  
			ptm->tm_hour, ptm->tm_min, ptm->tm_sec, 
			LEVEL, funcName, fileName, line); 

	va_list   args;
	va_start(args,   format); 
	p = ngx_vslprintf(p ,  logbuf+LOG_BIGBUF_LEN-2, format , args);
	va_end(args); 
	if(big_buf_rest(logbuf, p) > 0){ 
 		p = ngx_snprintf(p, big_buf_rest(logbuf, p), "\n");
	}
	logbuf[LOG_BIGBUF_LEN-1] = 0;
	if(LogCb == NULL){
		fprintf(stderr, "%.*s", (int)(p-logbuf), logbuf);
	}else{
 		LogCb((const char*)logbuf, p-logbuf);
 	}
}


