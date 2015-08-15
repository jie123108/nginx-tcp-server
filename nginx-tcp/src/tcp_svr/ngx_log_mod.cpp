//#line 2 "ngx_bizlog_mod.c"
extern "C" {
#include <ngx_stream.h>
}
#include <sys/stat.h>
#include <unistd.h>
#include "ngx_log_mod.h"

typedef struct {
	ngx_flag_t enable;
	ngx_str_t logfile;
	ngx_str_t debugfile;
	ngx_int_t log_level;
} bizlog_svr_conf_t;
 
NLOG_LEVEL g_NlogLevel = NL_NONE;

ngx_open_file_t* g_biz_logger = NULL;
ngx_open_file_t* g_biz_debuger = NULL;

NLOG_LEVEL NInt2LogLevel(int logLevel){
	NLOG_LEVEL level;
	if(logLevel <= NL_NONE){
		level = NL_NONE;
	}else if(logLevel >= NL_ALL){
		level = NL_ALL;
	}else{
		level = (NLOG_LEVEL)logLevel;
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

void NWriteLog(const char* log, int size){
	if(g_biz_logger!=NULL && g_biz_logger->fd > 0){
		ngx_write_fd(g_biz_logger->fd, (void*)log,size);
	}
}

void NWriteDebugLog(const char* log, int size){
	if(g_biz_debuger!=NULL && g_biz_debuger->fd > 0){
		ngx_write_fd(g_biz_debuger->fd, (void*)log,size);
	}
}

char* ngx_stream_bizlog_init(ngx_conf_t *cf, bizlog_svr_conf_t *cscf)
{
	//BlSetLogLevel(BlInt2LogLevel(cscf->log_level));
	//BlSetLogCb(&WriteLog, &WriteDebugLog);

   	g_biz_logger = ngx_conf_open_file(cf->cycle,&cscf->logfile);
	if(g_biz_logger == NULL){
		return (char*)NGX_CONF_ERROR;
	}
	
	g_biz_debuger = ngx_conf_open_file(cf->cycle,&cscf->debugfile);
	if(g_biz_debuger == NULL){
		return (char*)NGX_CONF_ERROR;
	}
	
	
	
	g_NlogLevel = NInt2LogLevel(cscf->log_level);
	
	//cf->cycle->conf_ctx[ngx_stream_bizlog_module.index] = (void***)cscf;


   	return NGX_CONF_OK;
}

 
ngx_int_t  ngx_stream_bizlog_init_process(ngx_cycle_t *cycle)
{
	if(g_biz_logger != NULL){
		dup2(g_biz_logger->fd, fileno(stderr));
	}
	if(g_biz_debuger != NULL){
		dup2(g_biz_debuger->fd, fileno(stdout));	
	}
	
	return 0;
}

//static char* ngx_stream_bizlog_mod(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void* ngx_stream_bizlog_create_srv_conf(ngx_conf_t *cf);

static char* ngx_stream_bizlog_merge_srv_conf(ngx_conf_t *cf,void *parent, void *child);

static ngx_conf_enum_t ngx_stream_bizlog_loglevels[] = {
		{ngx_string("0"), 0},
		{ngx_string("1"), 1},
		{ngx_string("2"), 2},
		{ngx_string("3"), 3},
		{ngx_string("4"), 4},
		{ngx_string("5"), 5},
		{ngx_string("error"), 0},
		{ngx_string("warn"), 1},
		{ngx_string("info"), 2},
		{ngx_string("debug"), 3},
		{ngx_string("debug2"), 4},
		{ngx_string("all"), 5}
};

static ngx_command_t  ngx_stream_bizlog_commands[] = {
    
    { ngx_string("bizlog"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(bizlog_svr_conf_t, enable),
      NULL },
    { ngx_string("log_level"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot, 
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(bizlog_svr_conf_t, log_level),
      ngx_stream_bizlog_loglevels},
    { ngx_string("logfile"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(bizlog_svr_conf_t, logfile),
      NULL },
    { ngx_string("debugfile"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(bizlog_svr_conf_t, debugfile),
      NULL },

      ngx_null_command
};

static ngx_stream_module_t  ngx_stream_bizlog_module_ctx = {
    NULL,   				        /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,  						   /* init main configuration */

    ngx_stream_bizlog_create_srv_conf,                          /* create server configuration */
    ngx_stream_bizlog_merge_srv_conf                          /* merge server configuration */
};


ngx_module_t  ngx_stream_bizlog_module = {
    NGX_MODULE_V1,
    &ngx_stream_bizlog_module_ctx, /* module context */
    ngx_stream_bizlog_commands,   /* module directives */
    NGX_STREAM_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    &ngx_stream_bizlog_init_process, /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,      /* exit process */
    NULL,      /* exit master */
    NGX_MODULE_V1_PADDING
};

static void* ngx_stream_bizlog_create_srv_conf(ngx_conf_t *cf)
{
    bizlog_svr_conf_t  *conf;

    conf = (bizlog_svr_conf_t*)ngx_pcalloc(cf->pool, sizeof(bizlog_svr_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
	conf->log_level = NGX_CONF_UNSET;
	conf->enable = NGX_CONF_UNSET;
	
	ngx_memzero(&conf->logfile, sizeof(ngx_str_t));
	ngx_memzero(&conf->debugfile, sizeof(ngx_str_t));
	
    return conf;
}

static char *
ngx_stream_bizlog_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    bizlog_svr_conf_t *prev = (bizlog_svr_conf_t*)parent;
    bizlog_svr_conf_t *conf = (bizlog_svr_conf_t*)child;

	ngx_conf_merge_value(conf->log_level, prev->log_level, (ngx_int_t)NL_INFO);
	ngx_conf_merge_value(conf->enable, prev->enable, 0);
	ngx_conf_merge_str_value(conf->logfile, prev->logfile, "logs/ngx_biz.log");
	ngx_conf_merge_str_value(conf->debugfile, prev->debugfile, "logs/ngx_biz.debug");

	if(conf->enable){
		return ngx_stream_bizlog_init(cf, conf);
	}
   return NGX_CONF_OK;
}


#define NLOG_TF "%02d-%02d %02d:%02d:%02d "
#define NLOG_BUF_LEN (1024*2)

void NPrint(NLogCb LogCb,const char* LEVEL, const char* funcName, 
			const char* fileName, int line,  const char* format,  ...){
#define buf_rest(buf, p) (buf+NLOG_BUF_LEN-p-1)
	u_char logbuf[NLOG_BUF_LEN];	
	memset(logbuf, 0, NLOG_BUF_LEN);
	u_char* p = logbuf; 
	//不显示日志时间。
	time_t timep;
	struct tm *ptm, mytm;
	timep = ngx_time();
	ptm = localtime_r(&timep, &mytm); 
	
	p = ngx_snprintf(p, buf_rest(logbuf, p), NLOG_TF "%s:%s[%s:%d] ", 
			1+ptm->tm_mon, ptm->tm_mday,  
			ptm->tm_hour, ptm->tm_min, ptm->tm_sec, 
			LEVEL, funcName, fileName, line); 

	va_list   args;
	va_start(args,format); 
	p = ngx_vslprintf(p ,  logbuf+NLOG_BUF_LEN-2, format, args);
	va_end(args); 
	if(buf_rest(logbuf, p) > 0){ 
 		p = ngx_snprintf(p, buf_rest(logbuf, p), "\n");
	}
	logbuf[NLOG_BUF_LEN-1] = 0;
	if(LogCb == NULL){
		fprintf(stderr, "%.*s", (int)(p-logbuf), logbuf);
	}else{
 		LogCb((const char*)logbuf, p-logbuf);
 	}
}

 
void NPrintBig(NLogCb LogCb,const char* LEVEL, const char* funcName, 
			const char* fileName, int line,  const char* format,  ...){
#define NLOG_BIGBUF_LEN (1024*32)
#define big_buf_rest(buf, p) (buf+NLOG_BIGBUF_LEN-p-1)
	u_char logbuf[NLOG_BIGBUF_LEN];	
	memset(logbuf, 0, NLOG_BIGBUF_LEN);
	u_char* p = logbuf; 
	//不显示日志时间。
	time_t timep;
	struct tm *ptm, mytm;
	timep = ngx_time();
	ptm = localtime_r(&timep, &mytm); 
	
	p = ngx_snprintf(p, big_buf_rest(logbuf, p), NLOG_TF "%s:%s[%s:%d] ", 
			1+ptm->tm_mon, ptm->tm_mday,  
			ptm->tm_hour, ptm->tm_min, ptm->tm_sec, 
			LEVEL, funcName, fileName, line); 

	va_list   args;
	va_start(args,   format); 
	p = ngx_vslprintf(p ,  logbuf+NLOG_BIGBUF_LEN-2, format , args);
	va_end(args); 
	if(big_buf_rest(logbuf, p) > 0){ 
 		p = ngx_snprintf(p, big_buf_rest(logbuf, p), "\n");
	}
	logbuf[NLOG_BIGBUF_LEN-1] = 0;
	if(LogCb == NULL){
		fprintf(stderr, "%.*s", (int)(p-logbuf), logbuf);
	}else{
 		LogCb((const char*)logbuf, p-logbuf);
 	}
}


