
extern "C"{
#include "ngx_tcp_log.h"
#include <stdlib.h>
#include <stdint.h>
#include <alloca.h>
#include "test_protocol.h"
}
#include "test_impl.h"

 
void* test_cfg_new(ngx_conf_t* cf)
{
	test_config_t* testcfg =  (test_config_t*)ngx_palloc(cf->pool, sizeof(test_config_t));
	testcfg->cf = cf;
	
	return testcfg;
} 

/**
 * 配置初始化
 */
int test_cfg_init(const char* config, void* appcfg,ngx_tcp_core_srv_conf_t* core_cfg)
{
	test_config_t* testcfg = (test_config_t*)appcfg;
	CIniFile inifile(config);
	if(!inifile.ReadFile()){
		CONF_ERROR("read config [%s] failed! err: %s", config, strerror(errno));
		return NGX_ERROR;
	} 

	string ip = inifile.GetValue("backend", "ip", "127.0.0.1");
	strncpy(testcfg->backend_ip, ip.c_str(), sizeof(testcfg->backend_ip));
	testcfg->backend_port = inifile.GetValueI("backend", "port", 2014);
	
	mysql_config_read(&inifile, &testcfg->mysql_config, "mysql");
	//这一步很重要，当使用异步方式时，timeout必须为0，否则mysql_connect会出错。
	#ifndef NOT_USE_ASYNC
	if(core_cfg->use_async){
		testcfg->mysql_config.timeout = 0;
	}
	#endif
	return NGX_OK;
}

void* test_ctx_new(ngx_cycle_t* cycle, void* appcfg)
{
	//test_config_t* cfg = (test_config_t*)appcfg;
	test_ctx_t* ctx = (test_ctx_t*)ngx_palloc(cycle->pool, sizeof(test_ctx_t));
	ctx->cycle = cycle;
		
	return ctx;
}

/**
 * 上下文初始化
 */
int test_ctx_init(void* appcfg, void* appctx)
{
	//int ret = 0;    
	test_ctx_t* ctx = (test_ctx_t*)appctx;
	test_config_t* cfg = (test_config_t*)appcfg;
	ctx->mysql_pool = mysql_pool_new(cfg->mysql_config.conns, &cfg->mysql_config);
	LOG_INFO("[%d] mysql_pool: %p", ngx_getpid(), ctx->mysql_pool);

	return NGX_OK;  
}

inline void test_ctx_destroy(ngx_cycle_t* cycle, void* appctx)
{
	test_ctx_t* ctx = (test_ctx_t*)appctx;
	mysql_pool_free(ctx->mysql_pool);
	ctx->mysql_pool = NULL;	
}

inline void test_cfg_destroy(ngx_cycle_t* cycle, void* appcfg)
{
	//test_config_t* testcfg = (test_config_t*)appcfg;
	
}

inline void test_exit_master(ngx_cycle_t* cycle){
	
}

inline req_head_t* test_ngx_new_req_head(ngx_pool_t* pool)
{
	req_header_t* header = (req_header_t*)NGX_TCP_PALLOC(pool,sizeof(req_header_t));
	//LOG_DEBUG("################ new req header ###################");
	return header;
}


inline rsp_head_t* test_ngx_new_rsp_head(ngx_pool_t* pool, req_head_t* req_head)
{
	req_header_t* reqheader = (req_header_t*)req_head;
	rsp_header_t* header = (rsp_header_t*)NGX_TCP_PALLOC(pool, sizeof(rsp_header_t));

	header->cmd = reqheader->cmd; 
	header->seq = reqheader->seq;
	
	
	return header;
}

inline size_t test_ngx_tcp_get_req_body_size(req_head_t* header)
{
	req_header_t* reqheader = (req_header_t*)header;
	return reqheader->len;
}

inline size_t test_ngx_tcp_get_rsp_body_size(rsp_head_t* header)
{
	rsp_header_t* rspheader = (rsp_header_t*)header;
	//LOG_DEBUG("rsp body size: %d", rspheader->rsplen+6);
	return rspheader->len;
}

inline int test_preproc_req_header(ngx_tcp_req_t* req)
{
	req_header_t* reqheader = (req_header_t*)req->req_header;
	LOG_HEADER("REQ:", reqheader);
	if(reqheader->magic != TEST_MAGIC){
		//验证magic出错了。
		LOG_ERROR("Invalid Request from [%V]", &req->c->addr_text);
		return -1;
	}
	
	//接收完成后对请求头进行一些处理(比如字节序转换)
	
	//LOG_DEBUG(" [%s] reqlen:%d", req->c->clientaddr, reqheader->reqlen);

	return 0;
}

inline int test_preproc_req_body(ngx_tcp_req_t* req)
{

	return 0;
}


inline int test_preproc_rsp_header(ngx_tcp_rsp_t* rsp)
{
	rsp_header_t* rspheader = (rsp_header_t*)rsp->rsp_header;
	LOG_HEADER("RSP:", rspheader);

	return 0;
}
 
inline int test_preproc_rsp_body(ngx_tcp_rsp_t* rsp)
{
	return 0;
}


inline void test_ngx_set_rsp_code(ngx_tcp_rsp_t* rsp, int ret)
{
	//rsp_header_t* rspheader = (rsp_header_t*)rsp->rsp_header;
	
	//rspheader->result = ret;
}


inline void test_ngx_tcp_free_req(ngx_pool_t* pool,ngx_tcp_req_t* req)
{
	if(req != NULL){ 
		NGX_TCP_PFREE(pool, req->req_header)
		NGX_TCP_PFREE(pool, req->body)
		NGX_TCP_PFREE(pool, req);
	}
}

inline void test_ngx_tcp_free_rsp(ngx_pool_t* pool,ngx_tcp_rsp_t* rsp)
{
	if(rsp != NULL){
		NGX_TCP_PFREE(pool, rsp->rsp_header);
		NGX_TCP_PFREE(pool, rsp->body);
		NGX_TCP_PFREE(pool, rsp);
	}
}

inline void test_ngx_tcp_debug_req(ngx_tcp_req_t* req){
	
}

inline void test_ngx_tcp_debug_rsp(ngx_tcp_rsp_t* rsp){

}

static const char* szTestServiceNames[] = 
{	
	"INIT",
	"ADD",
	"SUB",
	"QUERY",
	"SLEEP",
	NULL
};

const char* test_ngx_tcp_get_service_name(ngx_tcp_req_t* req)
{
	req_header_t* header = (req_header_t*)req->req_header;
	if(header->cmd <= 4){
		return szTestServiceNames[header->cmd];
	}
	
	return "UnknowService";
}

inline void test_ngx_tcp_debug_stats(ngx_tcp_data_t* data){
	const char* serviceName = test_ngx_tcp_get_service_name(data->req_data);
	//req_header_t* req_header = (req_header_t*)data->req_data->req_header;

	LOG_DEBUG("STAT [%s] all=%.4f,{recv=%.4f,proc=%.4f,send=%.4f}", 
			serviceName, data->stat.all,
			data->stat.recv_req,
			data->stat.proc,
			data->stat.send_rsp);
}



app_ctx_t g_app_ctx ={&test_cfg_new,&test_cfg_init,&test_ctx_new,
			&test_ctx_init,&test_ctx_destroy, &test_cfg_destroy,NULL};

static ngx_tcp_protocol_info_t g_tcp_cbs_test =
{
	sizeof(req_header_t),sizeof(rsp_header_t),
	&test_ngx_tcp_get_req_body_size,
	&test_ngx_tcp_get_rsp_body_size,
	&test_ngx_new_req_head,
	&test_ngx_new_rsp_head,
	&test_preproc_req_header,
	&test_preproc_req_body, /*preproc_req_body*/
	&test_preproc_rsp_header, 
	&test_preproc_rsp_body, /*preproc_rsp_body*/
	&test_ngx_tcp_free_req,
	&test_ngx_tcp_free_rsp,
	&test_ngx_tcp_debug_req,
	&test_ngx_tcp_debug_rsp,
	&test_ngx_set_rsp_code,
	&test_ngx_tcp_debug_stats, /*debug_stats*/
	NULL  /*req_again*/
};


int test_set_callbacks(ngx_tcp_data_t* tcp_data){
	memcpy(&tcp_data->protocbs, &g_tcp_cbs_test, sizeof(tcp_data->protocbs));
	tcp_data->tcp_proc = &test_proc;
	return 0;
}

ngx_set_callbacks_pt g_tcp_set_callbacks = &test_set_callbacks;

