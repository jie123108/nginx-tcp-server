
extern "C" {
#include "ngx_tcp_session.h"
#include "ngx_tcp_log.h"
#include "test_protocol.h"
#include <string.h>
#include <errno.h>
}
#include "mylib/MysqlBase.h"
#include "test_impl.h"

#define DEF_PAGE_SIZE 25

int test_get_testkey_value(MYSQL* mysql, int* value){
	char sql[128];
	memset(sql,0,sizeof(sql));
	sprintf(sql, "select value from ngx_test where `key`='testkey'");
	int ret = mysql_query_int(mysql, sql, value);
	return ret;
}

static void test_set_rsp_data(ngx_tcp_rsp_t* rsp, void* body, int len){
	rsp_header_t* rspheader = (rsp_header_t*)rsp->rsp_header;
	//设置响应体(参数body必须是通过NGX_TCP_PALLOC分配的，不能是local的变量)
	rsp->body = body;
	rsp->body_len = len;
	//设置响应头里面的长度。
	rspheader->len = len;
}

int test_init(ngx_tcp_req_t* req, ngx_tcp_rsp_t* rsp)
{
	int ret = 0;
	test_ctx_t* ctx = (test_ctx_t*)req->tcp_data->conf->appctx;
	
#define SQL_CREATE_TBL "drop table if exists ngx_test; "\
				"create table ngx_test(`key` varchar(32) primary key,value int default 0); "\
				"insert into ngx_test values('testkey', 0);"
	MYSQL* mysql = mysql_pool_get(ctx->mysql_pool);
	if(mysql == NULL){
		LOG_ERROR("get mysql connection failed!");
		ret = ERRNO_SYSTEM;
		return ret; 
	}

	ret = mysql_queryex(mysql, SQL_CREATE_TBL);
	if(ret == 0){ 
		mysql_free_all_result(mysql);
	}else{ 
		LOG_ERROR("init table failed!ret:%d, sql:[%s]", ret, SQL_CREATE_TBL);
		ret = ERRNO_SYSTEM;
	}

	mysql_pool_put(ctx->mysql_pool, mysql);
	
	return ret;
}

int test_add(ngx_tcp_req_t* req, ngx_tcp_rsp_t* rsp)
{
	int ret = 0;
	test_ctx_t* ctx = (test_ctx_t*)req->tcp_data->conf->appctx;

	if(req->body_len != sizeof(test_add_dt)){
		LOG_ERROR("invalid request !");
		return ERRNO_REQ_INVALID;
	}
	
	test_add_dt* add = (test_add_dt*)req->body;
	
	char sql[256];
	memset(sql,0,sizeof(sql));
	sprintf(sql, "update ngx_test set value=value+%d where `key`='testkey'", add->n);

	MYSQL* mysql = mysql_pool_get(ctx->mysql_pool);

	if(mysql == NULL){
		LOG_ERROR("get mysql connection failed!");
		ret = ERRNO_SYSTEM;
		return ret; 
	} 

	ret = mysql_queryex(mysql, sql);
	if(ret != 0){
		LOG_ERROR("execute [%s] failed! ret:%d", sql, ret);
		ret = ERRNO_SYSTEM;
	}
	
	int value = 0;
	ret = test_get_testkey_value(mysql, &value);
	if(ret == 0){
		test_result_dt* result = (test_result_dt*)NGX_TCP_PALLOC(req->c->pool, sizeof(test_result_dt));
		test_set_rsp_data(rsp, result, sizeof(test_result_dt));
	}	
	
	mysql_pool_put(ctx->mysql_pool, mysql);
	
	return ret;
}

int test_sub(ngx_tcp_req_t* req, ngx_tcp_rsp_t* rsp)
{
	int ret = 0;
	//没有实现
	return ret;
}

int test_query(ngx_tcp_req_t* req, ngx_tcp_rsp_t* rsp)
{
	int ret = 0;
	test_ctx_t* ctx = (test_ctx_t*)req->tcp_data->conf->appctx;

	
	MYSQL* mysql = mysql_pool_get(ctx->mysql_pool);
	if(mysql == NULL){
		LOG_ERROR("get mysql connection failed!");
		ret = ERRNO_SYSTEM;
		return ret;
	}

	int value = 0;
	ret = test_get_testkey_value(mysql, &value);
	if(ret == 0){
		test_result_dt* result = (test_result_dt*)NGX_TCP_PALLOC(req->c->pool, sizeof(test_result_dt));
		test_set_rsp_data(rsp, result, sizeof(test_result_dt));
	}	
	
	mysql_pool_put(ctx->mysql_pool, mysql);
	
	return ret;
}

int test_sleep(ngx_tcp_req_t* req, ngx_tcp_rsp_t* rsp)
{
	int ret = 0;
	test_ctx_t* ctx = (test_ctx_t*)req->tcp_data->conf->appctx;

	if(req->body_len != sizeof(test_sleep_dt)){
		LOG_ERROR("invalid request !");
		return ERRNO_REQ_INVALID;
	}
	
	test_sleep_dt* slp = (test_sleep_dt*)req->body;
	
	char sql[256];
	memset(sql,0,sizeof(sql));
	sprintf(sql, "select sleep(%d)", slp->second);

	MYSQL* mysql = mysql_pool_get(ctx->mysql_pool);
	if(mysql == NULL){
		LOG_ERROR("get mysql connection failed!");
		ret = ERRNO_SYSTEM;
		return ret;
	} 

 	LOG_DEBUG("xxxxxxxxxxxxxxxx %P Sleep xxxxxxxxxxxxxx", ngx_getpid());
	ret = mysql_queryex(mysql, sql);
	if(ret == 0){ 
		mysql_free_all_result(mysql);
	}else{
		LOG_ERROR("execute [%s] failed! ret:%d", sql, ret);
		ret = ERRNO_SYSTEM;
	}
	
	mysql_pool_put(ctx->mysql_pool, mysql);
	LOG_DEBUG("vvvvvvvvvvvvvvvv %P  wake vvvvvvvvvvvvvv", ngx_getpid());
	
	return ret;
}


extern int test_proc(ngx_tcp_req_t* req, ngx_tcp_rsp_t* rsp)
{
	int ret = 0;
	req_header_t* header = (req_header_t*)req->req_header;

	switch(header->cmd){
	case CMD_TEST_INIT:
		ret = test_init(req, rsp);
	break;
	case CMD_TEST_ADD:
		ret = test_add(req, rsp);
	break;
	case CMD_TEST_SUB:
		ret = test_sub(req, rsp);
	break;
	case CMD_TEST_QUERY:
		ret = test_query(req, rsp);
	break;
	case CMD_TEST_SLEEP:
		ret = test_sleep(req, rsp);
	break;
	default:
		ret = ERRNO_REQ_INVALID;
		LOG_ERROR("unexpected cmd [0x%04x], ip:%V", header->cmd, &req->c->addr_text);
	}
  
	return ret;
}

