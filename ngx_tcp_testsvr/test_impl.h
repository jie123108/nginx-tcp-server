
#ifndef __NGX_TEST_IMPL__
#define __NGX_TEST_IMPL__

extern "C"{
#include "ngx_tcp_session.h"
#include "test_protocol.h"
}
#include "mylib/MysqlPool.h"

typedef struct{
	ngx_conf_t* cf;
	mysql_config_t mysql_config;
	char backend_ip[32];
	int backend_port;
} test_config_t;

typedef struct{
	ngx_cycle_t* cycle;

	conn_pool_t* mysql_pool;
}test_ctx_t;

extern int test_proc(ngx_tcp_req_t* req, ngx_tcp_rsp_t* rsp);

#endif

