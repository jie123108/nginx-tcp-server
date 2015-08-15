
#ifndef __NGX_TEST_IMPL__
#define __NGX_TEST_IMPL__

#include "test_protocol.h"
#include "ngx_tcp_server.h"
#include "mylib/MysqlPool.h"

typedef struct{
	ngx_conf_t* cf;
	mysql_config_t mysql_config;
	char backend_ip[32];
	int backend_port;
} test_config_t;

class TestContext: public IContext {
public:
	TestContext(ngx_conf_t *cf);
	~TestContext();
	int cfg_init(const char* config, ngx_tcp_server_srv_conf_t* tcp_svr_cfg);
	int ctx_init(ngx_cycle_t* cycle);
	void destroy(ngx_cycle_t* cycle);

	MYSQL* mysql_get()
	{
		return mysql_pool_get(this->m_mysql_pool);
	}

	void mysql_put(MYSQL* mysql)
	{
		mysql_pool_put(this->m_mysql_pool, mysql);
	}
	
	void mysql_close(MYSQL* mysql)
	{
		mysql_pool_put(this->m_mysql_pool, mysql, 1);
	}
	
protected:
	ngx_cycle_t* m_cycle;
	conn_pool_t* m_mysql_pool;
	test_config_t m_config;

};


extern int test_proc(ngx_tcp_req_t* req, ngx_tcp_rsp_t* rsp);

#endif

