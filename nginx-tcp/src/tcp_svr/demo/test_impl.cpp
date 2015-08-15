#include "ngx_tcp_server.h"
#include "test_protocol.h"
#include "test_impl.h"
#include "ngx_tcp_def_protocol.h"
#include "ngx_log_mod.h"
#include <stdlib.h>
#include <stdint.h>
#include <alloca.h>
#include "mylib/MysqlBase.h"

TestContext::TestContext(ngx_conf_t *cf)
:m_cycle(NULL),m_mysql_pool(NULL)
{
	memset(&this->m_config, 0, sizeof(this->m_config));
	this->m_config.cf = cf;
}

TestContext::~TestContext(){};
/**
 * 配置初始化
 */
int TestContext::cfg_init(const char* config, ngx_tcp_server_srv_conf_t* tcp_svr_cfg)
{
	test_config_t* testcfg = &this->m_config;
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
	
	if(tcp_svr_cfg->use_async){
		testcfg->mysql_config.timeout = 0;
	}
	NLOG_DEBUG("mysql: config:%s", testcfg->mysql_config.host);
	return NGX_OK;
}

/**
 * 上下文初始化
 */
int TestContext::ctx_init(ngx_cycle_t* cycle)
{
	test_config_t* cfg = &this->m_config;
	this->m_cycle = cycle;
	this->m_mysql_pool = mysql_pool_new(cfg->mysql_config.conns, &cfg->mysql_config);
	NLOG_INFO("[%d] mysql_pool: %p", ngx_getpid(), this->m_mysql_pool);
	#define SQL_CREATE_TBL "drop table if exists ngx_test; "\
				"create table ngx_test(`key` varchar(32) primary key,value int default 0); "\
				"insert into ngx_test values('testkey', 0);"
	int ret = 0;
	MYSQL* mysql = this->mysql_get();
	if(mysql == NULL){
		NLOG_ERROR("get mysql connection failed!");
		ret = ERRNO_SYSTEM;
		return ret; 
	}
	NLOG_INFO("init ngx_test table!");
	ret = mysql_queryex(mysql, SQL_CREATE_TBL);
	NLOG_INFO("init ngx_test table ret:%d", ret);
	if(ret == 0){ 
		mysql_free_all_result(mysql);
	}else{ 
		NLOG_ERROR("init table failed!ret:%d, sql:[%s]", ret, SQL_CREATE_TBL);
		ret = ERRNO_SYSTEM;
	}
	// 在Init中取得的链接必须关闭掉，因为这个链接不是非阻塞的。
	this->mysql_close(mysql);

	return NGX_OK;  

}
void TestContext::destroy(ngx_cycle_t* cycle)
{
	mysql_pool_free(this->m_mysql_pool);
}

extern IContext* g_context_creater(ngx_conf_t *cf)
{
	IContext* context = new TestContext(cf);
	return context;
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

class TestProtocol: public CDefProtocol
{
public:
	TestProtocol()
	{
	this->magic = TEST_MAGIC;
	this->magic_big_endian = TEST_MAGIC_BIG;
	}
	virtual const char* get_service_name(ngx_tcp_req_t* req, char* buf)
	{
		req_header_t* reqheader = (req_header_t*)req->req_header;
		if(reqheader->cmd <= 4){
			strcpy(buf, szTestServiceNames[reqheader->cmd]);
		}else{
			strcpy(buf, "UnknowService");
		}
		return buf;
	}
};
 

static TestProtocol g_test_protocol;

int test_set_callbacks(ngx_tcp_data_t* tcp_data){
	tcp_data->cppcbs = (IProtocol*)&g_test_protocol;
	tcp_data->tcp_proc = &test_proc;
	//NLOG_DEBUG("xxx cppcbs: %p, tcp_proc: %p sizeof(ngx_tcp_data_t): %d sizeof(off_t): %d", 
	//		tcp_data->cppcbs, tcp_data->tcp_proc, sizeof(ngx_tcp_data_t), sizeof(off_t));
	
	return 0;
}

ngx_set_callbacks_pt g_tcp_set_callbacks = &test_set_callbacks;

