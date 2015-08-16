// ngx_tcp_server.h必须是第一个包含(#include)的文件，否则可能导致结构体大小不一致。
#include "ngx_tcp_server.h"
#include "ngx_log_mod.h"
#include "IniFile.h"

/*****************************************
 上下文，配置相关处理与实现
 *****************************************/
typedef struct{
	char welcome[128]; //欢迎语。
} hello_config_t;

class HelloContext: public IContext {
public:
	HelloContext(ngx_conf_t *cf){
		this->m_cycle = cf->cycle;
		memset(&this->m_config,0,sizeof(this->m_config));
	}
	
	~HelloContext(){}
	// 配置初始化
	int cfg_init(const char* config, ngx_tcp_server_srv_conf_t* tcp_svr_cfg){
		CIniFile inifile(config);
		if(!inifile.ReadFile()){
			CONF_ERROR("read config [%s] failed! err: %s", config, strerror(errno));
			return NGX_ERROR;
		} 

		string welcome = inifile.GetValue("hello", "welcome", "nginx-tcp-server");
		strncpy(this->m_config.welcome, welcome.c_str(), sizeof(this->m_config.welcome));
		return NGX_OK;
	}

	//数据库，网络链接相关的初始化。
	int ctx_init(ngx_cycle_t* cycle){
		//由于Hello World程序没相应的部分，这里不需要实现
		return 0;
	}
	
	void destroy(ngx_cycle_t* cycle){
		//相关资源销毁，清理。
	}

	const char* get_welcome()
	{
		return this->m_config.welcome;
	}

protected:
	ngx_cycle_t* m_cycle;
	hello_config_t m_config;

};

/*****************************************
 定义MAGIC,命令字,及错误码
 *****************************************/
#define MAGIC 0xa0b1
#define MAGIC_BIG 0xb1a0

#define CMD_LOGIN 0x1
#define CMD_EXIT 0x2

#define ERRNO_OK	0					//成功	
#define ERRNO_SYSTEM	1				//系统错误	所有接口
#define ERRNO_REQ_INVALID	2			//请求参数错误。	所有接口

/*****************************************
 定义请求体及响应体
 *****************************************/
typedef struct {
	char username[32]; //这里实际长度是变长的，所以可以已经读取到\0为止。
}hello_req_dt;

typedef struct {
	char data[4]; //这里实际长度是变长的，所以可以已经读取到\0为止。
}hello_rsp_dt;


/*****************************************
 协议处理相关定义与实现
 *****************************************/
// 请求头定义
typedef struct {
	uint16_t magic; //协议识别码，为一个固定值，请求及响应均相同。
	uint32_t len; 	//指令体长度，0表示没有指令体。
	uint16_t cmd;	//指令号。
}__attribute__ ((packed)) hello_req_header_t;
// 响应头定义
typedef struct {
	uint16_t magic; //协议识别码，为一个固定值，请求及响应均相同。
	uint32_t len; 	//指令体长度，0表示没有指令体。
	uint16_t cmd;	//指令号。
	uint16_t code;  
}__attribute__ ((packed)) hello_rsp_header_t;

// 协议处理类定义
class CHelloProtocol: public IProtocol{
public:
	CHelloProtocol()
	:magic(MAGIC),magic_big_endian(MAGIC_BIG){ } 

	 req_head_t* new_req_head(ngx_pool_t* pool, uint16_t* size)
	 {
		hello_req_header_t* header = (hello_req_header_t*)NGX_TCP_PALLOC(pool, sizeof(hello_req_header_t));
		*size = (uint16_t)sizeof(hello_req_header_t);
		return header;
	 }
	 rsp_head_t* new_rsp_head(ngx_pool_t* pool, req_head_t* rheader, uint16_t* size)
	{
		hello_req_header_t* reqheader = (hello_req_header_t*)rheader;
		hello_rsp_header_t* header = (hello_rsp_header_t*)NGX_TCP_PALLOC(pool, sizeof(hello_rsp_header_t));
		header->magic = reqheader->magic;
		header->cmd = reqheader->cmd + 1;
		header->len = 0;
		header->code = 0;
		*size = (uint16_t)sizeof(hello_rsp_header_t);
		return header;
	}
	size_t get_req_body_size(req_head_t* header)
	{
		hello_req_header_t* reqheader = (hello_req_header_t*)header;
		return reqheader->len;
	}
	size_t get_rsp_body_size(rsp_head_t* header)
	{
		hello_rsp_header_t* rspheader = (hello_rsp_header_t*)header;
		return rspheader->len;
	}

	int preproc_req_header(ngx_tcp_req_t* req)
	{
		hello_req_header_t* reqheader = (hello_req_header_t*)req->req_header;
		if(reqheader->magic != magic && reqheader->magic != magic_big_endian){
			char buf[128];
			memset(buf,0,sizeof(buf));
			bin2hex((unsigned char *)reqheader, sizeof(hello_req_header_t), buf);
			NLOG_ERROR("Invalid Req Hdr:%s",buf);
			return -1;
		}
		
		NLOG_DEBUG("req_header #magic: 0x%04xd, cmd:%d, len:%d",
					(int)reqheader->magic, (int)reqheader->cmd,(int)reqheader->len);
		return 0;
	}

	int preproc_req_body(ngx_tcp_req_t* req)
	{
		return 0;
	}
	int preproc_rsp_header(ngx_tcp_rsp_t* rsp)
	{
		//hello_rsp_header_t* rspheader = (hello_rsp_header_t*)rsp->rsp_header;
		
		return 0;
	}
	int preproc_rsp_body(ngx_tcp_rsp_t* rsp)
	{
		return 0;
	}

	void debug_req(ngx_tcp_req_t* req)
	{
	 	//NLOG_DEBUG("#########################");
	}
	void debug_rsp(ngx_tcp_rsp_t* rsp)
	{
	}
	void free_req(ngx_pool_t* pool,ngx_tcp_req_t* req)
	{
		if(req != NULL){ 
			NGX_TCP_PFREE(pool, req->req_header)
			NGX_TCP_PFREE(pool, req->body)
			NGX_TCP_PFREE(pool, req);
		}
	} 
	void free_rsp(ngx_pool_t* pool,ngx_tcp_rsp_t* rsp)
	{
		if(rsp != NULL){
			NGX_TCP_PFREE(pool, rsp->rsp_header);
			NGX_TCP_PFREE(pool, rsp->body);
			NGX_TCP_PFREE(pool, rsp);
		}
	}

	void set_rsp_code(ngx_tcp_rsp_t* rsp, int ret)
	{
		hello_rsp_header_t* rspheader = (hello_rsp_header_t*)rsp->rsp_header;
		
		rspheader->code = ret;
	}

	virtual const char* get_service_name(ngx_tcp_req_t* req, char* buf){
		hello_req_header_t* reqheader = (hello_req_header_t*)req->req_header;
		switch(reqheader->cmd){
		case CMD_LOGIN: sprintf(buf, "login"); break;
		case CMD_EXIT: sprintf(buf, "exit"); break;
		default: sprintf(buf, "unknow");
		}
		return buf;
	}
	void debug_stats(ngx_tcp_data_t* data){
		char serviceName[64];
		memset(serviceName,0,sizeof(serviceName));
		this->get_service_name(data->req_data, serviceName);

		NLOG_DEBUG("STAT [%s] all=%.4f,{recv=%.4f,proc=%.4f,send=%.4f}", 
				serviceName, data->stat.all,
				data->stat.recv_req,
				data->stat.proc,
				data->stat.send_rsp);

	}

	//当接收请求时，遇到E_AGAIN时调用的回调。
	int req_again(ngx_tcp_req_t* req)
	{
		return 0;
	}
protected:
	uint16_t magic;
	uint16_t magic_big_endian;
};

/*****************************************
 服务处理回调定义及实现
 *****************************************/
//帮助类
static void hello_set_rsp_data(ngx_tcp_rsp_t* rsp, void* body, int len){
	hello_rsp_header_t* rspheader = (hello_rsp_header_t*)rsp->rsp_header;
	//设置响应体(参数body必须是通过NGX_TCP_PALLOC分配的，不能是local的变量)
	rsp->body = body;
	rsp->body_len = len;
	//设置响应头里面的长度。
	rspheader->len = len;
}

int hello_login(ngx_tcp_req_t* req, ngx_tcp_rsp_t* rsp)
{
	int ret = 0;
	HelloContext* ctx = (HelloContext*)req->tcp_data->conf->appctx;
	hello_req_dt* req_data = (hello_req_dt*)req->body;
	
	char buf[1024];
	memset(buf,0,sizeof(buf));
	int rsp_len = sprintf(buf, "Hello %s,%s!", req_data->username, ctx->get_welcome())+1;
	
	hello_rsp_dt* result = (hello_rsp_dt*)NGX_TCP_PALLOC(req->c->pool, rsp_len);
	strncpy(result->data, buf, rsp_len);
	
	hello_set_rsp_data(rsp, result, rsp_len);
	
	return ret;
}

int hello_exit(ngx_tcp_req_t* req, ngx_tcp_rsp_t* rsp)
{
	int ret = 0;
	//HelloContext* ctx = (HelloContext*)req->tcp_data->conf->appctx;
	hello_req_dt* req_data = (hello_req_dt*)req->body;

	char buf[1024];
	memset(buf,0,sizeof(buf));
	int rsp_len = sprintf(buf, "Bye %s!", req_data->username)+1;
	
	hello_rsp_dt* result = (hello_rsp_dt*)NGX_TCP_PALLOC(req->c->pool, rsp_len);
	strncpy(result->data, buf, rsp_len);
	
	hello_set_rsp_data(rsp, result, rsp_len);
	
	return ret;
}


int hello_proc(ngx_tcp_req_t* req, ngx_tcp_rsp_t* rsp)
{
	int ret = 0;
	hello_req_header_t* header = (hello_req_header_t*)req->req_header;

	switch(header->cmd){
	case CMD_LOGIN:
		ret = hello_login(req, rsp);
	break;
	case CMD_EXIT:
		ret = hello_exit(req, rsp);
	break;	
	default:
		ret = ERRNO_REQ_INVALID;
		NLOG_ERROR("unexpected cmd [0x%04xd], ip:%s", (int)header->cmd, &req->c->clientaddr);
	}
  
	return ret;
}

/*****************************************
 设置上下文，协议处理及服务处理回调。
 *****************************************/
// 上下文创建回调。
extern IContext* g_context_creater(ngx_conf_t *cf)
{
	IContext* context = new HelloContext(cf);
	return context;
}

static CHelloProtocol g_hello_protocol;
// 协议处理类及服务处理回调
int hello_set_callbacks(ngx_tcp_data_t* tcp_data){
	tcp_data->cppcbs = (IProtocol*)&g_hello_protocol;
	tcp_data->tcp_proc = &hello_proc;
	
	return 0;
}

ngx_set_callbacks_pt g_tcp_set_callbacks = &hello_set_callbacks;

