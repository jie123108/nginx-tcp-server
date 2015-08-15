#ifndef __NGX_TCP_DEF_PROTOCOL_H__
#define __NGX_TCP_DEF_PROTOCOL_H__
#include "ngx_tcp_server.h"
#include <stdint.h>
//协议头。
typedef struct {
	uint16_t magic; //协议识别码，为一个固定值，请求及响应均相同。
	uint32_t len; 	//指令体长度，0表示没有指令体。
	uint16_t cmd;	//指令号。
	uint16_t seq;   //指令序号。
	uint16_t ext;  
}__attribute__ ((packed)) req_header_t;

typedef struct {
	uint16_t magic; //协议识别码，为一个固定值，请求及响应均相同。
	uint32_t len; 	//指令体长度，0表示没有指令体。
	uint16_t cmd;	//指令号。
	uint16_t seq;   //指令序号。
	uint16_t code;  
}__attribute__ ((packed)) rsp_header_t;

class CDefProtocol : public IProtocol
{
public:
	CDefProtocol();
	
	virtual req_head_t* new_req_head(ngx_pool_t* pool, uint16_t* size);
	virtual rsp_head_t* new_rsp_head(ngx_pool_t* pool, req_head_t* header, uint16_t* size);
	virtual size_t get_req_body_size(req_head_t* header);
	virtual size_t get_rsp_body_size(rsp_head_t* header);

	virtual int preproc_req_header(ngx_tcp_req_t* req);
	virtual int preproc_req_body(ngx_tcp_req_t* req);
	virtual int preproc_rsp_header(ngx_tcp_rsp_t* rsp);
	virtual int preproc_rsp_body(ngx_tcp_rsp_t* rsp);

	virtual void debug_req(ngx_tcp_req_t* req);
	virtual void debug_rsp(ngx_tcp_rsp_t* rsp);
	virtual void free_req(ngx_pool_t* pool,ngx_tcp_req_t* req);
	virtual void free_rsp(ngx_pool_t* pool,ngx_tcp_rsp_t* rsp);

	virtual void set_rsp_code(ngx_tcp_rsp_t* rsp, int ret);
	
	virtual void debug_stats(ngx_tcp_data_t* data);
	//当接收请求时，遇到TCP_AGAIN时调用的回调。
	virtual int req_again(ngx_tcp_req_t* req); 
	
	virtual const char* get_service_name(ngx_tcp_req_t* req, char* buf){
		req_header_t* reqheader = (req_header_t*)req->req_header;
		sprintf(buf, "service-%d", reqheader->cmd);
		return buf;
	}
public:
	//size_t req_head_size;
	//size_t rsp_head_size;
	uint16_t magic;
	uint16_t magic_big_endian;
};

#define NTOHS(n) n=ntohs(n)
#define NTOHL(n) n=ntohl(n)
#define HTONS(n) n=htons(n)
#define HTONL(n) n=htonl(n)


#endif
