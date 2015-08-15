#include "ngx_log_mod.h"
#include "ngx_tcp_def_protocol.h"


CDefProtocol::CDefProtocol()
:magic(0x1234),magic_big_endian(0x3412)

{
	
} 

 req_head_t* CDefProtocol::new_req_head(ngx_pool_t* pool, uint16_t* size)
 {
	req_header_t* header = (req_header_t*)NGX_TCP_PALLOC(pool, sizeof(req_header_t));
	*size = (uint16_t)sizeof(req_header_t);
	return header;
 }
 rsp_head_t* CDefProtocol::new_rsp_head(ngx_pool_t* pool, req_head_t* rheader, uint16_t* size)
{
	req_header_t* reqheader = (req_header_t*)rheader;
	rsp_header_t* header = (rsp_header_t*)NGX_TCP_PALLOC(pool, sizeof(rsp_header_t));
	memcpy(header, reqheader, sizeof(req_header_t));
	header->cmd = reqheader->cmd | (1<<15);
	header->len = 0;
	header->code = 0;
	*size = (uint16_t)sizeof(rsp_header_t);
	return header;
}
size_t CDefProtocol::get_req_body_size(req_head_t* header)
{
	req_header_t* reqheader = (req_header_t*)header;
	return reqheader->len;
}
size_t CDefProtocol::get_rsp_body_size(rsp_head_t* header)
{
	rsp_header_t* rspheader = (rsp_header_t*)header;
	return rspheader->len;
}

int CDefProtocol::preproc_req_header(ngx_tcp_req_t* req)
{
	req_header_t* reqheader = (req_header_t*)req->req_header;
	if(reqheader->magic != magic && reqheader->magic != magic_big_endian){
		char buf[128];
		memset(buf,0,sizeof(buf));
		bin2hex((unsigned char *)reqheader, sizeof(req_header_t), buf);
		NLOG_ERROR("Invalid Req Hdr:%s",buf);
		return -1;
	}
	req->isbigendian = (reqheader->magic==magic_big_endian)?1:0;
	if(req->isbigendian){
		NTOHS(reqheader->magic);
		NTOHL(reqheader->len);
		NTOHS(reqheader->cmd);
		NTOHS(reqheader->seq);
		NTOHS(reqheader->ext);
	}
	NLOG_DEBUG("req_header #magic: 0x%04xd, cmd:%d, len:%d,seq:%d",
				(int)reqheader->magic, (int)reqheader->cmd,
				(int)reqheader->len, (int)reqheader->seq);

	
	return 0;
}

int CDefProtocol::preproc_req_body(ngx_tcp_req_t* req)
{
	return 0;
}
int CDefProtocol::preproc_rsp_header(ngx_tcp_rsp_t* rsp)
{
	rsp_header_t* rspheader = (rsp_header_t*)rsp->rsp_header;
	if(rsp->isbigendian){
		HTONS(rspheader->magic);
		HTONL(rspheader->len);
		HTONS(rspheader->cmd);
		HTONS(rspheader->seq);
		HTONS(rspheader->code);
	}

	return 0;
}
int CDefProtocol::preproc_rsp_body(ngx_tcp_rsp_t* rsp)
{
	return 0;
}

void CDefProtocol::debug_req(ngx_tcp_req_t* req)
{
 	//NLOG_DEBUG("#########################");
}
void CDefProtocol::debug_rsp(ngx_tcp_rsp_t* rsp)
{
}
void CDefProtocol::free_req(ngx_pool_t* pool,ngx_tcp_req_t* req)
{
	if(req != NULL){ 
		NGX_TCP_PFREE(pool, req->req_header)
		NGX_TCP_PFREE(pool, req->body)
		NGX_TCP_PFREE(pool, req);
	}
} 
void CDefProtocol::free_rsp(ngx_pool_t* pool,ngx_tcp_rsp_t* rsp)
{
	if(rsp != NULL){
		NGX_TCP_PFREE(pool, rsp->rsp_header);
		NGX_TCP_PFREE(pool, rsp->body);
		NGX_TCP_PFREE(pool, rsp);
	}
}

void CDefProtocol::set_rsp_code(ngx_tcp_rsp_t* rsp, int ret)
{
	rsp_header_t* rspheader = (rsp_header_t*)rsp->rsp_header;
	
	rspheader->code = ret;
}

void CDefProtocol::debug_stats(ngx_tcp_data_t* data){
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
int CDefProtocol::req_again(ngx_tcp_req_t* req)
{
	return 0;
}


