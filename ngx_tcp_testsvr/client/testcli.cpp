#include "testcli.h"
#include "../mylib/testlog.h"
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>
#include <signal.h>

inline int sock_send_req(int sockfd,  req_header_t* req_header, const void* body){
	int ret = 0;
	int sendlen = 0;
	ret = sock_send_all(sockfd, req_header, sizeof(req_header_t));
	if(ret == -1){
		LOG_ERROR("send req_header failed! ret=%d, err:%s", ret, strerror(errno));
		return -1;
	}
	sendlen += ret;
	ret = sock_send_all(sockfd, body, req_header->len);
	if((uint32_t)ret != req_header->len){
		LOG_ERROR("send req body failed! ret=%d, err:%s", ret, strerror(errno));
		return -1;
	}
	sendlen += ret;
	
	return sendlen;
}


inline int sock_recv_rsp(int sockfd, rsp_header_t* req_header, void* rsp_body, int* bodylen){
	int ret = 0;
	rsp_header_t rsp_header;
	memset(&rsp_header,0,sizeof(req_header_t));
	ret = sock_recv_all(sockfd, &rsp_header, sizeof(rsp_header_t));
	if(ret != sizeof(rsp_header_t)){
		LOG_ERROR("recv rsp_header failed! ret=%d, err:%s", ret, strerror(errno));
		return ERRNO_SOCK_ERR;
	}

	if(rsp_header.code != 0){
		LOG_ERROR("rsp result: %d", rsp_header.code);
		return rsp_header.code;
	}

	int len = rsp_header.len;
	if(len > 0){
		if(*bodylen < len){
			LOG_ERROR("rsp body len (%d) < rsp_header.len(%d)", *bodylen, len);
			return -1;
		}
		ret = sock_recv_all(sockfd, rsp_body, len);
		if(ret != len){
			LOG_ERROR("recv body len [%d] != bodylen", ret, len);
			return ERRNO_SOCK_ERR;
		}
		*bodylen = len;
	}
	
	return 0;
}

static uint64_t test_seq(){
	static uint64_t seq = 0;
	
	return seq++;
}


int cli_test_init(client_ctx_t* ctx)
{
	int ret = 0;
	req_header_t reqheader;
	reqheader.magic = TEST_MAGIC;
	reqheader.cmd = CMD_TEST_INIT;
	reqheader.seq = test_seq();
	reqheader.len = 0;

	ret = sock_send_req(ctx->socket, &reqheader, NULL);
	if((uint32_t)ret != reqheader.len+sizeof(req_header_t)){
		LOG_ERROR("sock_send_req failed!, ret=%d, reqheader.reqlen=%d", ret, reqheader.len);
		ctx->err = ERRNO_SOCK_ERR;
		ctx->needclose = 1;
		return ctx->err;
	}

	rsp_header_t rsp_header;

	ret = sock_recv_rsp(ctx->socket, &rsp_header, NULL,0);
	ctx->err = ret;
	if(ret == ERRNO_SOCK_ERR){
		ctx->needclose = 1;
	}
	
	return ret;	
}

int cli_test_add(client_ctx_t* ctx, int n, int* result)
{
	int ret = 0;
	req_header_t reqheader;
	reqheader.magic = TEST_MAGIC;
	reqheader.cmd = CMD_TEST_ADD;
	reqheader.seq = test_seq();
	reqheader.len = sizeof(test_add_dt);

	test_add_dt add;
	add.n = n;
	ret = sock_send_req(ctx->socket, &reqheader, &add);
	if((uint32_t)ret != reqheader.len+sizeof(req_header_t)){
		LOG_ERROR("sock_send_req failed!, ret=%d, reqheader.len=%d", ret, reqheader.len);
		ctx->err = ERRNO_SOCK_ERR;
		ctx->needclose = 1;
		return ctx->err;
	}

	rsp_header_t rsp_header;
	test_result_dt res;
	memset(&res,0,sizeof(res));
	int rsp_len = sizeof(res);
	ret = sock_recv_rsp(ctx->socket, &rsp_header, &res, &rsp_len);
	ctx->err = ret;
	if(ret == 0){
		*result = res.value;
	}else if(ret == ERRNO_SOCK_ERR){
		ctx->needclose = 1;
	}
	
	return ret;
}

int cli_test_sub(client_ctx_t* ctx, int n, int* result)
{
	int ret = 0;
	req_header_t reqheader;
	reqheader.magic = TEST_MAGIC;
	reqheader.cmd = CMD_TEST_SUB;
	reqheader.seq = test_seq();
	reqheader.len = sizeof(test_sub_dt);

	test_sub_dt sub;
	sub.n = n;
	ret = sock_send_req(ctx->socket, &reqheader, &sub);
	if((uint32_t)ret != reqheader.len+sizeof(req_header_t)){
		LOG_ERROR("sock_send_req failed!, ret=%d, reqheader.reqlen=%d", ret, reqheader.len);
		ctx->err = ERRNO_SOCK_ERR;
		ctx->needclose = 1;
		return ctx->err;
	}

	rsp_header_t rsp_header;
	test_result_dt res;
	memset(&res,0,sizeof(res));
	int rsp_len = sizeof(res);
	ret = sock_recv_rsp(ctx->socket, &rsp_header, &res, &rsp_len);
	ctx->err = ret;
	if(ret == 0){
		*result = res.value;
	}else if(ret == ERRNO_SOCK_ERR){
		ctx->needclose = 1;
	}
	
	return ret;
}

int cli_test_query(client_ctx_t* ctx, int* result)
{
	int ret = 0;
	req_header_t reqheader;
	reqheader.magic = TEST_MAGIC;
	reqheader.cmd = CMD_TEST_QUERY;
	reqheader.seq = test_seq();
	reqheader.len = 0;

	ret = sock_send_req(ctx->socket, &reqheader, NULL);
	if((uint32_t)ret != reqheader.len+sizeof(req_header_t)){
		LOG_ERROR("sock_send_req failed!, ret=%d, reqheader.reqlen=%d", ret, reqheader.len);
		ctx->err = ERRNO_SOCK_ERR;
		ctx->needclose = 1;
		return ctx->err;
	}

	rsp_header_t rsp_header;
	test_result_dt res;
	memset(&res,0,sizeof(res));
	int rsp_len = sizeof(res);
	ret = sock_recv_rsp(ctx->socket, &rsp_header, &res, &rsp_len);
	ctx->err = ret;
	if(ret == 0){
		*result = res.value;
	}else if(ret == ERRNO_SOCK_ERR){
		ctx->needclose = 1;
	}
	
	return ret;
}

int cli_test_sleep(client_ctx_t* ctx, int second)
{
	int ret = 0;
	req_header_t reqheader;
	reqheader.magic = TEST_MAGIC;
	reqheader.cmd = CMD_TEST_SLEEP;
	reqheader.seq = test_seq();
	reqheader.len = sizeof(test_sleep_dt);

	test_sleep_dt slp;
	slp.second = second;
	ret = sock_send_req(ctx->socket, &reqheader, &slp);
	if((uint32_t)ret != reqheader.len+sizeof(req_header_t)){
		LOG_ERROR("sock_send_req failed!, ret=%d, reqheader.reqlen=%d", ret, reqheader.len);
		ctx->err = ERRNO_SOCK_ERR;
		ctx->needclose = 1;
		return ctx->err;
	}

	rsp_header_t rsp_header;

	ret = sock_recv_rsp(ctx->socket, &rsp_header, NULL,0);
	ctx->err = ret;
	if(ret == ERRNO_SOCK_ERR){
		ctx->needclose = 1;
	}
	
	return ret;
}

