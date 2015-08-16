#ifndef __MSGONLINE_PROTOCOL_H__
#define  __MSGONLINE_PROTOCOL_H__
#include <stdint.h>
#include <arpa/inet.h>

#pragma pack(push) //保存对齐状态
#pragma pack(1) //设置1字节对齐
#ifndef TEST_CLIENT
#include "ngx_tcp_def_protocol.h"
#endif

#ifndef __NGX_TCP_DEF_PROTOCOL_H__
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
#endif

#define log_HEADER(str, header);  NLOG_DEBUG("%s magic:0x%04x, len:%d,cmd:%d,seq:%d, code:%d",\
			str, (int)header->magic,header->len,header->cmd,header->seq, header->code);

#pragma pack(pop) //恢复对齐状态。

typedef struct {
	int n;
}test_add_dt;

typedef struct {
	int n;
}test_sub_dt;

typedef struct {
	int value;
}test_result_dt;

typedef struct {
	int second;
}test_sleep_dt;

//返回错误吗：
#define ERRNO_OK	0					//成功	
#define ERRNO_SYSTEM	1				//系统错误	所有接口
#define ERRNO_REQ_INVALID	2			//请求参数错误。	所有接口

#define TEST_MAGIC 0xabcd
#define TEST_MAGIC_BIG 0xcdab

#define CMD_TEST_INIT 0
#define CMD_TEST_ADD 1
#define CMD_TEST_SUB 2
#define CMD_TEST_QUERY 3
#define CMD_TEST_SLEEP 4

#endif

