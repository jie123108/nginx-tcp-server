#ifndef __BASELIB_TCP_TEST_CLIENT_H__
#define __BASELIB_TCP_TEST_CLIENT_H__
#include "Thread.h"
#include <sys/time.h>

#define MAX_TEST_THREADS 1024
#define MAX_TEST_CONNECTIONS (1024*100)

extern int g_errors[0xFFFF];
#define ERRNO_UNKNOW 0xFF01
#define ERRNO_CONN 0xFF02

typedef void ClientCtx;

int ParseArgs(int argc, char* argv[], char* host,int* port, 
		int* threads, int* connections,int* requestCount, int* func, int* logLevel);

typedef int (*FTcpRequest)(int index,ClientCtx* ctx, void* args);
typedef ClientCtx* (*FClientCtxNew)(const char* host, int port);
typedef void (*FClientCtxFree)(ClientCtx* ctx);

ClientCtx* SocketClientNew(const char* host, int port);
void SocketClientFree(ClientCtx* ctx);

int RunTcpTestClient(const char* ip, int port, unsigned int threads, 
	unsigned int request_count, 
	FTcpRequest RequestCb,void* args,FClientCtxNew ClientNewCb, 
	FClientCtxFree ClientFreeCb, int expectedCode=0,int num=10000);

#endif

