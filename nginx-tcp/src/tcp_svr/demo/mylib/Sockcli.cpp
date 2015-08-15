#ifdef NGX_TCP_SERVER
#include "ngx_log_mod.h"
#endif
#include "Sockcli.h"
#include "testlog.h"
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#define MAX(a,b) ((a)>(b)?(a):(b))
#define MIN(a,b) ((a)<(b)?(a):(b))

int sock_recv_all(int sockfd, void* pMsg, int iMsgLen){
	int ret = 0;
	int recv_cnt = 0;

BLOCK_RECV:
	while(recv_cnt < iMsgLen){
		ret = recv(sockfd, ((char*)pMsg)+recv_cnt, iMsgLen-recv_cnt, 0);
		if(ret == 0){
			NLOG_ERROR("Recv Msg error! socket closed!");
			return ret;
		}else if(ret < 0)
		{
			if(errno == EINTR){
				goto BLOCK_RECV;
			}else{
				return -1;
			}
		}
		recv_cnt += ret;
	}

	return recv_cnt;
}


int sock_send_all(int sockfd, const void* pMsg, int iMsgLen)
{
	size_t		nleft;
	ssize_t		nwritten;
	const char*	ptr;

	ptr = (const char*)pMsg;
	nleft = iMsgLen;
	while (nleft > 0) {
		if ( (nwritten = send(sockfd, ptr, MIN(nleft, SND_BUF_SZ), 0)) <= 0){
			if (nwritten < 0 && errno == EINTR)
				nwritten = 0;		/* and call write() again */
			else
				return(-1);			/* error */
		}

		nleft -= nwritten;
		ptr   += nwritten;
	}
	
	return(iMsgLen);
}

/**
 * optname: SO_SNDTIMEO or SO_RCVTIMEO
 */
int sock_set_timeout(int socket, int optname, int sec, int usec){
	struct timeval tv;
	tv.tv_sec = sec;
	tv.tv_usec = usec;
	int ret = setsockopt(socket, SOL_SOCKET, optname, &tv, sizeof(tv) );
	return ret;
}

int sock_set_nodelay(int socket)
{	
	int on=1;
	int ret = setsockopt(socket, IPPROTO_TCP, TCP_NODELAY,&on,sizeof(on)); 	   
	
	return ret;
}


int sock_set_nonblock(int socket){
	int opts;
	opts = fcntl(socket, F_GETFL, 0);
	if(opts <0){
		NLOG_ERROR("fcntl(sock, F_GETFL) failed!");
		return -1;
	}
	opts = opts | O_NONBLOCK;
	fcntl(socket, F_SETFL, opts);

	return 0;
}

int sock_set_block(int socket){
	int opts;
	opts = fcntl(socket, F_GETFL, 0);
	if(opts <0){
		NLOG_ERROR("fcntl(sock, F_GETFL) failed!");
		return -1;
	}
	opts = opts & (~O_NONBLOCK);
	fcntl(socket, F_SETFL, opts);

	return 0;
}

int sock_set_cork(int socket, int on){
	int ret = setsockopt (socket, SOL_TCP, TCP_CORK, &on, sizeof (on));
	if(ret == -1){
		NLOG_ERROR("Set Sock CORK Failed! err=%s", strerror(errno));
	}

	return ret;
}

int sock_set_linger(int socket, int second)
{
	linger sLinger;
	sLinger.l_onoff = 1;  // (在closesocket()调用,但是还有数据没发送完毕的时候容许逗留)
	sLinger.l_linger = second; // 延迟的时间。
	int ret = setsockopt(socket,SOL_SOCKET, SO_LINGER,(const char*)&sLinger, sizeof(sLinger));
	if(ret == -1){
		NLOG_ERROR("Set Sock Linger Failed! err=%s", strerror(errno));
	}
	
	return ret;
}

int sock_set_reuseaddr(int socket){
	int reuse=1;
	int ret = setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));   //允许地址重用
	if(ret == -1){
		NLOG_ERROR("Set Sock ReuseAddr Failed! err=%s", strerror(errno));
	}
	
	return ret;
}

int sock_set_keepalive(int socket, int iInterval, int iCount)
{
	int iKeepAlive = 1;
	int ret = setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, (void *)&iKeepAlive, sizeof(iKeepAlive)); 
	if(ret == -1){
		NLOG_ERROR("Set Sock[%d] KeepAlive Failed! err=%s",socket,  strerror(errno));
		return ret;
	}
	
	ret = setsockopt(socket, SOL_TCP , TCP_KEEPIDLE , (const char*)&iInterval , sizeof(iInterval) );
	if(ret == -1){
		NLOG_ERROR("Set Sock KeepAlive Idle Failed! err=%s", strerror(errno));
		return ret;
	}
		 
	ret = setsockopt(socket, SOL_TCP , TCP_KEEPINTVL , (const char*)&iInterval,sizeof(iInterval) );
	if(ret == -1){
		NLOG_ERROR("Set Sock KeepAlive Interval Failed! err=%s", strerror(errno));
		return ret;
	}
		 
	ret = setsockopt(socket, SOL_TCP , TCP_KEEPCNT , (const char*)&iCount,sizeof(iCount) );
	if(ret == -1){
		NLOG_ERROR("Set Sock KeepAlive Count Failed! err=%s", strerror(errno));
		return ret;
	}
	
	return ret;
}

client_ctx_t* client_new()
{
	client_ctx_t* ctx = (client_ctx_t*)malloc(sizeof(client_ctx_t));
	memset(ctx, 0, sizeof(client_ctx_t));
	return ctx;
}

void client_free(client_ctx_t* ctx)
{
	if(ctx != NULL){
		if(ctx->socket > 0){
			close(ctx->socket);
		}
		free(ctx);
	}
}

int client_reinit(client_ctx_t* ctx){
	if(ctx->socket > 0){
		close(ctx->socket);
		ctx->socket = 0;
	}
	return client_init(ctx, ctx->ip,ctx->port,ctx->timeout_send,ctx->timeout_recv);
}

int client_close(client_ctx_t* ctx){
	if(ctx->socket > 0){
		close(ctx->socket);
		ctx->socket = 0;
	}
	return 0;
}

int client_test_conn(client_ctx_t* ctx)
{
	if(ctx->socket <= 0){
		return client_init(ctx, ctx->ip,ctx->port,ctx->timeout_send,ctx->timeout_recv);
	}
	return 0;
}

int client_init(client_ctx_t* ctx, const char* ip, int port, int timeout_send,int timeout_recv)
{
	strncpy(ctx->ip, ip, sizeof(ctx->ip));
	ctx->port = port;
	ctx->timeout_send = timeout_send;
	ctx->timeout_recv = timeout_recv;
	
	ctx->socket = socket(PF_INET, SOCK_STREAM, 0);
	struct sockaddr_in cliaddr;
	bzero(&cliaddr , sizeof(cliaddr));
	cliaddr.sin_family = PF_INET;
	cliaddr.sin_port = htons(ctx->port);
	int ret = inet_pton(PF_INET, ctx->ip, &cliaddr.sin_addr);
	if(ret == -1)
	{
		close(ctx->socket);
		ctx->socket = 0;
		return -1;
	}

	ret = connect(ctx->socket , (struct sockaddr*)&cliaddr , sizeof(cliaddr));
	if(ret == 0){
		ret = sock_set_nodelay(ctx->socket);
		if(ret == -1){
			printf("sock_set_nodelay failed! err:%s\n", strerror(errno));
		}
		
		if(timeout_send > 0){
			ret = sock_set_timeout(ctx->socket, SO_SNDTIMEO, ctx->timeout_send, 0);
			if(ret == -1){
				printf("set send timeout(%d) faild! err:%s\n", ctx->timeout_send, strerror(errno));
			}
		}
		if(timeout_recv > 0){
			//NLOG_DEBUG("########### recv timeout:%d #############", ctx->timeout_recv);
			ret = sock_set_timeout(ctx->socket, SO_RCVTIMEO, ctx->timeout_recv, 0);
			if(ret == -1){
				printf("set recv timeout(%d) faild! err:%s\n", ctx->timeout_recv, strerror(errno));
			}
		}
	}
	
	return ret;
}

int client_init2(client_ctx_t* ctx, int socket)
{
	ctx->socket = socket;
	return 0;
}

