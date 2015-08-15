#ifndef __SOCKET_CLIENT_H__
#define __SOCKET_CLIENT_H__

#define SND_BUF_SZ (1024*4)

typedef struct client_ctx_t{
	int socket;
	char ip[32];
	int port:16;
	int timeout_recv:16;
	int timeout_send:16;
	int err:16;
	/**
	 * 是否要关闭连接，如果发送与接收出错时，
	 * 需要设置该位.在sock_pool_put时会关闭该连接。
	 */
	int needclose:1; 
	int ext1;
}client_ctx_t;

int sock_recv_all(int sockfd, void* pMsg, int iMsgLen);
int sock_send_all(int sockfd, const void* pMsg, int iMsgLen);
/**
 * optname: SO_SNDTIMEO or SO_RCVTIMEO
 */
int sock_set_timeout(int socket, int optname, int sec, int usec);
int sock_set_nodelay(int socket);
int sock_set_nonblock(int socket);
int sock_set_block(int socket);
int sock_set_cork(int socket, int on);
int sock_set_linger(int socket, int second);
int sock_set_reuseaddr(int socket);
int sock_set_keepalive(int socket, int iInterval, int iCount);

/**
 * 创建一个session上下文
 * 返回值: 返回新创建的上下文.
 */
client_ctx_t* client_new();
/**
 * 清除并释放session上下文
 */
void client_free(client_ctx_t* ctx);

/**
 * 初始化session上下文,连接网络连接
 * ip: 服务器地址
 * port: 服务商品
 * timeout:发送与接收的超时时间(秒)
 * 返回值: 0表示正常， -1表示出错。
 */
int client_init(client_ctx_t* ctx, const char* ip, int port, int timeout_send=5,int timeout_recv=10);

/**
 * 重新连接
 */
int client_reinit(client_ctx_t* ctx);

int client_close(client_ctx_t* ctx);
int client_test_conn(client_ctx_t* ctx);

/**
 * 直接使用已经建立好的连接来初始化
 * 返回值: 0表示正常， -1表示出错。
 */
int client_init2(client_ctx_t* ctx, int socket);

#endif

