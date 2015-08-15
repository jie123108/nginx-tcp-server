#include "ngx_log_mod.h"
#include "ngx_tcp_async_proc.h"
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <dlfcn.h>
#include <poll.h>
}


#define MTASK_WAKE_TIMEDOUT   0x01
//#define MTASK_WAKE_NOFINALIZE 0x02

static ngx_tcp_data_t *coroutine_current = NULL;

#define coroutine_setcurrent(data) (coroutine_current = (data))

#define coroutine_resetcurrent() coroutine_setcurrent(NULL)

#define coroutine_scheduled (coroutine_current != NULL)

int tcp_coroutine_wake(ngx_tcp_data_t* data, int flags);


static void tcp_coroutine_read_event_handler(ngx_event_t *ev) {
	ngx_connection_t *c = (ngx_connection_t*)ev->data;
	ngx_tcp_data_t* data = (ngx_tcp_data_t*)c->data;
	ngx_tcp_server_srv_conf_t* tcp_svr_conf;
	tcp_svr_conf = (ngx_tcp_server_srv_conf_t*)data->req_data->tcp_data->conf;
	int wf = 0;

	if (ev->timedout) {		
		NLOG_WARN("fd[%d]:%s read timeout(%d)", data->req_data->c->fd, 
					data->req_data->c->clientaddr,					
					tcp_svr_conf->backend_timeout_recv);
		NLOG_DEBUG2("fd[%d]:%s read timeout(%d)", data->req_data->c->fd, 
					data->req_data->c->clientaddr,					
					tcp_svr_conf->backend_timeout_recv);
		wf |= MTASK_WAKE_TIMEDOUT;
	}

	tcp_coroutine_wake(data, wf);
}

static void tcp_coroutine_write_event_handler(ngx_event_t *ev) {
	ngx_connection_t *c = (ngx_connection_t*)ev->data;
	ngx_tcp_data_t* data = (ngx_tcp_data_t*)c->data;
	ngx_tcp_server_srv_conf_t* tcp_svr_conf;
	tcp_svr_conf = (ngx_tcp_server_srv_conf_t*)data->req_data->tcp_data->conf;
	int wf = 0;

	if (ev->timedout) {		
		NLOG_WARN("fd[%d]:%s write timeout(%d)", data->req_data->c->fd, 
					data->req_data->c->clientaddr,
					tcp_svr_conf->backend_timeout_send);
		wf |= MTASK_WAKE_TIMEDOUT;
	}

	tcp_coroutine_wake(data, wf);
}

/* returns 1 on timeout */
int tcp_coroutine_yield(int fd, ngx_int_t event) {
	ngx_tcp_data_t* data = coroutine_current;
	ngx_connection_t *c;
	ngx_event_t *e;
	ngx_tcp_server_srv_conf_t* tcp_svr_conf;
	char clientaddr[32];
	memset(clientaddr,0,sizeof(clientaddr));
	
	c = ngx_get_connection(fd, data->req_data->c->log);
	if(c == NULL){//worker_connections are not enough while nginx tcp module init connection
		NLOG_ERROR("worker_connections are not enough while nginx tcp module init connection");
		data->async->timedout = 1;
		return data->async->timedout;
	}
	c->data = data;
	memcpy(clientaddr, data->req_data->c->clientaddr, sizeof(clientaddr));

	tcp_svr_conf = (ngx_tcp_server_srv_conf_t*)data->req_data->tcp_data->conf;
	NLOG_DEBUG2("req[%s] backend fd[%d] ++++++ coroutine yield %s +++++", 
		clientaddr, c->fd, event & NGX_WRITE_EVENT ? "write" : "read");

	if (event == NGX_READ_EVENT){
		e = c->read;
		e->data = c;
		e->handler = &tcp_coroutine_read_event_handler;
		e->log = data->req_data->c->log;
		if(tcp_svr_conf->backend_timeout_recv != NGX_CONF_UNSET_MSEC){
			ngx_add_timer(e, tcp_svr_conf->backend_timeout_recv);
		}
	}else{
		e = c->write;
		e->data = c;
		e->handler = &tcp_coroutine_write_event_handler;
		e->log = data->req_data->c->log;
		if(tcp_svr_conf->backend_timeout_send!= NGX_CONF_UNSET_MSEC){
			ngx_add_timer(e, tcp_svr_conf->backend_timeout_send);
		}
	}

	//ngx_epoll_add_event
	ngx_add_event(e, event, 0);

	data->async->timedout = 0;

	swapcontext(&data->async->work_ctx, &data->async->main_ctx);
	NLOG_DEBUG2("req[%s] backend fd[%d] ++++++ coroutine waked %s +++++", 
		clientaddr, c->fd, event & NGX_WRITE_EVENT ? "write" : "read");

	if (e->timer_set)
		ngx_del_timer(e);

	ngx_del_event(e, event, 0);
	ngx_free_connection(c);

	return data->async->timedout;
}


int tcp_coroutine_wake(ngx_tcp_data_t* data, int flags) {

	coroutine_setcurrent(data);

	if (flags & MTASK_WAKE_TIMEDOUT){
		data->async->timedout = 1;
	}

	int fd = data->req_data->c->fd;
	char clientaddr[32];
	memset(clientaddr,0,sizeof(clientaddr));
	memcpy(clientaddr, data->req_data->c->clientaddr, sizeof(clientaddr));

	NLOG_DEBUG2("fd[%d]:%s ------ work ctx wake------", fd, clientaddr);
	swapcontext(&data->async->main_ctx, &data->async->work_ctx);
	NLOG_DEBUG2("fd[%d]:%s ------ main ctx run ------", fd, clientaddr);
	//NLOG_DEBUG("ret=%d, rctx.uc_flags:%d", n, data->rctx.uc_flags);
	if (data->async->free_stask) {
		NLOG_DEBUG2("fd[%d]:%s xxxxxx coroutine finalize xxxxxx", fd, clientaddr);
		//NLOG_DEBUG("mmmmmmmm free: 0x%08x", (long long)data->async->wctx.uc_stack.ss_sp);
		data->async->work_ctx.uc_stack.ss_sp = NULL;
		ngx_free(data->async);
		data->async = NULL;
		return 1;
	}
	coroutine_resetcurrent();

	return 0;
}

#if defined(__i386__)
static void tcp_coroutine_proc(uint32_t data_ptr_v){
#else
static void tcp_coroutine_proc(uint32_t data_high, uint32_t data_low){
	uint64_t data_ptr_v = ((uint64_t)data_high << 32) | data_low;

#endif

	//NLOG_DEBUG2("data:0x%016llx", data_ptr_v);
	ngx_tcp_data_t* data = (ngx_tcp_data_t*)data_ptr_v;
	
	ngx_connection_t    *c = data->req_data->c;

	int ret = 0;
	data->stat.proc = ngx_second();
	NLOG_DEBUG2("fd[%d]:%s ### coroutine_proc start ####", c->fd,c->clientaddr);
	ret = data->tcp_proc(data->req_data,data->rsp_data);
	NLOG_DEBUG2("fd[%d]:%s ### coroutine_proc end ####", c->fd,c->clientaddr);
	data->stat.proc = ngx_second()-data->stat.proc;
	data->stat.code = ret;
	coroutine_resetcurrent();
	
	data->prot_set_rsp_code(data->rsp_data, ret);
	//log_ADDR(data->rsp_data);
	data->status = NS_SEND; 
 
	c->write->active = 0;
	c->write->ready = 0;
	//NLOG_DEBUG2("data {0x%08x} status:%d",data, data->status);
	c->write->handler = &ngx_tcp_server_write_handler;

	ret = ngx_handle_write_event(c->write, 0);
	if(ret != NGX_OK)
	{
	    NLOG_ERROR("ngx_hendle_write_event: %d", ret);
	    ngx_tcp_server_finalize(c);
	    data->status = NS_CLOSE;
	}


	data->stat.all = ngx_second()-data->stat.all;
	data->prot_debug_stats(data);

	if(data->req_data != NULL){
		data->prot_free_req(c->pool, data->req_data);
		data->req_data = NULL;
	}
	data->async->free_stask = 1;
	data->async->main_ctx.uc_flags = 1;
	setcontext(&data->async->main_ctx);

}

void ngx_tcp_proc_async(ngx_tcp_data_t* data){
	ngx_connection_t* c = data->req_data->c;
	ngx_socket_t fd = c->fd;
	char clientaddr[32];
	memset(clientaddr,0,sizeof(clientaddr));
	memcpy(clientaddr, c->clientaddr, sizeof(clientaddr));

	NLOG_DEBUG2("fd[%d]:%s ****** proc begin ******", fd, clientaddr);
	data->async = (ngx_tcp_async_t*)ngx_calloc(sizeof(ngx_tcp_async_t)
				+data->conf->stack_size, c->log);
	
	getcontext(&data->async->work_ctx);
	data->async->work_ctx.uc_stack.ss_size = data->conf->stack_size;
	data->async->work_ctx.uc_stack.ss_sp = data->async->stack;
	//NLOG_DEBUG("mmmmmmmm malloc: 0x%08x", (long long)data->async->wctx.uc_stack.ss_sp);
	data->async->work_ctx.uc_stack.ss_flags = 0;
	data->async->work_ctx.uc_link = NULL;
	data->async->free_stask = 0;

	#if defined(__i386__)
	uint32_t data_ptr_v = (uint32_t)data;
	
	makecontext(&data->async->work_ctx,  (void(*)(void))&tcp_coroutine_proc, 1, data_ptr_v);
	#else
	uint64_t data_ptr_v = (uint64_t)data;
	uint32_t data_high = (uint32_t)((data_ptr_v >> 32)&0xFFFFFFFF);
	uint32_t data_low = (uint32_t)(data_ptr_v & 0xFFFFFFFF);	
	makecontext(&data->async->work_ctx,  (void(*)(void))&tcp_coroutine_proc, 2, data_high, data_low);
	#endif
	
	if (tcp_coroutine_wake(data, 0)) {
		
	}
	NLOG_DEBUG2("fd[%d]:%s ****** proc end ******", fd, clientaddr);
}

/* Syscalls interceptors */

//#define LOG_TMP(format, args...); printf("INFO: %s[%s:%d]"format"\n", __FUNCTION__,__FILE__,__LINE__, ##args);
#define LOG_TMP(format, args...);

#define INIT_ONCE(name) static name##_pt orig_##name = (name##_pt)dlsym(RTLD_NEXT, #name)

typedef int (*accept_pt)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
//static accept_pt orig_accept;

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {

	ssize_t ret;
	int flags;
	INIT_ONCE(accept);
	
	if (coroutine_scheduled) {

		flags = fcntl(sockfd, F_GETFL, 0);

		if (!(flags & O_NONBLOCK))
			fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
	}
	
	for(;;) {

		ret = orig_accept(sockfd, addr, addrlen);
	
		if (!coroutine_scheduled || ret != -1 || errno != EAGAIN)
			return ret;

		if (tcp_coroutine_yield(sockfd, NGX_READ_EVENT)) {
			/* timeout */
			errno = EINVAL;
			return -1;
		}
	}
}


typedef int (*connect_pt)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
//static connect_pt orig_connect;

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {

	ssize_t ret=0;
	int flags;
	socklen_t len;
	INIT_ONCE(connect);
	LOG_TMP("coroutine_scheduled:%d", coroutine_scheduled);
	if (coroutine_scheduled) {		
		flags = fcntl(sockfd, F_GETFL, 0);
		
		if (!(flags & O_NONBLOCK)){
			ret = fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
			if(ret != 0){
				NLOG_ERROR("fcntl(sockfd=%d, F_SETFL, flags=%s) failed! err:%s",
						sockfd, flags|O_NONBLOCK, strerror(errno));
			}
		}
	}

	ret = orig_connect(sockfd, addr, addrlen);
	
	if (!coroutine_scheduled || ret != -1 || errno != EINPROGRESS)
		return ret;

	for(;;) {

		if (tcp_coroutine_yield(sockfd, NGX_WRITE_EVENT)) {
			errno = ETIMEDOUT;
			return -1;
		}

		len = sizeof(flags);

		flags = 0;

		ret = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &flags, &len);

		if (ret == -1 || !len)
			return -1;

		if (!flags)
			return 0;

		if (flags != EINPROGRESS) {
			errno = flags;
			return -1;
		}
	}
}



typedef ssize_t (*read_pt)(int fd, void *buf, size_t count);
ssize_t read(int fd, void *buf, size_t count) {

	//static read_pt orig_read = (read_pt)dlsym(RTLD_NEXT, "read");
	INIT_ONCE(read);
	
	ssize_t ret;
	LOG_TMP("read(%d) begin ", fd);	
	for(;;) {

		ret = orig_read(fd, buf, count);
	
		if (!coroutine_scheduled || ret != -1 || errno != EAGAIN){
			LOG_TMP("read(%d) end: %d ", fd, (int)ret);	
			return ret;
		}

		if (tcp_coroutine_yield(fd, NGX_READ_EVENT)) {
			errno = ECONNREFUSED;
			return -1;
		}
	}
}


typedef ssize_t (*write_pt)(int fd, const void *buf, size_t count);
//static write_pt orig_write;

ssize_t write(int fd, const void *buf, size_t count) {

	INIT_ONCE(write);
	ssize_t ret;
	LOG_TMP("write(%d) begin ", fd);	
	for(;;) {

		ret = orig_write(fd, buf, count);
	
		if (!coroutine_scheduled || ret != -1 || errno != EAGAIN){
			LOG_TMP("write(%d) end: %d ", fd, (int)ret);	
			return ret;
		}

		if (tcp_coroutine_yield(fd, NGX_WRITE_EVENT)) {
			errno = ECONNRESET;
			return -1;
		}
	}
}


typedef ssize_t (*recv_pt)(int sockfd, void *buf, size_t len, int flags);
//static recv_pt orig_recv;

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {

	INIT_ONCE(recv);
	ssize_t ret;
	LOG_TMP("recv(%d) begin ", sockfd);	
	for(;;) {
		ret = orig_recv(sockfd, buf, len, flags);
		if (!coroutine_scheduled || ret != -1 || errno != EAGAIN){
			LOG_TMP("recv(%d) end: %d ", sockfd, (int)ret);	
			return ret;
		}

		if (tcp_coroutine_yield(sockfd, NGX_READ_EVENT)) {
			errno = ECONNRESET;
			return -1;
		}
	}
}


typedef ssize_t (*send_pt)(int sockfd, const void *buf, size_t len, int flags);
//static send_pt orig_send;

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {

	ssize_t ret;
	LOG_TMP("send(%d) begin ", sockfd);	
	INIT_ONCE(send);
	for(;;) {
		ret = orig_send(sockfd, buf, len, flags);
		if (!coroutine_scheduled || ret != -1 || errno != EAGAIN){
			LOG_TMP("send(%d) end: %d ", sockfd, (int)ret);	
			return ret;
		}

		if (tcp_coroutine_yield(sockfd, NGX_WRITE_EVENT)) {
			errno = ECONNREFUSED;
			return -1;
		}
	}
}

typedef int (*poll_pt)(struct pollfd *fds, nfds_t nfds, int timeout);
//static poll_pt orig_poll;

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {

	INIT_ONCE(poll);
	return coroutine_scheduled && timeout
		? (int)nfds /* always ready! */
		: orig_poll(fds, nfds, timeout);
	//return coroutine_scheduled ? (int)nfds: orig_poll(fds, nfds, timeout);
}


#if 0
/* TODO: check for fcntl() removing O_NONBLOCK flag */
__attribute__((constructor(101))) static void __tcp_coroutine_init() {
	printf("Init user thread ...\n");
#define INIT_SYSCALL(name) orig_##name = (name##_pt)dlsym(RTLD_NEXT, #name)
	INIT_SYSCALL(accept);
	INIT_SYSCALL(connect);
	//INIT_SYSCALL(read);
	INIT_SYSCALL(write);
	INIT_SYSCALL(recv);
	INIT_SYSCALL(send);
	INIT_SYSCALL(poll);
#undef INIT_SYSCALL
}
#endif


