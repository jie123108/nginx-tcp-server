#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <dlfcn.h>
#include <poll.h>
#include "ngx_tcp.h"
#include "ngx_tcp_log.h"
#include "ngx_tcp_async_proc.h"

#undef LOG_DEBUG2
#define LOG_DEBUG2(format, args...) 

#define MTASK_WAKE_TIMEDOUT   0x01
//#define MTASK_WAKE_NOFINALIZE 0x02
#ifndef NOT_USE_ASYNC
static ngx_tcp_data_t *mtask_current = NULL;

#define mtask_setcurrent(data) (mtask_current = (data))

#define mtask_resetcurrent() mtask_setcurrent(NULL)

#define mtask_scheduled (mtask_current != NULL)

int tcp_mtask_wake(ngx_tcp_data_t* data, int flags);


static void tcp_mtask_read_event_handler(ngx_event_t *ev) {
	ngx_connection_t *c = (ngx_connection_t*)ev->data;
	ngx_tcp_data_t* data = (ngx_tcp_data_t*)c->data;
	ngx_tcp_core_srv_conf_t* core_conf;
	core_conf = (ngx_tcp_core_srv_conf_t*)data->req_data->tcp_data->conf;
	int wf = 0;

	if (ev->timedout) {		
		LOG_WARN("fd[%d]:%V read timeout(%d)", data->req_data->c->fd, 
					&data->req_data->c->addr_text,					
					core_conf->backend_timeout_recv);
		LOG_DEBUG2("fd[%d]:%V read timeout(%d)", data->req_data->c->fd, 
					&data->req_data->c->addr_text,					
					core_conf->backend_timeout_recv);
		wf |= MTASK_WAKE_TIMEDOUT;
	}

	tcp_mtask_wake(data, wf);
}

static void tcp_mtask_write_event_handler(ngx_event_t *ev) {
	ngx_connection_t *c = (ngx_connection_t*)ev->data;
	ngx_tcp_data_t* data = (ngx_tcp_data_t*)c->data;
	ngx_tcp_core_srv_conf_t* core_conf;
	core_conf = (ngx_tcp_core_srv_conf_t*)data->req_data->tcp_data->conf;
	int wf = 0;

	if (ev->timedout) {		
		LOG_WARN("fd[%d]:%V write timeout(%d)", data->req_data->c->fd, 
					&data->req_data->c->addr_text,
					core_conf->backend_timeout_send);
		wf |= MTASK_WAKE_TIMEDOUT;
	}

	tcp_mtask_wake(data, wf);
}

/* returns 1 on timeout */
int tcp_mtask_yield(int fd, ngx_int_t event) {
	ngx_tcp_data_t* data = mtask_current;
	ngx_connection_t *c;
	ngx_event_t *e;
	ngx_tcp_core_srv_conf_t* core_conf;
	char clientaddr[32];
	memset(clientaddr,0,sizeof(clientaddr));
	
	c = ngx_get_connection(fd, data->req_data->c->log);
	if(c == NULL){//worker_connections are not enough while nginx tcp module init connection
		LOG_ERROR("worker_connections are not enough while nginx tcp module init connection");
		data->async->timedout = 1;
		return data->async->timedout;
	}
	c->data = data;
	ngx_sprintf((u_char*)clientaddr, "%V", &c->addr_text);

	core_conf = (ngx_tcp_core_srv_conf_t*)data->req_data->tcp_data->conf;
	LOG_DEBUG2("req[%s] backend fd[%d] ++++++ mtask yield %s +++++", 
		clientaddr, c->fd, event & NGX_WRITE_EVENT ? "write" : "read");

	if (event == NGX_READ_EVENT){
		e = c->read;
		e->data = c;
		e->handler = &tcp_mtask_read_event_handler;
		e->log = data->req_data->c->log;
		if(core_conf->backend_timeout_recv != NGX_CONF_UNSET_MSEC){
			ngx_add_timer(e, core_conf->backend_timeout_recv);
		}
	}else{
		e = c->write;
		e->data = c;
		e->handler = &tcp_mtask_write_event_handler;
		e->log = data->req_data->c->log;
		if(core_conf->backend_timeout_send!= NGX_CONF_UNSET_MSEC){
			ngx_add_timer(e, core_conf->backend_timeout_send);
		}
	}

	//ngx_epoll_add_event
	ngx_add_event(e, event, 0);

	data->async->timedout = 0;

	swapcontext(&data->async->work_ctx, &data->async->main_ctx);
	LOG_DEBUG2("req[%s] backend fd[%d] ++++++ mtask waked %s +++++", 
		clientaddr, c->fd, event & NGX_WRITE_EVENT ? "write" : "read");

	if (e->timer_set)
		ngx_del_timer(e);

	ngx_del_event(e, event, 0);
	ngx_free_connection(c);

	return data->async->timedout;
}


int tcp_mtask_wake(ngx_tcp_data_t* data, int flags) {

	mtask_setcurrent(data);

	if (flags & MTASK_WAKE_TIMEDOUT){
		data->async->timedout = 1;
	}

	int fd = data->req_data->c->fd;
	char clientaddr[32];
	memset(clientaddr,0,sizeof(clientaddr));
	ngx_sprintf((u_char*)clientaddr, "%V", &data->req_data->c->addr_text);

	LOG_DEBUG2("fd[%d]:%s ------ work ctx wake------", fd, clientaddr);
	swapcontext(&data->async->main_ctx, &data->async->work_ctx);
	LOG_DEBUG2("fd[%d]:%s ------ main ctx run ------", fd, clientaddr);
	//LOG_DEBUG("ret=%d, rctx.uc_flags:%d", n, data->rctx.uc_flags);
	if (data->async->free_stask) {
		LOG_DEBUG2("fd[%d]:%s xxxxxx mtask finalize xxxxxx", fd, clientaddr);
		//LOG_DEBUG("mmmmmmmm free: 0x%08x", (long long)data->async->wctx.uc_stack.ss_sp);
		data->async->work_ctx.uc_stack.ss_sp = NULL;
		ngx_free(data->async);
		data->async = NULL;
		return 1;
	}
	mtask_resetcurrent();

	return 0;
}

#if defined(__i386__)
static void tcp_mtask_proc(uint32_t data_ptr_v){
#else
static void tcp_mtask_proc(uint32_t data_high, uint32_t data_low){
	uint64_t data_ptr_v = ((uint64_t)data_high << 32) | data_low;

#endif

	//LOG_DEBUG2("data:0x%016llx", data_ptr_v);
	ngx_tcp_data_t* data = (ngx_tcp_data_t*)data_ptr_v;
	
	ngx_connection_t    *c = data->req_data->c;

	int ret = 0;
	data->stat.proc = ngx_second();
	LOG_DEBUG2("fd[%d]:%V ### mtask_proc start ####", c->fd, &c->addr_text);
	ret = data->tcp_proc(data->req_data,data->rsp_data);
	LOG_DEBUG2("fd[%d]:%V ### mtask_proc end ####", c->fd, &c->addr_text);
	data->stat.proc = ngx_second()-data->stat.proc;
	mtask_resetcurrent();
	
	data->protocbs.set_rsp_code(data->rsp_data, ret);
	//LOG_ADDR(data->rsp_data);
	data->status = NS_SEND; 
 
	c->write->active = 0;
	c->write->ready = 0;
	//LOG_DEBUG2("data {0x%08x} status:%d",data, data->status);
	c->write->handler = &ngx_tcp_server_write_handler;

	ret = ngx_handle_write_event(c->write, 0);
	if(ret != NGX_OK)
	{
	    LOG_ERROR("ngx_hendle_write_event: %d", ret);
	    ngx_tcp_close_connection(c);
	    data->status = NS_CLOSE;
	}

	data->stat.all = ngx_second()-data->stat.all;
	if(data->protocbs.debug_stats != NULL){
		data->protocbs.debug_stats(data);
	}

	if(data->req_data != NULL){
		data->protocbs.free_req(c->pool, data->req_data);
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
	ngx_sprintf((u_char*)clientaddr, "%V", &c->addr_text);

	LOG_DEBUG2("fd[%d]:%s ****** proc begin ******", fd, clientaddr);
	data->async = (ngx_tcp_async_t*)ngx_calloc(sizeof(ngx_tcp_async_t)
				+data->conf->stack_size, c->log);
	
	getcontext(&data->async->work_ctx);
	data->async->work_ctx.uc_stack.ss_size = data->conf->stack_size;
	data->async->work_ctx.uc_stack.ss_sp = data->async->stack;
	//LOG_DEBUG("mmmmmmmm malloc: 0x%08x", (long long)data->async->wctx.uc_stack.ss_sp);
	data->async->work_ctx.uc_stack.ss_flags = 0;
	data->async->work_ctx.uc_link = NULL;
	data->async->free_stask = 0;

	#if defined(__i386__)
	uint32_t data_ptr_v = (uint32_t)data;
	
	makecontext(&data->async->work_ctx,  (void(*)(void))&tcp_mtask_proc, 1, data_ptr_v);
	#else
	uint64_t data_ptr_v = (uint64_t)data;
	uint32_t data_high = (uint32_t)((data_ptr_v >> 32)&0xFFFFFFFF);
	uint32_t data_low = (uint32_t)(data_ptr_v & 0xFFFFFFFF);	
	makecontext(&data->async->work_ctx,  (void(*)(void))&tcp_mtask_proc, 2, data_high, data_low);
	#endif
	
	if (tcp_mtask_wake(data, 0)) {
		
	}
	LOG_DEBUG2("fd[%d]:%s ****** proc end ******", fd, clientaddr);
}

/* Syscalls interceptors */

#if 0
#define LOG_TMP(format, args...); printf("INFO: %s "format"\n",__FUNCTION__,##args);
#define COST(expression);  double begin = ngx_second();expression; \
	LOG_TMP("%s cost: %.6f", #expression, ngx_second()-begin);
void show_flags(int sockfd){
	int flags = fcntl(sockfd, F_GETFL, 0);
	LOG_TMP("sockfd(%d) new flags: %d, O_NONBLOCK:%d", 
					sockfd, flags, O_NONBLOCK);
}
#else
#define LOG_TMP(format, args...);
#define COST(expression);  expression; 
#define show_flags(sockfd);
#endif

typedef int (*accept_pt)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
static accept_pt orig_accept;

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {

	ssize_t ret;
	int flags;

	if (mtask_scheduled) {

		flags = fcntl(sockfd, F_GETFL, 0);

		if (!(flags & O_NONBLOCK))
			fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
	}
	
	for(;;) {

		ret = orig_accept(sockfd, addr, addrlen);
	
		if (!mtask_scheduled || ret != -1 || errno != EAGAIN)
			return ret;

		if (tcp_mtask_yield(sockfd, NGX_READ_EVENT)) {
			/* timeout */
			errno = EINVAL;
			return -1;
		}
	}
}


typedef int (*connect_pt)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static connect_pt orig_connect;

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {

	ssize_t ret;
	int flags;
	socklen_t len;
	LOG_TMP("connect(%d) mtask_scheduled:%d", sockfd, mtask_scheduled);

	if (mtask_scheduled) {
		flags = fcntl(sockfd, F_GETFL, 0);
		LOG_TMP("sockfd(%d) flags: %d", sockfd, flags);
		if (!(flags & O_NONBLOCK)){
			LOG_TMP("#####SET (%d) TO NONBLACK #####", sockfd);
			ret = fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
			if(ret != 0){
				LOG_ERROR("fcntl(sockfd=%d, F_SETFL, flags=%s) failed! err:%s",
						sockfd, flags|O_NONBLOCK, strerror(errno));
			}
			show_flags(sockfd);
		}
	}

	COST(ret = orig_connect(sockfd, addr, addrlen));
	
	if (!mtask_scheduled || ret != -1 || errno != EINPROGRESS)
		return ret;

	for(;;) {

		if (tcp_mtask_yield(sockfd, NGX_WRITE_EVENT)) {
			errno = ETIMEDOUT;
			return -1;
		}

		len = sizeof(flags);

		flags = 0;

		ret = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &flags, &len);

		if (ret == -1 || !len)
			return -1;

		if (!flags){
			return 0;
		}

		if (flags != EINPROGRESS) {
			errno = flags;
			return -1;
		}
	}
}


typedef ssize_t (*read_pt)(int fd, void *buf, size_t count);
static read_pt orig_read;

ssize_t read(int fd, void *buf, size_t count) {

	ssize_t ret;
	LOG_TMP("read(%d) begin ", fd);	
	show_flags(fd);
	for(;;) {
		COST(ret = orig_read(fd, buf, count));
	
		if (!mtask_scheduled || ret != -1 || errno != EAGAIN){
			LOG_TMP("read(%d) end: %d ", fd, (int)ret);	
			return ret;
		}

		if (tcp_mtask_yield(fd, NGX_READ_EVENT)) {
			errno = ECONNREFUSED;
			return -1;
		}
	}
}


typedef ssize_t (*write_pt)(int fd, const void *buf, size_t count);
static write_pt orig_write;

ssize_t write(int fd, const void *buf, size_t count) {

	ssize_t ret;
	LOG_TMP("write(%d) begin ", fd);	
	show_flags(fd);
	for(;;) {

		COST(ret = orig_write(fd, buf, count));
	
		if (!mtask_scheduled || ret != -1 || errno != EAGAIN){
			LOG_TMP("write(%d) end: %d ", fd, (int)ret);	
			return ret;
		}

		if (tcp_mtask_yield(fd, NGX_WRITE_EVENT)) {
			errno = ECONNRESET;
			return -1;
		}
	}
}


typedef ssize_t (*recv_pt)(int sockfd, void *buf, size_t len, int flags);
static recv_pt orig_recv;

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {

	ssize_t ret;
	LOG_TMP("recv(%d) begin ", sockfd);	
	show_flags(sockfd);
	for(;;) {
		//double begin = ngx_second();
		COST(ret = orig_recv(sockfd, buf, len, flags));
		//double end = ngx_second();
		//LOG_TMP("recv(%d) cost: %.6f", sockfd, end-begin);
		if (!mtask_scheduled || ret != -1 || errno != EAGAIN){
			LOG_TMP("recv(%d) end: %d ", sockfd, (int)ret);	
			return ret;
		}

		if (tcp_mtask_yield(sockfd, NGX_READ_EVENT)) {
			errno = ECONNRESET;
			return -1;
		}
	}
}


typedef ssize_t (*send_pt)(int sockfd, const void *buf, size_t len, int flags);
static send_pt orig_send;

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {

	ssize_t ret;
	LOG_TMP("send(%d) begin ", sockfd);	
	show_flags(sockfd);
	for(;;) {
		COST(ret = orig_send(sockfd, buf, len, flags));
		if (!mtask_scheduled || ret != -1 || errno != EAGAIN){
			LOG_TMP("send(%d) end: %d ", sockfd, (int)ret);	
			return ret;
		}

		if (tcp_mtask_yield(sockfd, NGX_WRITE_EVENT)) {
			errno = ECONNREFUSED;
			return -1;
		}
	}
}

typedef int (*poll_pt)(struct pollfd *fds, nfds_t nfds, int timeout);
static poll_pt orig_poll;

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {

	return mtask_scheduled && timeout
		? (int)nfds /* always ready! */
		: orig_poll(fds, nfds, timeout);
	//return mtask_scheduled ? (int)nfds: orig_poll(fds, nfds, timeout);
}

/* TODO: check for fcntl() removing O_NONBLOCK flag */
__attribute__((constructor)) static void __tcp_mtask_init() {
	printf("Init user thread ...\n");
#define INIT_SYSCALL(name) orig_##name = (name##_pt)dlsym(RTLD_NEXT, #name)

	INIT_SYSCALL(accept);
	INIT_SYSCALL(connect);
	INIT_SYSCALL(read);
	INIT_SYSCALL(write);
	INIT_SYSCALL(recv);
	INIT_SYSCALL(send);
	INIT_SYSCALL(poll);

#undef INIT_SYSCALL
}
#endif

