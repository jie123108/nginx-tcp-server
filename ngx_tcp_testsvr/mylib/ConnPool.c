#include "ConnPool.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ngx_tcp_log.h"

#define PCALLOC(size) calloc(1,size)
#define PFREE(ptr) if(ptr){free(ptr);ptr=NULL;}

inline uint64_t uint64_inc(uint64_t* pcount){
	return __sync_add_and_fetch(pcount, 1);
}

#define sync_inc(p) __sync_add_and_fetch(p,1)
#define sync_dec(p) __sync_sub_and_fetch(p,1)
	

#define cpool_is_empty(pool) \
	(pool->start == pool->end && pool->curconns <= 0)

#define cpool_is_full(pool) \
	(pool->start == pool->end && pool->curconns > 0)

void* new_and_connect(conn_cb_t* cbs,void* args,conn_statis_t* statis){
	assert(cbs != NULL);
	void* conn = cbs->conn_new(args);
	if(conn != NULL){
		if(cbs->connect(conn, args)!=0){
			cbs->conn_free(conn);
			conn = NULL;
		}else{
			if(statis!=NULL)uint64_inc(&statis->connect);
		}
	}
	return conn;
}
void free_and_close(void* conn, conn_cb_t* cbs,conn_statis_t* statis){
	assert(cbs != NULL);
	if(conn != NULL){
		cbs->close(conn);
		cbs->conn_free(conn);
		if(statis!=NULL)uint64_inc(&statis->close);
	}
}

conn_pool_t* conn_pool_new(int size,int lazy_init,conn_cb_t* cbs, void* args)
{
	int i;
	assert(size > 0);
	conn_pool_t* pool = (conn_pool_t*)PCALLOC(sizeof(conn_pool_t));
	pool->conns = (void**)PCALLOC(sizeof(void*)*size);
	pool->size = size;
	pool->args = args;
	pool->curconns = 0;
	pool->cbs = (conn_cb_t*)PCALLOC(sizeof(conn_cb_t));
	memcpy(pool->cbs, cbs, sizeof(conn_cb_t));

	if(lazy_init == 0){
		pool->start = pool->end = 0;
		for(i=0;i<size; i++){
			pool->conns[i] = new_and_connect(cbs, args,&pool->statis);
			if(pool->conns[i]) sync_inc(&pool->curconns);
		}
	}else{
		pool->start = 0;
		pool->end = 0;
	}
	

	pthread_spin_init(&pool->spin, 0);
	return pool;
}

void conn_pool_free(conn_pool_t* pool)
{
	conn_cb_t* cbs = pool->cbs;
	int i;
	for(i=0;i<pool->size; i++){
		if(pool->conns[i] != NULL){
			free_and_close(pool->conns[i], cbs,&pool->statis);
			pool->conns[i] = NULL;
			sync_dec(&pool->curconns);
		}
	}
	pthread_spin_destroy(&pool->spin);
	PFREE(pool->cbs);
	PFREE(pool->conns);
	PFREE(pool);
}

void* conn_pool_get(conn_pool_t* pool)
{
	void* conn = NULL;
	conn_cb_t* cbs =pool->cbs;
	int islocked = (pthread_spin_lock(&pool->spin)==0);

	int null_count = 0;
	while(!cpool_is_empty(pool)){			
		if(pool->conns[pool->start] == NULL){
			pool->start = (pool->start+1)%pool->size;
			if(++null_count >= pool->size){//表示所有的链接都是空的。
				printf("############## conn_poo_get pool is empty ##############\n");
				pool->curconns = 0;
				break;
			}
			continue;
		}else{
			conn = pool->conns[pool->start];
			pool->conns[pool->start] = NULL;
			sync_dec(&pool->curconns);
			pool->start = (pool->start+1)%pool->size;
			if(conn != NULL)uint64_inc(&pool->statis.get);
			break;
		}
	}
	
	if(islocked)pthread_spin_unlock(&pool->spin);
	
	if(conn==NULL){
		conn = new_and_connect(cbs, pool->args, &pool->statis);
		if(conn != NULL)uint64_inc(&pool->statis.get_real);
	}
	
	return conn;
	
}

int conn_pool_put(conn_pool_t* pool, void* conn)
{
	conn_cb_t* cbs = pool->cbs;
	if(cbs->test_close(conn)){//需要关闭
		free_and_close(conn,cbs,&pool->statis);
		uint64_inc(&pool->statis.release_real);
		conn = NULL;
	}

	if(conn != NULL){
		int islocked = (pthread_spin_lock(&pool->spin)==0);
		
		if(!cpool_is_full(pool)){
			assert(pool->conns[pool->end] == NULL);			
			pool->conns[pool->end] = conn;
			conn = NULL;
			pool->end = (pool->end+1) % pool->size;
			sync_inc(&pool->curconns);
			uint64_inc(&pool->statis.release);			
		} 
		
		if(islocked)pthread_spin_unlock(&pool->spin);

		if(conn != NULL){
			free_and_close(conn,cbs,&pool->statis);
			uint64_inc(&pool->statis.release_real);
			conn = NULL;
		}
	}
	
	return 0;
}
