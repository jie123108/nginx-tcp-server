#ifndef __MYSQL_BASE_H__
#define __MYSQL_BASE_H__
#include <errmsg.h>
#include <mysqld_error.h>
#include <mysql.h>
#include <stdlib.h>
#include "ngx_tcp_log.h"


#define ERRNO_OK 0
#define ERRNO_EXEC_SQL_ERROR 	1100 //sql 执行异常(指sql语句有问题)。
#define ERRNO_MYSQL_ERROR		1101//sql异常(比如连接异常)(非sql语句问题引起的异常)
#define ERRNO_DATA_EXIST 		1110  //数据已经存在(插入数据时，出错)
#define ERRNO_DATA_NOT_FOUND 	1111 //查询无结果。


inline int mysql_queryex(MYSQL* mysql, const char* sql){
	int ret = 0;
	int len = strlen(sql);
	ret = mysql_real_query(mysql, sql, len);

	if (0 != ret)
	{
		int err = mysql_errno(mysql);
		if(err == CR_SERVER_GONE_ERROR || err == ER_QUERY_INTERRUPTED
			|| err == CR_SERVER_LOST){
			LOG_ERROR("Execute Sql[%.800s] Failed!: %d, %s\n", sql,err, mysql_error(mysql));
			return ERRNO_MYSQL_ERROR;
		}else if(err == ER_DUP_ENTRY){
			LOG_DEBUG("Execute Sql[%.800s] Failed!: %s\n", sql, mysql_error(mysql));		
			return ERRNO_DATA_EXIST;
		}
		
		LOG_ERROR("Execute Sql[%.800s] Failed!: %d, %s\n", sql,err, mysql_error(mysql));
		if(len > 1024){
			LOG_DEBUG2_BIG("ERROR: Execute Sql[%s] Failed!: %d, %s\n", sql,err, mysql_error(mysql));
		}
		return ERRNO_EXEC_SQL_ERROR;
	}

	return ERRNO_OK;
}

inline int mysql_update(MYSQL* mysql, const char* sql, int* effects){
	int ret = mysql_queryex(mysql, sql);
	*effects = mysql_affected_rows(mysql);
	return ret;
}


inline int mysql_query_int(MYSQL* mysql, const char* sql, int* iret){
	int ret = 0;
	ret = mysql_queryex(mysql, sql);
	if(ret != ERRNO_OK){
		return ret;
	}
	
	MYSQL_RES* result = NULL;
	ret = ERRNO_DATA_NOT_FOUND;
	int i=0;
	do 
	{ 
		i++;
	    result = mysql_use_result( mysql ); 
		if(result == NULL){
			break;
		}
		if(ret != ERRNO_OK ){
			//usleep(10);
			MYSQL_ROW row = mysql_fetch_row(result);
			if(row != NULL){
				ret = ERRNO_OK;
				*iret  = atoi(row[0]);
			}
		}		
	    mysql_free_result(result); 
	}while(mysql_next_result(mysql)==0);
	
	return ret;
}

inline void mysql_free_all_result(MYSQL* mysql){
	MYSQL_RES* result = NULL;
	do 
	{ 
	    	result = mysql_use_result( mysql ); 
		if(result != NULL){
	    		mysql_free_result(result); 
		}		
	}while(mysql_next_result(mysql)==0);
}

typedef int (*FParseResult)(MYSQL_ROW row, void* obj);

inline int mysql_query_and_parse(MYSQL* mysql, const char* sql,FParseResult ParseResult, void* obj){
	int ret = mysql_queryex(mysql, sql);
	if(ret != 0){
		return ret;
	}
	MYSQL_RES* result = NULL;
	ret = ERRNO_DATA_NOT_FOUND;
	
	do { 
	    result = mysql_use_result(mysql); 
		if(result == NULL){
			break;
		}
		if(ret != ERRNO_OK){			
			MYSQL_ROW row = mysql_fetch_row(result);
			if(row != NULL){
				ret = ParseResult(row, obj);
			}
		}		
	    mysql_free_result(result); 
	}while(mysql_next_result(mysql)==0);


	return ret;
}

inline int mysql_trans_begin(MYSQL* mysql)
{
	return mysql_query(mysql, "begin");
}

inline int mysql_trans_commit(MYSQL* mysql)
{
	return mysql_query(mysql, "commit");
}

inline int mysql_trans_rollback(MYSQL* mysql)
{
	return mysql_query(mysql, "rollback");
}

#endif

