#include "TcpTestClient.h"
#include "Timer.h"
#include "Atom.h"
#include "testlog.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

static double g_now_second = 0;
static double g_start = 0;
int g_errors[0xFFFF];
static int g_counter = 0;
static int g_thread_cnt = 0;
static int g_stop = 0;

static CThread* g_threads[MAX_TEST_THREADS];
static ClientCtx* g_ctxs[MAX_TEST_CONNECTIONS];
static CTimer g_timeTimer;

static void TimerAdd(void* args){
	g_now_second = second();
}


int ParseArgs(int argc, char* argv[], char* host, 
	int* port, int* threads,int* connections, int* requestCount, int* func, int* logLevel){
	int result;
	while((result = getopt(argc, argv, "h:p:t:c:f:r:l:?")) != -1){
		switch(result){
		case 'h'://host
		strcpy(host, optarg);
		break;
		case 'p'://Port
			*port = atoi(optarg);
		break;
		case 't'://threads
			*threads = atoi(optarg);
		break;
		case 'c':
			*connections = atoi(optarg);
		break;
		case 'r'://request count
			*requestCount = atoi(optarg);
		break;
		case 'f'://function
			if(func != NULL){
				*func = atoi(optarg);
			}
		break;
		case 'l'://log level.
			if(logLevel != NULL){
				*logLevel = atoi(optarg);
			}
		break;
		case '?':
			return 255;
		break;
		//default:
			//NLOG_ERROR("Unknow option -%c", result);
			//exit(0);
		}
	}

	return 0;
}


class CTcpTestThread :public CThread{
public:
	CTcpTestThread(const char* threadName,ClientCtx* ctxs, int request_count, 
			int* counter,FTcpRequest requestCb, void* args, int num)
	:CThread(512, 1)
	{
		strncpy(m_threadName, threadName, sizeof(m_threadName));
		m_ctxs = ctxs;
		m_ctx_cnt = 1;
		m_requestCount = request_count;
		m_counter = counter;
		m_requestCb = requestCb;
		m_args = args;
		m_num = num;
		m_ctxIdx = -1;
	}
	
	ClientCtx* GetCtx(){
		return m_ctxs;
	}
	
	void Run()
	{
		NLOG_INFO("Thread [%s] Start...", m_threadName);
		int ret = 0;
		for(int i= GetCounter(); i <= m_requestCount; i= GetCounter()){
			ClientCtx* ctx = GetCtx();

			ret = m_requestCb(i, ctx, m_args);
			
			if(ret== 0){
				AtomInt_Inc(&g_errors[0]);
			}else{
				if(ret < 0){
					AtomInt_Inc(&g_errors[ERRNO_UNKNOW]);
				}else{
					AtomInt_Inc(&g_errors[ret%0xFFFF]);
				}
			}

			if(i % m_num == 0){
				double usedtime = g_now_second -g_start;
				//NLOG_DEBUG("start:%.3f - now:%.3f", g_start, g_now_second);
				printf("Request %d time:%.3f\n", i, usedtime);
			}
			if(g_stop) break;
		}
		
		NLOG_INFO("Thread [%s] Stop...", m_threadName);
	}
	
	~CTcpTestThread(){};

	int GetCounter(){
		return AtomInt_Inc(m_counter);
	}

private:
	char m_threadName[32];
	ClientCtx* m_ctxs;
	int m_ctx_cnt;
	int m_requestCount;
	int* m_counter;
	FTcpRequest m_requestCb;
	void* m_args;
	int m_ctxIdx;
	int m_num;
	
};

void Report(int expectedCode){
	int total = g_counter;
	double usedtimes = g_now_second - g_start;
	double ops = 0;
	if(usedtimes != 0){
		ops = g_counter/usedtimes;
	}
	
	printf("requests,error,threads,totaltimes,  QPS\n");
	printf("%8d,%5d,%7d,%10.3f,%.2f\n", total,total-g_errors[0],g_thread_cnt, usedtimes,
			 ops);
	if(g_errors[expectedCode%0xFFFF]==total){
		printf("************** All Test Is OK **************\n");
	}else{
		printf("  Code...................Count\n");
		int i;
		for(i=0;i < 0xFFFF;i++){
			if(g_errors[i] != 0){
				printf("0x%04X...................%5d\n", i, g_errors[i]);
			}
		}
		printf("0x%04X is Expect Code\n", expectedCode);

	}
}

static void test_signal_handler(int sig){
	g_stop = 1;
}

int RunTcpTestClient(const char* ip, int port, unsigned int threads, 
			unsigned int request_count, FTcpRequest RequestCb, void* args,
			FClientCtxNew ClientNewCb, FClientCtxFree ClientFreeCb,int expectedCode, int num)
{
	if(threads > MAX_TEST_THREADS){
		NLOG_ERROR("threads(%d) > MAX_TEST_THREADS(%d)", threads, MAX_TEST_THREADS);
		return -1;
	}
	signal(SIGINT, test_signal_handler);
	signal(SIGQUIT, test_signal_handler);

	int connections = threads;

	g_thread_cnt = threads;
	g_timeTimer.InitThreadTimer(&TimerAdd, NULL);
	g_timeTimer.SetTimerName("timeTimer");
	g_timeTimer.StartTimer(0.001, 0.001);

	memset(&g_errors, 0, sizeof(int)*0xFFFF);
	memset(&g_threads, 0, sizeof(CThread*)*MAX_TEST_THREADS);
	memset(&g_ctxs, 0, sizeof(ClientCtx*)*MAX_TEST_THREADS);
	
	unsigned int i;
	NLOG_INFO("################## Test Begin ###################");
	NLOG_INFO("################# Connect Begin #################");
	for(i=0;ClientNewCb != NULL && i < connections; i++){
		g_ctxs[i] = ClientNewCb(ip, port); 
		if(g_ctxs[i] == NULL){
			NLOG_ERROR("Connec to [%s:%d] failed!", ip,port);
			return -1;
		}
	}
	NLOG_INFO("#################  Connect End  #################");

	g_start = second();
	g_now_second = second();

	char threadName[32];
	for(i=0;i < threads; i++){
		sprintf(threadName, "thread-%d", i);
		
		NLOG_INFO("########## One Thread One Socket ##############");
		g_threads[i] = new CTcpTestThread(threadName, g_ctxs[i],
			request_count, &g_counter, RequestCb, args, num);
		
		
		g_threads[i]->Start();

	}
	
	for(i=0;i < threads; i++){
		g_threads[i]->Join();
		delete g_threads[i];
		g_threads[i] = NULL;
	}
	
	for(i=0;ClientFreeCb != NULL&&i < connections; i++){
		ClientFreeCb(g_ctxs[i]);
		g_ctxs[i] = NULL;
	}
	
	NLOG_INFO("################## Test End ###################");
	if((unsigned)g_counter > request_count){//修正for循环引起的超界问题。
		g_counter = request_count;
	}
	Report(expectedCode);

	return 0;
}

