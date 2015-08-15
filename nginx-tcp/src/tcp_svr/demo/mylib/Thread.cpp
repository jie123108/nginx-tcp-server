#include "Thread.h"
#include "testlog.h"
#include<sched.h>
#include<sys/sysinfo.h>
#include <unistd.h>

int get_cpu_count()
{
	return sysconf(_SC_NPROCESSORS_CONF); 
}

int thread_set_affinity(int cpu_no){
	if(cpu_no >= get_cpu_count()){
		NLOG_ERROR("Invalid cpu no[%d], the max no of cpu is %d", 
					cpu_no, get_cpu_count()-1);
		return -1;
	}
	
	cpu_set_t mask;
	CPU_ZERO(&mask); 
	CPU_SET(cpu_no, &mask);
	int ret = 0;
	ret = sched_setaffinity(0, sizeof(mask), &mask);
	if(ret == -1) 
	{ 
		NLOG_ERROR("could not set CPU affinity!"); 
	}

	return ret;
}


CThread::CThread(int stackSize, int isJoinable)
:m_isJoinable(isJoinable)
,m_thread(0)
, m_stackSize(stackSize){
	m_isStop = false;
}

CThread::~CThread() {
	if (m_thread != 0){
		m_thread = 0;
	}
}

int CThread::Start() {
	if (m_thread != 0)
	{
		NLOG_ERROR(" %%%%%%%% WARN: Thread is started %%%%%%%%%%");
	    return -1;
	}

	pthread_attr_t attr ;
	pthread_attr_init( &attr ) ;

	if( pthread_attr_setstacksize( &attr , m_stackSize*1024 )){
		NLOG_ERROR( "pthread_attr_setstacksize is failed!!" ) ;
		pthread_attr_destroy( &attr ) ;
		return  -1;
	}

	PThreadProc threadProc = (PThreadProc)ThreadProc;
	int ret = pthread_create(&this->m_thread, &attr, threadProc, this);
	if(ret != 0)
	{
		NLOG_ERROR("CThread.Start is faild");
	}

	pthread_attr_destroy(&attr);

	return ret;
}

void CThread::Stop(){
	if(m_thread != 0){
		m_isStop = true;
		pthread_cancel(m_thread ) ;
		if(m_isJoinable){
			pthread_join(m_thread , NULL ) ;
		}
	}
}

int CThread::Join() {
	if(m_isJoinable){
		if(m_thread != 0) {
			int ret = pthread_join(m_thread, NULL);
			if(ret != 0){
				NLOG_ERROR("pthread join [%d] faild!", (int)pthread_self());
			}
			m_thread = 0;
		}
		return 0;
	}else{
		NLOG_ERROR("Join faild! thread is unjoinable!");
		return -1;
	}
}

int CThread::SetAffinity(int cpu_no){
	if(cpu_no >= get_cpu_count()){
		NLOG_ERROR("Invalid cpu no[%d], the max no of cpu is %d", 
					cpu_no, get_cpu_count()-1);
		return -1;
	}
	
	cpu_set_t mask;
	CPU_ZERO(&mask); 
	CPU_SET(cpu_no, &mask);
	int ret = 0;
	ret = sched_setaffinity(0, sizeof(mask), &mask);
	if(ret == -1) 
	{ 
		NLOG_ERROR("could not set CPU affinity!"); 
	}

	return ret;
}


unsigned CThread::ThreadProc(void* param) {
    	CThread* p = static_cast<CThread*>(param);
	if(!p->m_isJoinable){
		//unjoinable线程,设置成detach状态,使线程退出时自动释放资源.
		int ret = pthread_detach(pthread_self());
		if(ret != 0){
			NLOG_ERROR("detach thread[%d] faild!", (int)pthread_self());
		}
	}
	
	p->m_isStop = false;
	p->Run();
	p->m_isStop = true;
	p->m_thread = 0;//将m_thread清0,这样,等Run执行完成后,可以再次Start.
	return 0;
}
