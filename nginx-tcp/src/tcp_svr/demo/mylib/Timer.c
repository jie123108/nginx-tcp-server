#include "Timer.h"
#include "testlog.h"
#include <pthread.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>

static void s_timer_proc(union sigval arg);

static void s_sigaction(int sig,siginfo_t * siginfo,void *);

CTimer::CTimer()
	:m_timer(0),m_first(0), m_interval(0){ 
	memset(m_name, 0, sizeof(m_name));
}

CTimer::CTimer(const char* name)
	:m_timer(0),m_first(0), m_interval(0){ 
	SetTimerName(name);
}

void CTimer::SetTimerName(const char* name){
	strncpy(m_name, name, sizeof(m_name));
}

int CTimer::InitThreadTimer(TimerProc proc, void* proc_arg, size_t threadStackSize){
	if(m_timer != 0){
		NLOG_ERROR("Timer Inited ! m_timer(=%ld) != 0", (long)m_timer);
		return -1;
	}
	
	pthread_attr_t pthread_attr;
	pthread_attr_init(&pthread_attr);
	pthread_attr_setstacksize(&pthread_attr, threadStackSize * 1024);

	m_timerArg.proc = proc;
	m_timerArg.args = proc_arg;
	
	struct sigevent evt;
	memset(&evt, 0, sizeof(evt));
	
	evt.sigev_notify = SIGEV_THREAD;
	evt.sigev_value.sival_ptr = &m_timerArg;
	evt.sigev_notify_function = &s_timer_proc;
	evt.sigev_notify_attributes = &pthread_attr;

	int ret = timer_create(CLOCK_REALTIME, &evt, &m_timer);

	pthread_attr_destroy(&pthread_attr);
	if(m_name[0] == 0){//Name is NULL
		sprintf(m_name, "ThreadTimer-%ld", (long)m_timer);
	}	
	return ret;
}

int CTimer::InitSignalTimer(TimerProc proc, void* proc_arg){
	if(m_timer != 0){
		NLOG_ERROR("Timer Inited ! m_timer(=%ld) != 0", (long)m_timer);
		return -1;
	}

	m_timerArg.proc = proc;
	m_timerArg.args = proc_arg;
#if 0
	sigset_t sigset;
	sigfillset (&sigset);
	sigdelset (&sigset, SIGUSR2);
	sigprocmask (SIG_SETMASK, &sigset, NULL);
#endif

	struct sigaction action;
	memset(&action, 0, sizeof(action));
	sigemptyset(&action.sa_mask);
	action.sa_flags = SA_SIGINFO|SA_RESTART;
	action.sa_sigaction = &s_sigaction;
	if(sigaction(SIGUSR2, &action, NULL) <0){
		NLOG_ERROR("sigactin failed! err:%s", strerror(errno));
		return -1;
	}

	struct sigevent evt;
	memset(&evt, 0, sizeof(evt));
	evt.sigev_notify = SIGEV_SIGNAL;
	evt.sigev_signo = SIGUSR2;
	evt.sigev_value.sival_ptr = (void*)&m_timerArg;
	int ret = timer_create(CLOCK_REALTIME, &evt, &m_timer);
	if(m_name[0] == 0){//Name is NULL
		sprintf(m_name, "SignalTimer-%ld", (long)m_timer);
	}	

	return ret;
}


int CTimer::RestartTimer(double first, double interval){
	//时间间隔有变化 。
	if(m_first != first || m_interval != interval){
		NLOG_INFO("Timer [%s] Restarted [first:%.3lf, interval:%.3lf]", m_name, first, interval);
		StopTimer();
		return StartTimer(first, interval);
	}

	return 0;
}

int CTimer::StartTimer(double first, double interval){
	if(m_timer == 0){
		NLOG_ERROR("Timer Not Tnitialized!");
		return -1;
	}

	//first == 0
	if(fabs(first) < 0.000000001){
		NLOG_ERROR("arg first [%lf] Is Invalid!", first);
		return -1;
	}
	//interval == 0
	if(fabs(interval) < 0.000000001){
		NLOG_ERROR("arg interval [%lf] Is Invalid!", interval);
		return -1;
	}

	m_first = first;
	m_interval = interval;
	
	 struct  itimerspec timespec;
	 memset(&timespec, 0, sizeof(timespec));
	 timespec.it_value.tv_sec = Floor(first);
	 timespec.it_value.tv_nsec = ToNanoseconds(Frac(first));
	 timespec.it_interval.tv_sec = Floor(interval);
	 timespec.it_interval.tv_nsec =ToNanoseconds(Frac(interval));
	/* NLOG_DEBUG("Timer(%s) Start! First Run[%.6lf], Interval[%.6lf]",
					m_name,first, interval);
	*/
	return timer_settime(m_timer, 0, &timespec, NULL);		 
}

int CTimer::StopTimer(){
	if(m_timer == 0){
		return 0;
	}
	int ret = timer_settime(m_timer, 0, NULL, NULL);
	return ret;
}

int CTimer::DestroyTimer(){
	if(m_timer != 0){
		timer_delete(m_timer);
		m_timer = 0;
	}

	return 0;
}

static void s_timer_proc (union sigval arg){
	TimerArg* timerArg = (TimerArg*)arg.sival_ptr;
	if(timerArg->proc != NULL){
		timerArg->proc(timerArg->args);
	}
}

static void s_sigaction(int sig,siginfo_t * siginfo,void *proctx){
	TimerArg* timerArg = (TimerArg*)siginfo->si_value.sival_ptr;
	if(timerArg->proc != NULL){
		timerArg->proc(timerArg->args);
	}
}

