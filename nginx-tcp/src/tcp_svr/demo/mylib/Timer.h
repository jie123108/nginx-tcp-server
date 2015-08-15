#ifndef __BASE_LIB_TIMER_H__
#define  __BASE_LIB_TIMER_H__
#include <signal.h> 
#include <time.h>
#include <math.h>
/*==============================================================
 * FileName:      Timer.h
 * Version:        1.0
 * Created by:    liuxj
 * Copyright (c) 2011 qvod Corporation.  All Rights Reserved. 
 *--------------------------------------------------------------
 * Description:   
 *      定时器类。
 *=============================================================*/

#define Floor(double_val) ((long)floor(double_val))
#define Frac(double_val) (double_val-Floor(double_val))
#define ToNanoseconds(seconds) (long int)(seconds * 1000000000)

typedef void (*TimerProc)(void* args);
typedef struct {
	TimerProc proc;
	void* args;
}TimerArg;

class CTimer{
private:
	char m_name[32]; //用于输出调试信息。
	TimerArg m_timerArg;
	timer_t m_timer;
	double m_first; 
	double m_interval;
public:
	CTimer();
	CTimer(const char* name);
	~CTimer(){
		StopTimer();
		DestroyTimer();
	}

	void SetTimerName(const char* name);
	
	/*--------------------------------------------------------------
	* Function:     	InitThreadTimer
	* Description:  	初始化一个定时器(类型为线程) 线程类型的定时
	*				器使用于调用频率不太高的场合。
	* Input:			proc, 定时器到时间后要执行的线程处理函数。
	*				proc_arg, 线程处理函数的参数。
	*				threadStackSize, 线程使用的堆栈大小,单位KB。
	* Return:       	启动状态，0表示成功， 1表示失败。
	*-------------------------------------------------------------*/
	int InitThreadTimer(TimerProc proc, void* proc_arg, size_t threadStackSize =10);

	int InitSignalTimer(TimerProc proc, void* proc_arg);
	
	/*--------------------------------------------------------------
	* Function:     	StartTimer
	* Description:  	启动一个定时器
	* Input:			first, 每一次运行的时间(单位为秒,小数部分转成nanoseconds)
	*				interval, 后面运行的间隔时间(单位为秒,小数部分转成nanoseconds)
	* Return:       	启动状态，0表示成功， 1表示失败。
	*-------------------------------------------------------------*/
	int StartTimer(double first, double interval);

	/*--------------------------------------------------------------
	* Description:  	重新一个定时器(重新设置时间间隔)
	* Input:			first, 每一次运行的时间(单位为秒,小数部分转成nanoseconds)
	*				interval, 后面运行的间隔时间(单位为秒,小数部分转成nanoseconds)
	* Return:       	启动状态，0表示成功， 1表示失败。
	*-------------------------------------------------------------*/
	int RestartTimer(double first, double interval);
	
	int StopTimer();

	int DestroyTimer();
};

#if 0
union sigval { 
 int sival_int; 
 void *sival_ptr; 
 }; 

 struct sigevent { 
 int sigev_notify; /* Notification method */ 
 int sigev_signo; /* Timer expiration signal */ 
 union sigval sigev_value; /* Value accompanying signal or 
 passed to thread function */ 
 void (*sigev_notify_function) (union sigval); 
 /* Function used for thread 
 notifications (SIGEV_THREAD) */ 
 void *sigev_notify_attributes; 
 /* Attributes for notification thread 
 (SIGEV_THREAD) */ 
 pid_t sigev_notify_thread_id; 
 /* ID of thread to signal (SIGEV_THREAD_ID) */ 
 };

 其中，sigev_notify 指明了通知的方式 :

SIGEV_NONE

当定时器到期时，不发送异步通知，但该定时器的运行进度可以使用 timer_gettime(2) 监测。

SIGEV_SIGNAL

当定时器到期时，发送 sigev_signo 指定的信号。

SIGEV_THREAD

当定时器到期时，以 sigev_notify_function 开始一个新的线程。该函数使用 sigev_value 作为其参数，当 sigev_notify_attributes 非空，则制定该线程的属性。注意，由于 Linux 上线程的特殊性，这个功能实际上是由 glibc 和内核一起实现的。

SIGEV_THREAD_ID (Linux-specific)

仅推荐在实现线程库时候使用。

如果 evp 为空的话，则该函数的行为等效于：sigev_notify = SIGEV_SIGNAL，sigev_signo = SIGVTALRM，sigev_value.sival_int = timer ID 。

  struct   timespec   {   
                  long                 tv_sec;                  /*   seconds   */   
                  long                 tv_nsec;                 /*   nanoseconds  (1/1000000000 seconds) */   
  };   

  struct     itimerspec   {   
                  struct     timespec   it_interval;         /*   timer   period   */   
                  struct     timespec   it_value;            /*   timer   expiration   */   
  };  

#endif

#endif



