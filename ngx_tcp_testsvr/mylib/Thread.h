#ifndef __THREAD_H_
#define __THREAD_H_
/*==============================================================
 * FileName:      Thread.h
 * Version:        1.0
 * Created by:    liuxj
 * Copyright (c) 2011 qvod Corporation.  All Rights Reserved. 
 *--------------------------------------------------------------
 * Description:   
 *      线程封装类。并可以设置堆栈大小，绑定CPU等基本功能
 *=============================================================*/
#include <pthread.h>

#define THREAD_STACK_SIZE 1024 //默认线程堆栈大小(单位KB).
typedef void* (* PThreadProc)(void*);

#define CLASS_UNCOPYABLE(classname) \
     private: \
      classname(const classname&); \
      classname& operator=(const classname&);

class Runnable {
public:
     virtual void Run() = 0;
     virtual ~Runnable() {}
};

int thread_set_affinity(int cpu_no);


class CThread : public Runnable {
     CLASS_UNCOPYABLE(CThread)
public:
	
    /*--------------------------------------------------------------
	* Function:     	CThread
	* Description:  	构造函数。
	* Input:			stackSize, 线程使用的堆栈大小。
	*				isJoinable, 线程是不是可Join的。
	* Return:       	启动状态，0表示成功， 1表示失败。
	*-------------------------------------------------------------*/
	CThread(int stackSize=THREAD_STACK_SIZE, int isJoinable=1);
    	virtual ~CThread();

      /*--------------------------------------------------------------
	* Function:     	Start
	* Description:  	启动线程。
	* Input:			无。
	* Return:       	启动状态，0表示成功， 1表示失败。
	*-------------------------------------------------------------*/
	virtual int Start();

	/*--------------------------------------------------------------
	 * Function:		Stop
	 * Description: 	停止线程。
	 * Input:			无。
	 * Return:		无。
	 *-------------------------------------------------------------*/
	virtual void Stop();

	void SetStop(){ m_isStop = true;}
	/*--------------------------------------------------------------
	 * Function:		Join
	 * Description: 	Join线程。
	 * Input:			无。
	 * Return:		无。
	 *-------------------------------------------------------------*/
	int  Join();

	/*--------------------------------------------------------------
	 * Function:		SetAffinity
	 * Description: 	将线程绑定到某个CPU之上。
	 * 				Linux下，查看每个CPU的使用率：top -d 1
	 *				之后按下1. 则显示多个CPU
	 * Input:			cpu_no CPU序号。(从0开始)
	 * Return:		返回绑定状态， 0表示成功， -1表示失败。
	 *-------------------------------------------------------------*/
	int SetAffinity(int cpu_no);

	inline int DetachSelf(){return pthread_detach(pthread_self());}
	
	bool isStoped(){
		return m_isStop;
	}
	virtual void Run()=0; // { LOG_ERROR("Function Run Unimplement....");}

protected:
	bool m_isStop;
	int m_isJoinable;	// 1 joinable 0 unjoinable.
	pthread_t m_thread;
	int m_stackSize;

private:
    static unsigned ThreadProc(void* param);
};

#endif
