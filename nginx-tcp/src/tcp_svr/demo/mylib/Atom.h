#ifndef __ATOM_H__
#define __ATOM_H__
/*==============================================================
 * FileName:      Atom.h
 * Version:        1.0
 * Created by:    liuxj
 * Copyright (c) 2011 qvod Corporation.  All Rights Reserved. 
 *--------------------------------------------------------------
 * Description:   
 *      原子操作，包括加法，减法，递增，递减等。
 * 使用方法: int i= 10; int j = Atom<int>::Inc(&i)
 *=============================================================*/

#define AtomInt_Inc(ptr) Atom<int>::Inc(ptr)
#define AtomInt_Dec(ptr) Atom<int>::Dec(ptr)
#define AtomInt_Add(ptr, n) Atom<int>::Add(ptr, n)
#define AtomInt_Sub(ptr, n) Atom<int>::Sub(ptr, n)
#define AtomInt_Set(ptr, n) Atom<int>::Set(ptr, n)

#define AtomLL_Inc(ptr) Atom<long long>::Inc(ptr)
#define AtomLL_Dec(ptr) Atom<long long>::Dec(ptr)
#define AtomLL_Add(ptr, n) Atom<long long>::Add(ptr, n)
#define AtomLL_Sub(ptr, n) Atom<long long>::Sub(ptr, n)
#define AtomLL_Set(ptr, n) Atom<long long>::Set(ptr, n)


#define AtomUint64_Inc(ptr) Atom<uint64_t>::Inc(ptr)
#define AtomUint64_Dec(ptr) Atom<uint64_t>::Dec(ptr)
#define AtomUint64_Add(ptr, n) Atom<uint64_t>::Add(ptr, n)
#define AtomUint64_Sub(ptr, n) Atom<uint64_t>::Sub(ptr, n)
#define AtomUint64_Set(ptr, n) Atom<uint64_t>::Set(ptr, n)


template <typename T>
class Atom{
public:

	/*--------------------------------------------------------------
	 * 功能：		原子设置值。
	 * 参数：		pValue, 要进行原子操作的指针。
	 *			value 要设置的值。
	 * 返回值：	返回设置前pValue的值。
	 *-------------------------------------------------------------*/
	inline static T Set(volatile T* pValue, T value)
	{
		return __sync_lock_test_and_set(pValue, value);
	}
	
	/*--------------------------------------------------------------
	 * 功能：		原子加法。
	 * 参数：		pValue, 要进行原子操作的指针。
	 *			n 要加的值。
	 * 返回值：	返回增加后的值。
	 *-------------------------------------------------------------*/
	inline static T Add(volatile T* pValue, T n)
	{
		return __sync_add_and_fetch(pValue, n);
	}
	
	/*--------------------------------------------------------------
	 * 功能：		原子减法。
	 * 参数：		pValue, 要进行原子操作的指针。
	 *			n 要减的值。
	 * 返回值：	返回减法后的值。
	 *-------------------------------------------------------------*/
	inline static T Sub(volatile T* pValue, T n)
	{
		return __sync_sub_and_fetch(pValue, n);
	}

	
	/*--------------------------------------------------------------
	 * 功能：		原子加1。
	 * 参数：		pValue, 要进行原子操作的指针。
	 * 返回值：	返回递增后的值。
	 *-------------------------------------------------------------*/
	inline static T Inc(volatile T* pValue)
	{
		return Add(pValue, 1);
	}
	
	/*--------------------------------------------------------------
	 * 功能：		原子减1。
	 * 参数：		pValue, 要进行原子操作的指针。
	 * 返回值：	返回递减后的值。
	 *-------------------------------------------------------------*/
	inline static T Dec(volatile T* pValue)
	{
		return Sub(pValue, 1);
	}

};

#endif

