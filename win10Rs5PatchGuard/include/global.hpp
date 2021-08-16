#pragma once 
#define _NO_CRT_STDIO_INLINE 
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(push, 0)
#include <ntifs.h>
#include <ntdef.h>
#include <ntddk.h>
#include <cstdio>
#include <stddef.h>
#include<type_traits>
#pragma warning(pop)


ULONG Log(const char* format, ...);

void* operator new(size_t size);
void* operator new[](size_t size);
void* operator new(size_t, void* _Where);

void operator delete(void* p);
void operator delete(void* p,size_t size);
void operator delete[](void* p);
void operator delete[](void* p, size_t size);

void deallocate(void* p);

template<typename T1,typename T2>
inline void construct(T1* p, T2& value)
{	
	//p->T1();
	new (p) T1(value);
}

template<typename T>
inline void destroy(T* pointer)
{
	pointer->~T();
}

template<typename T>
inline void destroy(typename T::iterator first, typename T::iterator last)
{
	while (first != last) {
		destroy(&*first);
		++first;
	}
}

