#include"global.hpp"

#ifdef DBG
ULONG memory_alloc;
ULONG memory_free;
#endif // DBG


ULONG Log(const char* format, ...)
{
	char buffer[256];

	va_list ap;
	__va_start(&ap, format);
	vsprintf(buffer, format, ap);

	return DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, buffer);
}

void* operator new(size_t size)
{
#ifndef DBG
	return ExAllocatePoolWithQuotaTag(NonPagedPool, size, 'ltsk');
#endif // !1
	void* p = ExAllocatePoolWithQuotaTag(NonPagedPool, size, 'ltsk');
	memory_alloc++;
	return p;
}

void* operator new[](size_t size)
{
#ifndef DBG
	return ExAllocatePoolWithQuotaTag(NonPagedPool, size, 'ltsk');
#endif // !1
	void* p = ExAllocatePoolWithQuotaTag(NonPagedPool, size, 'ltsk');
	memory_alloc++;
	return p;
}

void* operator new(size_t, void* _Where)
{
	return (_Where);
}

void operator delete(void* p)
{
#ifndef DBG
	if (p)
		ExFreePoolWithTag(p, 'kstl');
#endif // !DBG
	
	if (p) {
		memory_free++;
		ExFreePoolWithTag(p, 'kstl');
	}
}

void operator delete(void* p, size_t size)
{
#ifndef DBG
	if (p)
		ExFreePoolWithTag(p, 'kstl');
#endif // !DBG

	if (p) {
		memory_free++;
		ExFreePoolWithTag(p, 'kstl');	}
}

void operator delete[](void* p)
{
#ifndef DBG
	if (p)
		ExFreePoolWithTag(p, 'kstl');
#endif // !DBG

	if (p) {	//operator new[] ���÷����ǰ(size_t)���ֽ�������new[]����ĸ���
				//�������ڴ���void * p��ʱ����Զ�������-size_t
		memory_free++;
		ExFreePoolWithTag((void*)((ULONG_PTR)p), 'kstl');
	}
	
}

void operator delete[](void* p,size_t size)
{
#ifndef DBG
	if (p)
		ExFreePoolWithTag(p, 'kstl');
#endif // !DBG

	if (p) {
		memory_free++;
		ExFreePoolWithTag(p, 'kstl');
	}
	
}

void deallocate(void* p)
{
	//���ȫ�ֺ������ڵ�����������ͷ��ڴ棬����������������
#ifndef DBG
	if (p)
		ExFreePoolWithTag(p, 'kstl');
#endif // !DBG

	if (p) {
		memory_free++;
		ExFreePoolWithTag(p, 'kstl');
	}
}






