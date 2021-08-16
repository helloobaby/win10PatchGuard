#include"Utilities.h"

#define INRANGE(x,a,b)    (x >= a && x <= b) 
#define getBits( x )    (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte( x )    (getBits(x[0]) << 4 | getBits(x[1]))

namespace Utils
{

	ULONG_PTR FindPattern(ULONG_PTR base, const char* pattern,ULONG lenth)
	{
		const char* pat = pattern;
		ULONG_PTR firstMatch = 0;
		for (ULONG_PTR pCur = base; pCur < base + lenth; pCur++)
		{
			if (!*pat)
				return firstMatch;

			if (*(const char*)pat == '\?' || *(const char*)pCur == (const char)getByte(pat))
			{
				if (!firstMatch)
					firstMatch = pCur;


				if (!pat[2])
					return firstMatch;

				if (*(SHORT*)pat == '\?\?' || *(const char*)pat != '\?')
					pat += 3;

				else
					pat += 2;
			}
			else
			{
				pat = pattern;
				firstMatch = 0;
			}
		}
		return NULL;
	
	}

	ULONG_PTR GetExportFunc(const wchar_t* funcName)
	{
		//RTL_CONSTANT_STRING内部用了sizeof,那么传指针算长度就会有问题
		UNICODE_STRING 	stringFunc = {};
		RtlInitUnicodeString(&stringFunc, funcName);
		return (ULONG_PTR)MmGetSystemRoutineAddress(&stringFunc);
	}

	BOOLEAN IsProcessInWhite(const unsigned char* imageName)
	{
		if (!_stricmp((const char*)imageName, "Csrss.exe") ||
			!_stricmp((const char*)imageName, "System") ||
			!_stricmp((const char*)imageName, "Taskmgr.exe") ||
			!_stricmp((const char*)imageName, "Svchost.exe") ||
			!_stricmp((const char*)imageName, "Explorer.exe") ||
			!_stricmp((const char*)imageName, "System.exe") ||
			!_stricmp((const char*)imageName, "dllhost.exe") ||
			!_stricmp((const char*)imageName, "dwm.exe") ||
			!_stricmp((const char*)imageName, "ctfmon.exe") ||
			!_stricmp((const char*)imageName, "services.exe") ||
			!_stricmp((const char*)imageName, "smss.exe") ||
			!_stricmp((const char*)imageName, "lsass.exe") ||
			strstr((const char*)imageName, "vmtool") ||
			strstr((const char*)imageName, "Runtime") ||
			strstr((const char*)imageName, "WinStore") ||
			strstr((const char*)imageName, "taskhost") ||
			strstr((const char*)imageName, "WmiPrv"))
			return true;

		return false;
	}

	BOOLEAN IsProcessToProtected(const unsigned char* imageName)
	{
		if (strstr((const char*)imageName, "cheat") ||
			!_stricmp((const char*)imageName, "x64dbg.exe") ||
			!_stricmp((const char*)imageName, "x32dbg.exe") ||
			strstr((const char*)imageName, "ReClass") ||
			!_stricmp((const char*)imageName, "DbgX.Shell.exe") ||
			!_stricmp((const char*)imageName, "EngHost.exe") ||
			strstr((const char*)imageName, "PCHunter"))
			return true;

		return false;
	}

	BOOLEAN IsWindowToProtected(const unsigned char* windowName)
	{
		if (strstr((const char*)windowName, "Cheat Engine") ||
			strstr((const char*)windowName, "dbg") ||
			strstr((const char*)windowName, "WinDbg") ||
			strstr((const char*)windowName, "ReClass.NET") ||
			strstr((const char*)windowName, "List1"))//List1是PCHunter
			return true;


		return false;
	}

	ULONG Log(const char* format, ...)
	{
		char buffer[256];

		va_list ap;
		__va_start(&ap, format);
		vsprintf(buffer, format, ap);

		return DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, buffer);
	}

	ULONG_PTR BBGetPte()
	{
		//DbgBreakPoint();
		ULONG64 _t = __readcr3();
		PHYSICAL_ADDRESS pml4t = { _t };
		pml4t.QuadPart &= ~0xfff; //开启KPTI之后 cr3没有页对齐

		PPHYSICAL_ADDRESS pml4_va = (PPHYSICAL_ADDRESS)BBMmMapIoSpace(pml4t, 0x1000);
		int slot = 0;
		int index = 0;
		if (pml4_va)
		{
			while ((pml4_va[index].QuadPart & 0xFFFFFFFFF000) != pml4t.QuadPart)
			{
				index++;
				slot++;
				if (index >= 512) {
					KdPrint(("BBGetPte failed ! \n"));
					return NULL;
				}
			}
			ULONG64 pte_base = (slot + 0x1FFFE00i64) << 39;
			ZwUnmapViewOfSection(ZwCurrentProcess(), (PVOID)pml4_va);
			return pte_base;
		}
		return NULL;
	}

	ULONG_PTR BBMmMapIoSpace(PHYSICAL_ADDRESS PhysicalAddress, size_t NumbterOfBytes)
	{
		HANDLE hPhysicalMemory = NULL;
		WCHAR PhysicalMemoryName[] = L"\\Device\\PhysicalMemory";
		UNICODE_STRING PhysicalMemoryString;
		OBJECT_ATTRIBUTES attributes;
		RtlInitUnicodeString(&PhysicalMemoryString, PhysicalMemoryName);
		InitializeObjectAttributes(&attributes, &PhysicalMemoryString, 0, NULL, NULL);
		NTSTATUS status = ZwOpenSection(&hPhysicalMemory, SECTION_MAP_READ, &attributes);

		size_t view_size;        //必须为size_t  如果是ULONG或者DWORD会返回
		PVOID vaddress;          // 映射的虚地址       
		LARGE_INTEGER base;      // 物理内存地址

		vaddress = 0;
		view_size = NumbterOfBytes;
		base.QuadPart = (ULONGLONG)(PhysicalAddress.QuadPart);

		if (NT_SUCCESS(status)) {
			status = ZwMapViewOfSection(hPhysicalMemory,
				ZwCurrentProcess(),
				(PVOID*)&vaddress,
				0,
				view_size,
				&base,
				&view_size,
				ViewUnmap,
				MEM_TOP_DOWN,
				PAGE_READONLY);

			if (!NT_SUCCESS(status))
			{
				KdPrint(("ZwMapViewOfSection fault with status = %llx\n", status));
				return NULL;
			}
			else
				return (ULONG_PTR)vaddress;
		}
		else
		{
			KdPrint(("ZwOpenSection fault with status = %llx\n", status));
			return NULL;

		}
	}

}