#pragma once
#include"stdafx.h"
#include<cstdio>

namespace Utils
{

	ULONG_PTR FindPattern(ULONG_PTR base, const char* pattern, ULONG lenth);
	ULONG_PTR GetExportFunc(const wchar_t* funcName);
	//需要过滤的系统进程，如system、csrss.exe
	BOOLEAN IsProcessInWhite(const unsigned char* imageName);
	//需要保护的作弊进程，例如CE x64dbg
	BOOLEAN IsProcessToProtected(const unsigned char* imageName);
	BOOLEAN IsWindowToProtected(const unsigned char* windowName);
	ULONG Log(const char* format, ...);
	ULONG_PTR BBGetPte();
	ULONG_PTR BBMmMapIoSpace(PHYSICAL_ADDRESS PhysicalAddress, size_t NumbterOfBytes);

}