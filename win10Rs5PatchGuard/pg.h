#include"stdafx.h"
#include"vector.hpp"

using std::vector;

typedef struct _SYSTEM_BIGPOOL_ENTRY
{
    union {
        PVOID VirtualAddress;
        ULONG_PTR NonPaged : 1;
    };
    ULONG_PTR SizeInBytes;
    union {
        UCHAR Tag[4];
        ULONG TagUlong;
    };
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;
typedef struct _SYSTEM_BIGPOOL_INFORMATION
{
    ULONG Count;
    SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;

#pragma warning(disable : 4214)
typedef struct _MMPTE_HARDWARE64
{
    ULONGLONG Valid : 1;
    ULONGLONG Dirty1 : 1;
    ULONGLONG Owner : 1;
    ULONGLONG WriteThrough : 1;
    ULONGLONG CacheDisable : 1;
    ULONGLONG Accessed : 1;
    ULONGLONG Dirty : 1;
    ULONGLONG LargePage : 1;
    ULONGLONG Global : 1;
    ULONGLONG CopyOnWrite : 1;
    ULONGLONG Unused : 1;
    ULONGLONG Write : 1;
    ULONGLONG PageFrameNumber : 36;
    ULONGLONG reserved1 : 4;
    ULONGLONG SoftwareWsIndex : 11;
    ULONGLONG NoExecute : 1;
} MMPTE_HARDWARE64, * PMMPTE_HARDWARE64;

typedef struct _MMPTE
{
    union
    {
        ULONG_PTR Long;
        MMPTE_HARDWARE64 Hard;
    } u;
} MMPTE;
typedef MMPTE* PMMPTE;
#ifndef PTE_SHIFT
#define PTE_SHIFT 3
#endif
#ifndef PTI_SHIFT
#define PTI_SHIFT 12
#endif
#ifndef PDI_SHIFT
#define PDI_SHIFT 21
#endif
#ifndef PPI_SHIFT
#define PPI_SHIFT 30
#endif
#ifndef PXI_SHIFT
#define PXI_SHIFT 39
#endif

#define PHYSICAL_ADDRESS_BITS 40

inline ULONG_PTR gKernelBase;

inline vector<void*>* gAccessRoutine;

void FindAccessRoutine();

void InitKernelBase();

void BypassStart();

void InitAllFuncPointers();

void ExcuteHook();

void RestoreHook();

using KiDispatchException_t = VOID(__fastcall*)(
    IN PEXCEPTION_RECORD ExceptionRecord,
    IN PKEXCEPTION_FRAME ExceptionFrame,
    IN PKTRAP_FRAME TrapFrame,
    IN KPROCESSOR_MODE PreviousMode,
    IN BOOLEAN FirstChance
    );

inline KiDispatchException_t OriginKiDispatchException;
inline PVOID SystemKiDispatchException;

VOID(__fastcall DetourKiDispatchException)(
    IN PEXCEPTION_RECORD ExceptionRecord,
    IN PKEXCEPTION_FRAME ExceptionFrame,
    IN PKTRAP_FRAME TrapFrame,
    IN KPROCESSOR_MODE PreviousMode,
    IN BOOLEAN FirstChance
    );

inline PVOID IdleLoopThread;

extern "C" 
{
    inline PVOID SystemKiProcessExpiredTimerList = (PVOID)0xFFFFF8027112BF00;
    inline PVOID OriginKiProcessExpiredTimerList;
    void DetourKiProcessExpiredTimerList();
    bool DpcHandler(KDPC* Dpc);
    VOID DummyDpc(
        IN struct _KDPC* Dpc,
        IN PVOID DeferredContext,
        IN PVOID SystemArgument1,
        IN PVOID SystemArgument2
        );
}

void AttackSystemThread();

NTSTATUS ScanBigPool();
PMMPTE GetPTEForVA(IN PVOID pAddress);

using ExAllocatePoolWithTag_t = PVOID(__fastcall*)(
    __drv_strictTypeMatch(__drv_typeExpr)POOL_TYPE PoolType,
    SIZE_T                                         NumberOfBytes,
    ULONG                                          Tag
    );
inline PVOID SystemExAllocatePoolWithTag;
inline ExAllocatePoolWithTag_t OriginExAllocatePoolWithTag;
PVOID DetourExAllocatePoolWithTag(
    __drv_strictTypeMatch(__drv_typeExpr)POOL_TYPE PoolType,
    SIZE_T                                         NumberOfBytes,
    ULONG                                          Tag
);

inline KIRQL WPOFFx64()
{
    KIRQL irql = KeRaiseIrqlToDpcLevel();
    UINT64 cr0 = __readcr0();
    cr0 &= 0xfffffffffffeffff;
    __writecr0(cr0);
    _disable();
    return irql;
}

inline void WPONx64(KIRQL irql)
{
    UINT64 cr0 = __readcr0();
    cr0 |= 0x10000;
    _enable();
    __writecr0(cr0);
    KeLowerIrql(irql);
}


inline PVOID SystemKiDeliverApc;