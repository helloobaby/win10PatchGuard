#include"stdafx.h"

extern "C" 
{

NTKERNELAPI
UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);


NTKERNELAPI PVOID RtlPcToFileHeader(
	PVOID PcValue,
	PVOID* BaseOfImage
);

typedef union _KWAIT_STATUS_REGISTER // 7 elements, 0x1 bytes (sizeof) 
{
    /*0x000*/     UINT8        Flags;
    struct                           // 6 elements, 0x1 bytes (sizeof) 
    {
        /*0x000*/         UINT8        State : 3;      // 0 BitPosition                  
        /*0x000*/         UINT8        Affinity : 1;   // 3 BitPosition                  
        /*0x000*/         UINT8        Priority : 1;   // 4 BitPosition                  
        /*0x000*/         UINT8        Apc : 1;        // 5 BitPosition                  
        /*0x000*/         UINT8        UserApc : 1;    // 6 BitPosition                  
        /*0x000*/         UINT8        Alert : 1;      // 7 BitPosition                  
    };
}KWAIT_STATUS_REGISTER, * PKWAIT_STATUS_REGISTER;

typedef struct _KTHREAD                                            // 187 elements, 0x5F0 bytes (sizeof) 
{
    /*0x000*/     struct _DISPATCHER_HEADER Header;                              // 58 elements, 0x18 bytes (sizeof)   
    /*0x018*/     VOID* SListFaultAddress;
    /*0x020*/     UINT64       QuantumTarget;
    /*0x028*/     VOID* InitialStack;
    /*0x030*/     VOID* StackLimit;
    /*0x038*/     VOID* StackBase;
    /*0x040*/     UINT64       ThreadLock;
    /*0x048*/     UINT64       CycleTime;
    /*0x050*/     ULONG32      CurrentRunTime;
    /*0x054*/     ULONG32      ExpectedRunTime;
    /*0x058*/     VOID* KernelStack;
    /*0x060*/     struct _XSAVE_FORMAT* StateSaveArea;
    /*0x068*/     struct _KSCHEDULING_GROUP* SchedulingGroup;
    /*0x070*/     union _KWAIT_STATUS_REGISTER WaitRegister;                     // 7 elements, 0x1 bytes (sizeof)     
    /*0x071*/     UINT8        Running;
    /*0x072*/     UINT8        Alerted[2];
    union                                                          // 2 elements, 0x4 bytes (sizeof)     
    {
        struct                                                     // 22 elements, 0x4 bytes (sizeof)    
        {
            /*0x074*/             ULONG32      AutoBoostActive : 1;                      // 0 BitPosition                      
            /*0x074*/             ULONG32      ReadyTransition : 1;                      // 1 BitPosition                      
            /*0x074*/             ULONG32      WaitNext : 1;                             // 2 BitPosition                      
            /*0x074*/             ULONG32      SystemAffinityActive : 1;                 // 3 BitPosition                      
            /*0x074*/             ULONG32      Alertable : 1;                            // 4 BitPosition                      
            /*0x074*/             ULONG32      UserStackWalkActive : 1;                  // 5 BitPosition                      
            /*0x074*/             ULONG32      ApcInterruptRequest : 1;                  // 6 BitPosition                      
            /*0x074*/             ULONG32      QuantumEndMigrate : 1;                    // 7 BitPosition                      
            /*0x074*/             ULONG32      UmsDirectedSwitchEnable : 1;              // 8 BitPosition                      
            /*0x074*/             ULONG32      TimerActive : 1;                          // 9 BitPosition                      
            /*0x074*/             ULONG32      SystemThread : 1;                         // 10 BitPosition                     
            /*0x074*/             ULONG32      ProcessDetachActive : 1;                  // 11 BitPosition                     
            /*0x074*/             ULONG32      CalloutActive : 1;                        // 12 BitPosition                     
            /*0x074*/             ULONG32      ScbReadyQueue : 1;                        // 13 BitPosition                     
            /*0x074*/             ULONG32      ApcQueueable : 1;                         // 14 BitPosition                     
            /*0x074*/             ULONG32      ReservedStackInUse : 1;                   // 15 BitPosition                     
            /*0x074*/             ULONG32      UmsPerformingSyscall : 1;                 // 16 BitPosition                     
            /*0x074*/             ULONG32      TimerSuspended : 1;                       // 17 BitPosition                     
            /*0x074*/             ULONG32      SuspendedWaitMode : 1;                    // 18 BitPosition                     
            /*0x074*/             ULONG32      SuspendSchedulerApcWait : 1;              // 19 BitPosition                     
            /*0x074*/             ULONG32      CetShadowStack : 1;                       // 20 BitPosition                     
            /*0x074*/             ULONG32      Reserved : 11;                            // 21 BitPosition                     
        }u2;
        /*0x074*/         LONG32       MiscFlags;
    };
    union                                                          // 2 elements, 0x4 bytes (sizeof)     
    {
        struct                                                     // 23 elements, 0x4 bytes (sizeof)    
        {
            /*0x078*/             ULONG32      BamQosLevel : 2;                          // 0 BitPosition                      
            /*0x078*/             ULONG32      AutoAlignment : 1;                        // 2 BitPosition                      
            /*0x078*/             ULONG32      DisableBoost : 1;                         // 3 BitPosition                      
            /*0x078*/             ULONG32      AlertedByThreadId : 1;                    // 4 BitPosition                      
            /*0x078*/             ULONG32      QuantumDonation : 1;                      // 5 BitPosition                      
            /*0x078*/             ULONG32      EnableStackSwap : 1;                      // 6 BitPosition                      
            /*0x078*/             ULONG32      GuiThread : 1;                            // 7 BitPosition                      
            /*0x078*/             ULONG32      DisableQuantum : 1;                       // 8 BitPosition                      
            /*0x078*/             ULONG32      ChargeOnlySchedulingGroup : 1;            // 9 BitPosition                      
            /*0x078*/             ULONG32      DeferPreemption : 1;                      // 10 BitPosition                     
            /*0x078*/             ULONG32      QueueDeferPreemption : 1;                 // 11 BitPosition                     
            /*0x078*/             ULONG32      ForceDeferSchedule : 1;                   // 12 BitPosition                     
            /*0x078*/             ULONG32      SharedReadyQueueAffinity : 1;             // 13 BitPosition                     
            /*0x078*/             ULONG32      FreezeCount : 1;                          // 14 BitPosition                     
            /*0x078*/             ULONG32      TerminationApcRequest : 1;                // 15 BitPosition                     
            /*0x078*/             ULONG32      AutoBoostEntriesExhausted : 1;            // 16 BitPosition                     
            /*0x078*/             ULONG32      KernelStackResident : 1;                  // 17 BitPosition                     
            /*0x078*/             ULONG32      TerminateRequestReason : 2;               // 18 BitPosition                     
            /*0x078*/             ULONG32      ProcessStackCountDecremented : 1;         // 20 BitPosition                     
            /*0x078*/             ULONG32      RestrictedGuiThread : 1;                  // 21 BitPosition                     
            /*0x078*/             ULONG32      VpBackingThread : 1;                      // 22 BitPosition                     
            /*0x078*/             ULONG32      ThreadFlagsSpare : 1;                     // 23 BitPosition                     
            /*0x078*/             ULONG32      EtwStackTraceApcInserted : 8;             // 24 BitPosition                     
        }u;
        /*0x078*/         LONG32       ThreadFlags;
    };
    /*0x07C*/     UINT8        Tag;
    /*0x07D*/     UINT8        SystemHeteroCpuPolicy;
    struct                                                         // 2 elements, 0x1 bytes (sizeof)     
    {
        /*0x07E*/         UINT8        UserHeteroCpuPolicy : 7;                      // 0 BitPosition                      
        /*0x07E*/         UINT8        ExplicitSystemHeteroCpuPolicy : 1;            // 7 BitPosition                      
    };
    union                                                          // 2 elements, 0x1 bytes (sizeof)     
    {
        struct                                                     // 2 elements, 0x1 bytes (sizeof)     
        {
            /*0x07F*/             UINT8        RunningNonRetpolineCode : 1;              // 0 BitPosition                      
            /*0x07F*/             UINT8        SpecCtrlSpare : 7;                        // 1 BitPosition                      
        };
        /*0x07F*/         UINT8        SpecCtrl;
    };
    /*0x080*/     ULONG32      SystemCallNumber;
    /*0x084*/     ULONG32      ReadyTime;
    /*0x088*/     VOID* FirstArgument;
    /*0x090*/     struct _KTRAP_FRAME* TrapFrame;
    union                                                          // 2 elements, 0x30 bytes (sizeof)    
    {
        /*0x098*/         struct _KAPC_STATE ApcState;                               // 9 elements, 0x30 bytes (sizeof)    
        struct                                                     // 3 elements, 0x30 bytes (sizeof)    
        {
            /*0x098*/             UINT8        ApcStateFill[43];
            /*0x0C3*/             CHAR         Priority;
            /*0x0C4*/             ULONG32      UserIdealProcessor;
        };
    };
};



































}