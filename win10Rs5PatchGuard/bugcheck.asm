*** Fatal System Error: 0x00000109
                       (0xA3A006DA0BD6B4F3,0xB3B713605E54F371,0xFFFFF8061EA178E0,0x0000000000000001)

https://github.com/tandasat/PgResarch/blob/5a2bb5433aae617cf9737bd1efc1643886f6bcf5/109/109/109.cpp#L227
ULONG64 pgContextAddr = bugCheckParameter[0] - 0xA3A03F5891C8B4E8;
reasonInfoAddr = bugCheckParameter[1] - 0xB3B74BDEE4453415;
第一个参数是CmpAppendDllSection的地址，第二个是context的地址，需要减去magic number
第三个参数是pg检测的地址(IopTimerDispatch)




//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 # Child-SP          RetAddr               Call Site
00 ffff8803`63a27d58 fffff805`5413bd72     nt!DbgBreakPointWithStatus
01 ffff8803`63a27d60 fffff805`5413b4f7     nt!KiBugCheckDebugBreak+0x12
02 ffff8803`63a27dc0 fffff805`5405e837     nt!KeBugCheck2+0x957
03 ffff8803`63a284e0 fffff805`5413907e     nt!KeBugCheckEx+0x107
04 ffff8803`63a28520 fffff805`5406721f     nt!KiFatalExceptionHandler+0x22
05 ffff8803`63a28560 fffff805`53fc0240     nt!RtlpExecuteHandlerForException+0xf
06 ffff8803`63a28590 fffff805`53ecdac4     nt!RtlDispatchException+0x430
07 ffff8803`63a28ce0 fffff808`d4bc26d9     nt!KiDispatchException+0x144
08 ffff8803`63a29390 fffff805`5406ff42     win10Rs5PatchGuard!DetourKiDispatchException+0x109 [C:\Users\asdf\source\repos\win10Rs5PatchGuard\win10Rs5PatchGuard\pg.cpp @ 90] 
09 ffff8803`63a29400 fffff805`5406be05     nt!KiExceptionDispatch+0xc2
0a ffff8803`63a295e0 fffff805`5407c00a     nt!KiGeneralProtectionFault+0x305
0b ffff8803`63a29770 fffff805`53f22f69     nt!IopTimerDispatch+0x1cf72a ;pg在这里准备触发异常
0c ffff8803`63a29960 fffff805`53f23eb7     nt!KiProcessExpiredTimerList+0x159
0d ffff8803`63a29a50 fffff805`5406214a     nt!KiRetireDpcList+0x4a7
0e ffff8803`63a29c60 00000000`00000000     nt!KiIdleLoop+0x5a

fffff805`5407c00a 393b            cmp     dword ptr [rbx],edi
0: kd> r rdx
rdx=691de21330a0b69b

.text:FFFFF80553EAC984 ;     __try { // __finally(IopTimerDispatch$fin$1)
.text:FFFFF80553EAC984 ;       __try { // __finally(IopTimerDispatch$fin$0)
.text:FFFFF80553EAC984 ;   __try { // __except at loc_FFFFF80553EAC993
.text:FFFFF80553EAC984                 mov     rcx, rbx
.text:FFFFF80553EAC987                 call    KiCustomAccessRoutine1
.text:FFFFF80553EAC98C                 nop
.text:FFFFF80553EAC98C ;       } // starts at FFFFF80553EAC984
.text:FFFFF80553EAC98D
.text:FFFFF80553EAC98D loc_FFFFF80553EAC98D:                   ; DATA XREF: .rdata:FFFFF80554233FC0↓o
.text:FFFFF80553EAC98D                 nop
.text:FFFFF80553EAC98D ;     } // starts at FFFFF80553EAC984
.text:FFFFF80553EAC98E
.text:FFFFF80553EAC98E loc_FFFFF80553EAC98E:                   ; DATA XREF: .rdata:FFFFF80554233FD0↓o
.text:FFFFF80553EAC98E                 jmp     loc_FFFFF8055407C00A ;这里也会解引用rbx，所以这里也会发生异常

//-----------------------------------------------------------------



//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 # Child-SP          RetAddr               Call Site
00 ffffa682`66c27d88 fffff802`71344d72     nt!DbgBreakPointWithStatus
01 ffffa682`66c27d90 fffff802`713444f7     nt!KiBugCheckDebugBreak+0x12
02 ffffa682`66c27df0 fffff802`71267837     nt!KeBugCheck2+0x957
03 ffffa682`66c28510 fffff802`7134207e     nt!KeBugCheckEx+0x107
04 ffffa682`66c28550 fffff802`7127021f     nt!KiFatalExceptionHandler+0x22
05 ffffa682`66c28590 fffff802`711c9240     nt!RtlpExecuteHandlerForException+0xf
06 ffffa682`66c285c0 fffff802`710d6ac4     nt!RtlDispatchException+0x430
07 ffffa682`66c28d10 fffff800`f1592715     nt!KiDispatchException+0x144
08 ffffa682`66c293c0 fffff802`71278f42     win10Rs5PatchGuard!DetourKiDispatchException+0x145 [C:\Users\asdf\source\repos\win10Rs5PatchGuard\win10Rs5PatchGuard\pg.cpp @ 104] 
09 ffffa682`66c29430 fffff802`71274e05     nt!KiExceptionDispatch+0xc2
0a ffffa682`66c29610 fffff802`71319a28     nt!KiGeneralProtectionFault+0x305
0b ffffa682`66c297a0 fffff802`7112bf69     nt!PopThermalZoneDpc+0xdb2a8
0c ffffa682`66c29960 fffff802`7112ceb7     nt!KiProcessExpiredTimerList+0x159
0d ffffa682`66c29a50 fffff802`7126b14a     nt!KiRetireDpcList+0x4a7
0e ffffa682`66c29c60 00000000`00000000     nt!KiIdleLoop+0x5a

//------------------------------------------------------------------------



//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 # Child-SP          RetAddr               Call Site
00 fffff802`73479098 fffff802`71344d72     nt!DbgBreakPointWithStatus
01 fffff802`734790a0 fffff802`713444f7     nt!KiBugCheckDebugBreak+0x12
02 fffff802`73479100 fffff802`71267837     nt!KeBugCheck2+0x957
03 fffff802`73479820 fffff802`7134207e     nt!KeBugCheckEx+0x107
04 fffff802`73479860 fffff802`7127021f     nt!KiFatalExceptionHandler+0x22
05 fffff802`734798a0 fffff802`711c9240     nt!RtlpExecuteHandlerForException+0xf
06 fffff802`734798d0 fffff802`710d6ac4     nt!RtlDispatchException+0x430
07 fffff802`7347a020 fffff800`f15b26e0     nt!KiDispatchException+0x144
08 fffff802`7347a6d0 fffff802`71278f42     win10Rs5PatchGuard!DetourKiDispatchException+0x110 [C:\Users\asdf\source\repos\win10Rs5PatchGuard\win10Rs5PatchGuard\pg.cpp @ 118] 
09 fffff802`7347a740 fffff802`71274e05     nt!KiExceptionDispatch+0xc2
0a fffff802`7347a920 fffff802`710e6dac     nt!KiGeneralProtectionFault+0x305
0b fffff802`7347aab0 fffff802`71319a31     nt!IoCancelIrp+0x2c
0c fffff802`7347aaf0 fffff802`7112bf69     nt!PopThermalZoneDpc+0xdb2b1
0d fffff802`7347acb0 fffff802`7112ceb7     nt!KiProcessExpiredTimerList+0x159
0e fffff802`7347ada0 fffff802`7126e595     nt!KiRetireDpcList+0x4a7
0f fffff802`7347afb0 fffff802`7126e380     nt!KxRetireDpcList+0x5
10 ffffa682`67c29800 fffff802`7126da6c     nt!KiDispatchInterruptContinue
11 ffffa682`67c29830 fffff802`7118d581     nt!KiDpcInterrupt+0x2dc
12 ffffa682`67c299c0 fffff802`716d451c     nt!KeWaitForSingleObject+0x1171
13 ffffa682`67c29a90 fffff802`71278885     nt!NtWaitForSingleObject+0xfc
14 ffffa682`67c29b00 00007ffb`d66cf714     nt!KiSystemServiceCopyEnd+0x25
15 000000cd`daceb0d8 00007ffb`d35f83d3     0x00007ffb`d66cf714
16 000000cd`daceb0e0 00000000`00000000     0x00007ffb`d35f83d3

这个快照的问题在于
.text:FFFFF805540357F6 loc_FFFFF805540357F6:                   ; DATA XREF: .rdata:FFFFF8055428F7B0↓o
.text:FFFFF805540357F6 ;   __except(PopThermalZoneDpc$filt$2) // owned by FFFFF805540357E7
.text:FFFFF805540357F6                 mov     rbx, [rsp+1B8h+arg_8]
.text:FFFFF805540357FE                 jmp     loc_FFFFF80554110A28

.text:FFFFF80554110A28 loc_FFFFF80554110A28:                   ; CODE XREF: PopThermalZoneDpc+2B↑j
.text:FFFFF80554110A28                                         ; PopThermalZoneDpc:loc_FFFFF805540357F1↑j ...
.text:FFFFF80554110A28 ; __unwind { // __C_specific_handler    ; Irp
.text:FFFFF80554110A28                 mov     rcx, [rbx+38h] ;如果hook KiDispatchException 随便传rbx的值的话，
                                                                    ;IoCancelIrp的行为也会导致问题
                                                                    ;pg的except块是用来恢复参数寄存器的
.text:FFFFF80554110A2C                 call    IoCancelIrp
.text:FFFFF80554110A31                 nop
.text:FFFFF80554110A32                 jmp     loc_FFFFF80554035804
//------------------------------------------------------------------------

//+++
这里出了个小插曲，想hook的时候发现hook _guard_dispatch_icall这里会直接卡死
主机加载也是cpu直接去世，蓝屏的机会都没有
所以这个方式拦截DPC行不通
//---

//+++
用khook的时候注意不要hook跳转附近的代码，会造成目的地不正确的问题，还要16字节对齐
//---

//++++++++++
2021.8.12 快照信息

//----------

//+++
2021.8.14  20:27 快照
*** Fatal System Error: 0x00000109
                       (0xA39FC9DF1A68D7C6,0xB3B6D6656CE70D94,0xFFFFF80306ED4980,0x0000000000000000)
ffff8a86`8880203f
Cmpxxx ffff8a8688802000
发现CmpXXX这个都是在一个页内，但是偏移地址随机
//---

//+++
开机的时候分配一个context，验证的时候还要分配一个context，执行验证完销毁，准备再一次验证
//---

//+++
pg线程的堆栈
1: kd> !thread ffff8a86824d8080
THREAD ffff8a86824d8080  Cid 0004.0098  Teb: 0000000000000000 Win32Thread: 0000000000000000 WAIT: (Executive) KernelMode Non-Alertable
    ffff8a8682481b50  Timer2SynchronizationObject
Not impersonating
DeviceMap                 ffff9a8c52e13060
Owning Process            ffff8a8682491040       Image:         System
Attached Process          N/A            Image:         N/A
Wait Start TickCount      32             Ticks: 3085 (0:00:00:48.203)
Context Switch Count      8              IdealProcessor: 0             
UserTime                  00:00:00.000
KernelTime                00:00:00.000
Win32 Start Address nt!ExpWorkerThread (0xfffff80306f26990)
Stack Init ffffeb018a11cc90 Current ffffeb018a11b670
Base ffffeb018a11d000 Limit ffffeb018a117000 Call 0000000000000000
Priority 12 BasePriority 12 PriorityDecrement 0 IoPriority 2 PagePriority 5
Child-SP          RetAddr               : Args to Child                                                           : Call Site
nt!KiSwapContext+0x76
nt!KiSwapThread+0x297
nt!KiCommitThreadWait+0x508
nt!KeWaitForSingleObject+0x520
0xffff8a86`81f10f0b //FsRtlMdlReadCompleteDevex+xx
0xffff8a86`82481b50
0xfffff803`00000000
//---


//+++
在给线程插入APC的时候，插入有时候蓝屏，执行也有时候蓝屏[待处理！]
1: kd> !thread
THREAD ffff8a8682557080  Cid 0004.000c  Teb: 0000000000000000 Win32Thread: 0000000000000000 RUNNING on processor 1
Not impersonating
DeviceMap                 ffff9a8c52e13060
Owning Process            ffff8a8682491040       Image:         System
Attached Process          N/A            Image:         N/A
Wait Start TickCount      32             Ticks: 2881 (0:00:00:45.015)
Context Switch Count      3              IdealProcessor: 0             
UserTime                  00:00:00.000
KernelTime                00:00:00.015
Win32 Start Address nt!PopIrpWorkerControl (0xfffff8030703df80)
Stack Init ffffeb018a00dc90 Current ffffeb018a00d820
Base ffffeb018a00e000 Limit ffffeb018a008000 Call 0000000000000000
Priority 15 BasePriority 13 PriorityDecrement 32 IoPriority 2 PagePriority 5
Child-SP          RetAddr               : Args to Child                                                           : Call Site
ffffeb01`8a00cc68 fffff803`07142d72     : 00000000`00000003 00000000`00000003 ffffeb01`8a00cdd0 fffff803`0700d380 : nt!DbgBreakPointWithStatus
ffffeb01`8a00cc70 fffff803`071424f7     : 00000000`00000003 ffffeb01`8a00cdd0 fffff803`07079660 00000000`00000139 : nt!KiBugCheckDebugBreak+0x12
ffffeb01`8a00ccd0 fffff803`07065837     : 00000000`00000000 00000000`00000000 ffff8a86`82557080 00000000`00000000 : nt!KeBugCheck2+0x957
ffffeb01`8a00d3f0 fffff803`07076e69     : 00000000`00000139 00000000`00000003 ffffeb01`8a00d750 ffffeb01`8a00d6a8 : nt!KeBugCheckEx+0x107
ffffeb01`8a00d430 fffff803`07077210     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000003 : nt!KiBugCheckDispatch+0x69
ffffeb01`8a00d570 fffff803`07075608     : 00000000`00000002 fffff803`070288d5 ffff8a86`82b66800 ffff8a86`824d81c0 : nt!KiFastFailDispatch+0xd0
ffffeb01`8a00d750 fffff803`070811e5     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : nt!KiRaiseSecurityCheckFailure+0x308 (TrapFrame @ ffffeb01`8a00d750)
ffffeb01`8a00d8e0 fffff803`06f8c23e     : ffff8a86`82557000 00000000`00000000 ffffb201`00000000 00000000`00000000 : nt!KiDeliverApc+0xf31c5
ffffeb01`8a00d9a0 fffff803`06f8bba9     : 00000000`00000000 00000000`00000000 ffff8a86`82557180 00000000`00000000 : nt!KiSwapThread+0x49e
ffffeb01`8a00da60 fffff803`06f8a930     : 00000000`00000000 00000000`00000000 00000000`00000000 ffffeb01`8a00db71 : nt!KiCommitThreadWait+0x549
ffffeb01`8a00db00 fffff803`0703dfa2     : fffff803`072c3660 00000000`00000000 00000000`00000000 00000000`00000000 : nt!KeWaitForSingleObject+0x520
ffffeb01`8a00dbd0 fffff803`06eefa45     : ffff8a86`82557080 fffff803`0703df80 00000000`00000000 00000000`00000000 : nt!PopIrpWorkerControl+0x22
ffffeb01`8a00dc10 fffff803`0706cb8c     : ffffb201`982e6180 ffff8a86`82557080 fffff803`06eef9f0 00000000`00000000 : nt!PspSystemThreadStartup+0x55
ffffeb01`8a00dc60 00000000`00000000     : ffffeb01`8a00e000 ffffeb01`8a008000 00000000`00000000 00000000`00000000 : nt!KiStartSystemThread+0x1c

出问题的线程APC信息
1: kd> dx -id 0,0,ffff8a8682491040 -r1 (*((ntkrnlmp!_LIST_ENTRY *)0xffff8a8682e3d598))
(*((ntkrnlmp!_LIST_ENTRY *)0xffff8a8682e3d598))                 [Type: _LIST_ENTRY]
    [+0x000] Flink            : 0xfffff80340746820 [Type: _LIST_ENTRY *]
    [+0x008] Blink            : 0xfffff80340746820 [Type: _LIST_ENTRY *]
//---






//+++
0: kd> k
 # Child-SP          RetAddr               Call Site
00 fffff806`28871d08 fffff806`26695d72     nt!DbgBreakPointWithStatus
01 fffff806`28871d10 fffff806`266954f7     nt!KiBugCheckDebugBreak+0x12
02 fffff806`28871d70 fffff806`265b8837     nt!KeBugCheck2+0x957
03 fffff806`28872490 fffff806`2669307e     nt!KeBugCheckEx+0x107
04 fffff806`288724d0 fffff806`265c121f     nt!KiFatalExceptionHandler+0x22
05 fffff806`28872510 fffff806`2651a240     nt!RtlpExecuteHandlerForException+0xf
06 fffff806`28872540 fffff806`26427ac4     nt!RtlDispatchException+0x430
DBGHELP: {c:\symbols}*http://msdl.microsoft.com/download/symbols/ is not a valid store
07 fffff806`28872c90 fffff802`e1702ae7     nt!KiDispatchException+0x144
08 fffff806`28873340 fffff806`265c9f42     win10Rs5PatchGuard!DetourKiDispatchException+0x137 [C:\Users\asdf\source\repos\win10Rs5PatchGuard\win10Rs5PatchGuard\pg.cpp @ 189] 
09 fffff806`288733b0 fffff806`265c5e05     nt!KiExceptionDispatch+0xc2
0a fffff806`28873590 fffff806`2666aa28     nt!KiGeneralProtectionFault+0x305
0b fffff806`28873720 fffff806`265a07d9     nt!PopThermalZoneDpc+0xdb2a8
0c fffff806`288738e0 fffff806`2647e577     nt!KiSwInterruptDispatch+0xfa9 另一个执行DPC的地方
0d fffff806`28873910 fffff806`2647dbbe     nt!KiExecuteAllDpcs+0x2e7
0e fffff806`28873a50 fffff806`265bc14a     nt!KiRetireDpcList+0x1ae
0f fffff806`28873c60 00000000`00000000     nt!KiIdleLoop+0x5a

.text:FFFFF8030704D7A9 loc_FFFFF8030704D7A9:                   ; CODE XREF: KiSwInterruptDispatch+56↑j
.text:FFFFF8030704D7A9                 mov     rax, rdi
.text:FFFFF8030704D7AC                 xor     rdi, rdx
.text:FFFFF8030704D7AF                 and     eax, 1000h
.text:FFFFF8030704D7B4                 test    rax, rax
.text:FFFFF8030704D7B7                 cmovz   rdi, rdx
.text:FFFFF8030704D7BB                 mov     rbx, [rdi+18h]
.text:FFFFF8030704D7BF                 mov     rcx, rbx
.text:FFFFF8030704D7C2                 call    _guard_check_icall
.text:FFFFF8030704D7C7                 mov     rdx, [rdi+20h]
.text:FFFFF8030704D7CB                 mov     rax, rbx
.text:FFFFF8030704D7CE                 mov     r9, rsi
.text:FFFFF8030704D7D1                 mov     r8, rbp
.text:FFFFF8030704D7D4                 mov     rcx, rdi
.text:FFFFF8030704D7D7                 call    rax ;执行PopThermalZoneDpc 触发验证   改nop nop 或者替换[rdi+18]函数指针
.text:FFFFF8030704D7D9                 nop     dword ptr [rax]
.text:FFFFF8030704D7DC                 mov     rbx, [rsp+28h+arg_0]
.text:FFFFF8030704D7E1                 mov     rbp, [rsp+28h+arg_8]
.text:FFFFF8030704D7E6                 mov     rsi, [rsp+28h+arg_10]
.text:FFFFF8030704D7EB                 add     rsp, 20h
.text:FFFFF8030704D7EF                 pop     rdi
.text:FFFFF8030704D7F0                 retn


KiSwInterruptDispatch明文解密，直接解密替换函数指针为dummp DPC
下断KiSwInterruptDispatch，发现正常使用断不下来，那么只有PG会执行这里，与系统正常运行无关
我又试了一下的直接把call rax 这句指令nop了，没替换DPC，测试了，也可以
//---


//+++
现在又来个快照，暂时找不到PG哪里触发了。
下断内存分配
  0 e Disable Clear  fffff807`080bb160     0001 (0001) nt!MmAllocateIndependentPages
     1 e Disable Clear  fffff807`0819ff90     0001 (0001) nt!MmAllocatePagesForMdlEx
     ExAllocatePoolWithTag
    都找不到pg的位置了。

    然后运气好的来了，这次PatchGuard上下文与上个快照分配的地方相同，然后直接在CmpAppendDllSection下硬件断点，成功断下！
    拿到看堆栈
    0: kd> k 这里堆栈太模糊，不清楚具体从哪里调用的
 # Child-SP          RetAddr               Call Site
00 fffff807`0a4738c8 ffffcf0c`4c9022fe     0xffffcf0c`4c9130f8 CmpAppendDllSection
01 fffff807`0a4738d0 00000000`20000080     0xffffcf0c`4c9022fe KiTimerDispatch 最后call rax这里 堆栈在调用前被清除了一部分
02 fffff807`0a4738d8 fffff807`080d3b07     0x20000080
03 fffff807`0a4738e0 9b1a1822`b182720d     nt!EtwTraceTimedEvent+0xe3
04 fffff807`0a473960 ffffcf0c`4c9021a7     0x9b1a1822`b182720d
05 fffff807`0a473968 00400a02`00000f44     0xffffcf0c`4c9021a7 KiTimerDispatch入口
06 fffff807`0a473970 fffff807`00000003     0x00400a02`00000f44
07 fffff807`0a473978 fffff807`081997e3     0xfffff807`00000003
08 fffff807`0a473980 fffff807`08124bbe     nt!KiTimer2Expiration+0x323 ->call xxx ->nop nop
09 fffff807`0a473a50 fffff807`0826314a     nt!KiRetireDpcList+0x1ae
0a fffff807`0a473c60 00000000`00000000     nt!KiIdleLoop+0x5a
补充版：
0: kd> dps rsp l100
fffff807`0a4738c8  ffffcf0c`4c9022fe
fffff807`0a4738d0  00000000`20000080
fffff807`0a4738d8  fffff807`080d3b07 nt!EtwTraceTimedEvent+0xe3
fffff807`0a4738e0  fffff807`0a473b10
fffff807`0a4738e8  ffffcf0c`4cfa9000
fffff807`0a4738f0  070c0906`08050300
fffff807`0a4738f8  020b0f01`040e0a0d
fffff807`0a473900  00000000`00000246
fffff807`0a473908  fffff807`08125577 nt!KiExecuteAllDpcs+0x2e7
fffff807`0a473910  5d66eb33`1d70cb10
fffff807`0a473918  fffff807`073bbf80
fffff807`0a473920  ffffcf0c`4d5022ed
fffff807`0a473928  fffff807`073b9180
fffff807`0a473930  ffffacc3`3a701003
fffff807`0a473938  00000000`00000000
fffff807`0a473940  fffff807`0a473b10
fffff807`0a473948  00000000`b4a47b29
fffff807`0a473950  00000000`01d7926d
fffff807`0a473958  9b1a1822`b182720d
fffff807`0a473960  ffffcf0c`4c9021a7
fffff807`0a473968  00400a02`00000f44
fffff807`0a473970  fffff807`00000003
fffff807`0a473978  fffff807`081997e3 nt!KiTimer2Expiration+0x323
其实我看过PatchGuard资料，知道有不用异常的DPC触发验证，这里终于见到了
因为KiTimerDispatch在INITDBG段，没解密上下文也找不到。
但是KiTimer2Expiration在text段
KiTimer2Expiration和KiTimerExpiration？？亲兄弟？
然后问题也很简单，只要windbg能识别出来的call site，那一定是没有把函数拷贝到PG上下文自己调用的

这是打在KiTimerDispatch开头时候的堆栈
// # Child-SP          RetAddr               Call Site
00 fffff807`0a473908 fffff807`08125577     0xffffcf0c`4c9021a7;KiTimerDispatch
01 fffff807`0a473910 fffff807`08124bbe     nt!KiExecuteAllDpcs+0x2e7
02 fffff807`0a473a50 fffff807`0826314a     nt!KiRetireDpcList+0x1ae
03 fffff807`0a473c60 00000000`00000000     nt!KiIdleLoop+0x5a

hook KiExecuteAllDpcs 替换函数指针即可

KiTimerDispatch:
                                          mov     byte ptr [r10], 2Eh ; '.'
INITKDBG:FFFFF803071FBCA6                 mov     byte ptr [r10+1], 48h ; 'H'
INITKDBG:FFFFF803071FBCAB                 mov     byte ptr [r10+2], 31h ; '1'
INITKDBG:FFFFF803071FBCB0                 mov     byte ptr [r10+3], 11h
INITKDBG:FFFFF803071FBCB5                 call    rax ; CmpAppendDllSection
//---