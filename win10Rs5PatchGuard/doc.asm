INIT:00000001409AAA10             CmpAppendDllSection proc near           ; DATA XREF: .pdata:000000014053B9F8↑o
INIT:00000001409AAA10                                                     ; sub_14098FE9C+2B97↑o
INIT:00000001409AAA10                             db      2Eh
INIT:00000001409AAA10 2E 48 31 11                 xor     [rcx], rdx ;这个2E 48 31 11是PG的上下文开始运行会写入的，
																	 ;开头的0xc8字节是双重加密，两次解密后才是IDA看的这样。
																	 ;这一句运行完异或解密下一条指令
INIT:00000001409AAA14 48 31 51 08                 xor     [rcx+8], rdx	;异或解密下两条指令
INIT:00000001409AAA18 48 31 51 10                 xor     [rcx+10h], rdx
INIT:00000001409AAA1C 48 31 51 18                 xor     [rcx+18h], rdx
INIT:00000001409AAA20 48 31 51 20                 xor     [rcx+20h], rdx
INIT:00000001409AAA24 48 31 51 28                 xor     [rcx+28h], rdx
INIT:00000001409AAA28 48 31 51 30                 xor     [rcx+30h], rdx
INIT:00000001409AAA2C 48 31 51 38                 xor     [rcx+38h], rdx
INIT:00000001409AAA30 48 31 51 40                 xor     [rcx+40h], rdx
INIT:00000001409AAA34 48 31 51 48                 xor     [rcx+48h], rdx
INIT:00000001409AAA38 48 31 51 50                 xor     [rcx+50h], rdx
INIT:00000001409AAA3C 48 31 51 58                 xor     [rcx+58h], rdx
INIT:00000001409AAA40 48 31 51 60                 xor     [rcx+60h], rdx
INIT:00000001409AAA44 48 31 51 68                 xor     [rcx+68h], rdx
INIT:00000001409AAA48 48 31 51 70                 xor     [rcx+70h], rdx
INIT:00000001409AAA4C 48 31 51 78                 xor     [rcx+78h], rdx
INIT:00000001409AAA50 48 83 C1 78                 add     rcx, 78h
INIT:00000001409AAA54 48 31 51 08                 xor     [rcx+8], rdx
INIT:00000001409AAA58 48 31 51 10                 xor     [rcx+10h], rdx
INIT:00000001409AAA5C 48 31 51 18                 xor     [rcx+18h], rdx
INIT:00000001409AAA60 48 31 51 20                 xor     [rcx+20h], rdx
INIT:00000001409AAA64 48 31 51 28                 xor     [rcx+28h], rdx
INIT:00000001409AAA68 48 31 51 30                 xor     [rcx+30h], rdx
INIT:00000001409AAA6C 48 31 51 38                 xor     [rcx+38h], rdx
INIT:00000001409AAA70 48 31 51 40                 xor     [rcx+40h], rdx
INIT:00000001409AAA74 48 31 51 48                 xor     [rcx+48h], rdx
INIT:00000001409AAA78 48 83 E9 78                 sub     rcx, 78h
INIT:00000001409AAA7C 31 11                       xor     [rcx], edx
INIT:00000001409AAA7E 48 8B C2                    mov     rax, rdx
INIT:00000001409AAA81 48 8B D1                    mov     rdx, rcx ;rdx->CmpAppendDllSection
INIT:00000001409AAA84 8B 8A C4 00+                mov     ecx, [rdx+0C4h]  ;
INIT:00000001409AAA8A 48 85 C0                    test    rax, rax
INIT:00000001409AAA8D 74 11                       jz      short loc_1409AAAA0
INIT:00000001409AAA8F
INIT:00000001409AAA8F             loc_1409AAA8F:                          ; CODE XREF: CmpAppendDllSection+8E↓j
INIT:00000001409AAA8F 48 31 84 CA+                xor     [rdx+rcx*8+0C0h], rax ;rax->key 从高地址到低地址解密
INIT:00000001409AAA97 48 D3 C8                    ror     rax, cl
INIT:00000001409AAA9A 48 0F BB C0                 btc     rax, rax ; win10相比win7多了这条指令
INIT:00000001409AAA9E E2 EF                       loop    loc_1409AAA8F ;cx为0就继续下面的指令，也就是说解密从rdx+C8 - 末尾
;												  上面4行代码对应的算法在梦无极的pdf-P10有记载，但是他提供的是没有btc指令的版本
INIT:00000001409AAAA0
INIT:00000001409AAAA0             loc_1409AAAA0:                          ; CODE XREF: CmpAppendDllSection+7D↑j
INIT:00000001409AAAA0 8B 82 D0 07+                mov     eax, [rdx+7D0h]
INIT:00000001409AAAA6 48 03 C2                    add     rax, rdx
INIT:00000001409AAAA9 48 83 EC 28                 sub     rsp, 28h
INIT:00000001409AAAAD FF D0                       call    rax
INIT:00000001409AAAAF 48 83 C4 28                 add     rsp, 28h
INIT:00000001409AAAB3 4C 8B 80 08+                mov     r8, [rax+108h]
INIT:00000001409AAABA 48 8D 88 80+                lea     rcx, [rax+780h]
INIT:00000001409AAAC1 BA 01 00 00+                mov     edx, 1
INIT:00000001409AAAC6 41 FF E0                    jmp     r8
INIT:00000001409AAAC9 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90                    db 0Fh dup(90h)












.text:00000001400018E0  __int64  IopTimerDispatch(_KDPC *a1, __int64 DeferredContext, __int64 a3, unsigned __int64 a4);
																
.text:0000000140001936                 mov     rax, rbx ;rbx为DeferredContext
.text:0000000140001939                 sar     rax, 47 ;这里是判断DefferedContext是否合法
.text:000000014000193D                 inc     rax
.text:0000000140001940                 xor     edi, edi
.text:0000000140001942                 cmp     rax, 1
.text:0000000140001946                 jbe     loc_1401D100A ;这里会跳到这个函数正常的流程
.text:000000014000194C                 mov     [rsp+1E8h+var_1B0], edi
.text:0000000140001950                 mov     byte ptr [rcx+_KDPC.Type], dil
.text:0000000140001953                 mov     rax, r9
.text:0000000140001956                 shr     rax, 8
.text:000000014000195A                 mov     [rcx+_KDPC.DeferredContext], rax
.text:000000014000195E                 mov     [r11-66h], r8
.text:0000000140001962                 mov     ecx, r8d
.text:0000000140001965                 mov     rax, rbx
.text:0000000140001968                 rol     rax, cl
.text:000000014000196B                 mov     [r11-0AEh], rax
.text:0000000140001972                 mov     rax, rdx
.text:0000000140001975                 ror     rax, cl
.text:0000000140001978                 mov     [r11-76h], rax
.text:000000014000197C                 xor     [rdx+28h], r9
.text:0000000140001980                 xor     [rdx+30h], r8	
.text:0000000140001984 loc_140001984:                          ; DATA XREF: .rdata:0000000140388FC0↓o
.text:0000000140001984                                         ; .rdata:0000000140388FD0↓o ...
.text:0000000140001984 ;     __try { // __finally(IopTimerDispatch$fin$1)
.text:0000000140001984 ;       __try { // __finally(IopTimerDispatch$fin$0)
.text:0000000140001984 ;   __try { // __except at loc_140001993
.text:0000000140001984                 mov     rcx, rbx
.text:0000000140001987                 call    KiCustomAccessRoutine1
.text:000000014000198C                 nop
.text:000000014000198C ;       } // starts at 140001984

.text:0000000140001993 loc_140001993:                          ; DATA XREF: .rdata:0000000140388FE0↓o
.text:0000000140001993 ;   __except(IopTimerDispatch$filt$2) // owned by 140001984
.text:0000000140001993                 xor     edi, edi
.text:0000000140001995                 mov     esi, [rsp+1E8h+var_164]
.text:000000014000199C                 mov     rbx, [rsp+1E8h+var_E0]
.text:00000001400019A4                  jmp     loc_1401D100A

.text:00000001401BD500 KiCustomAccessRoutine1 proc near ;初始化计数器准备触发异常
									   ....
									   and ecx,3
									   inc ecx
									   call    KiCustomRecurseRoutine1
									   ....
.text:00000001401BD527 KiCustomAccessRoutine1 endp

.text:00000001401BD4E0 KiCustomRecurseRoutine1 proc near       ; CODE XREF: KiCustomAccessRoutine1+1D↓p
.text:00000001401BD4E0                                         ; KiCustomRecurseRoutine0+8↓p
.text:00000001401BD4E0                                         ; DATA XREF: ...
.text:00000001401BD4E0                 sub     rsp, 28h
.text:00000001401BD4E4                 dec     ecx
.text:00000001401BD4E6                 jz      short loc_1401BD4ED
.text:00000001401BD4E8                 call    KiCustomRecurseRoutine2
.text:00000001401BD4ED
.text:00000001401BD4ED loc_1401BD4ED:                          ; CODE XREF: KiCustomRecurseRoutine1+6↑j
.text:00000001401BD4ED                 mov     eax, [rdx] ;ecx为0的时候解引用DeferredContext触发异常
.text:00000001401BD4EF                 add     rsp, 28h
.text:00000001401BD4F3                 retn
.text:00000001401BD4F3 KiCustomRecurseRoutine1 endp



.text:00000001401CA56E                               IopTimerDispatch$filt$2:                ; DATA XREF: .rdata:0000000140388FE0↓o
.text:00000001401CA56E                                                                       ; .pdata:00000001404F9FD4↓o ...
.text:00000001401CA56E                               ;   __except filter // owned by 140001984

.text:00000001401CA598 loc_1401CA598:;应该是第一层解密CmpAppendDllSection,然后调用它                         ; CODE XREF: IopTimerDispatch+1C8E5D↓j
.text:00000001401CA598                 mov     eax, [rbp+34h]
.text:00000001401CA59B                 cmp     eax, 19h
.text:00000001401CA59E                 jnb     loc_1401CA742
.text:00000001401CA5A4                 mov     rax, [rbp+40h]
.text:00000001401CA5A8                 mov     rcx, [rax]
.text:00000001401CA5AB                 mov     [rbp+90h], rcx
.text:00000001401CA5B2                 mov     rax, [rbp+48h]
.text:00000001401CA5B6                 mov     [rbp+0E8h], rax
.text:00000001401CA5BD                 mov     rax, [rbp+40h]
.text:00000001401CA5C1                 mov     rcx, [rax]
.text:00000001401CA5C4                 mov     [rbp+0E0h], rcx
.text:00000001401CA5CB                 mov     rax, [rbp+0E0h]
.text:00000001401CA5D2                 mov     [rbp+70h], rax
.text:00000001401CA5D6                 mov     rdx, [rbp+70h]
.text:00000001401CA5DA                 mov     rax, cs:KiWaitNever
.text:00000001401CA5E1                 xor     rdx, rax
.text:00000001401CA5E4                 mov     ecx, eax
.text:00000001401CA5E6                 rol     rdx, cl
.text:00000001401CA5E9                 mov     [rbp+70h], rdx
.text:00000001401CA5ED                 mov     rcx, [rbp+70h]
.text:00000001401CA5F1                 mov     rax, [rbp+0E8h]
.text:00000001401CA5F8                 xor     rcx, rax
.text:00000001401CA5FB                 bswap   rcx
.text:00000001401CA5FE                 xor     rcx, cs:KiWaitAlways
.text:00000001401CA605                 mov     [rbp+70h], rcx
.text:00000001401CA609                 mov     rcx, [rbp+40h]
.text:00000001401CA60D                 mov     rax, [rbp+70h]
.text:00000001401CA611                 mov     [rcx], rax
.text:00000001401CA614                 mov     eax, [rbp+34h]
.text:00000001401CA617                 mov     rdx, [rbp+50h]
.text:00000001401CA61B                 imul    rdx, rax
.text:00000001401CA61F                 mov     rax, [rbp+40h]
.text:00000001401CA623                 add     rdx, [rax]
.text:00000001401CA626                 mov     rax, [rbp+40h]
.text:00000001401CA62A                 mov     [rax], rdx
.text:00000001401CA62D                 mov     r9, [rbp+90h]
.text:00000001401CA634                 not     r9d
.text:00000001401CA637                 and     r9d, 3Fh
.text:00000001401CA63B                 mov     eax, [rbp+34h]
.text:00000001401CA63E                 mov     edx, 0C8h
.text:00000001401CA643                 sub     edx, eax
.text:00000001401CA645                 mov     r8d, [rbp+34h]
.text:00000001401CA649                 imul    r8d, edx
.text:00000001401CA64D                 mov     ecx, 40h
.text:00000001401CA652                 sub     ecx, r9d
.text:00000001401CA655                 shl     r8, cl
.text:00000001401CA658                 mov     eax, [rbp+34h]
.text:00000001401CA65B                 mov     edx, 0C8h
.text:00000001401CA660                 sub     edx, eax
.text:00000001401CA662                 mov     eax, [rbp+34h]
.text:00000001401CA665                 imul    edx, eax
.text:00000001401CA668                 mov     ecx, r9d
.text:00000001401CA66B                 shr     rdx, cl
.text:00000001401CA66E                 or      rdx, r8
.text:00000001401CA671                 mov     rax, [rbp+48h]
.text:00000001401CA675                 xor     rax, rdx
.text:00000001401CA678                 mov     [rbp+48h], rax
.text:00000001401CA67C                 mov     r8, [rbp+90h]
.text:00000001401CA683                 and     r8d, 3Fh
.text:00000001401CA687                 mov     ecx, 40h
.text:00000001401CA68C                 sub     ecx, r8d
.text:00000001401CA68F                 mov     rdx, [rbp+48h]
.text:00000001401CA693                 shr     rdx, cl
.text:00000001401CA696                 mov     rax, [rbp+48h]
.text:00000001401CA69A                 mov     ecx, r8d
.text:00000001401CA69D                 shl     rax, cl
.text:00000001401CA6A0                 or      rax, rdx
.text:00000001401CA6A3                 mov     [rbp+48h], rax
.text:00000001401CA6A7                 mov     rcx, [rbp+50h]
.text:00000001401CA6AB                 mov     rax, [rbp+48h]
.text:00000001401CA6AF                 add     rcx, rax
.text:00000001401CA6B2                 mov     [rbp+48h], rcx
.text:00000001401CA6B6                 mov     dword ptr [rbp+6Ch], 0
.text:00000001401CA6BD
.text:00000001401CA6BD loc_1401CA6BD:                          ; CODE XREF: IopTimerDispatch+1C8E4B↓j
.text:00000001401CA6BD                 mov     eax, [rbp+6Ch]
.text:00000001401CA6C0                 cmp     eax, 10h
.text:00000001401CA6C3                 mov     rax, [rbp+40h]
.text:00000001401CA6C7                 jnb     short loc_1401CA72D
.text:00000001401CA6C9                 mov     cl, [rax]
.text:00000001401CA6CB                 and     cl, 0Fh
.text:00000001401CA6CE                 mov     [rbp+30h], cl
.text:00000001401CA6D1                 movzx   eax, byte ptr [rbp+30h]
.text:00000001401CA6D5                 mov     al, [rbp+rax+58h]
.text:00000001401CA6D9                 mov     [rbp+30h], al
.text:00000001401CA6DC                 mov     rax, [rbp+40h]
.text:00000001401CA6E0                 mov     rcx, [rax]
.text:00000001401CA6E3                 and     rcx, 0FFFFFFFFFFFFFFF0h
.text:00000001401CA6E7                 mov     rax, [rbp+40h]
.text:00000001401CA6EB                 mov     [rax], rcx
.text:00000001401CA6EE                 movzx   ecx, byte ptr [rbp+30h]
.text:00000001401CA6F2                 mov     rax, [rbp+40h]
.text:00000001401CA6F6                 mov     rdx, [rax]
.text:00000001401CA6F9                 or      rdx, rcx
.text:00000001401CA6FC                 mov     rax, [rbp+40h]
.text:00000001401CA700                 mov     [rax], rdx

.text:00000001401CA78B 48 B9 DB 27 2A BC 17 A2 15 6A                 mov     rcx, 6A15A217BC2A27DBh
.text:00000001401CA795 48 33 C1                                      xor     rax, rcx
.text:00000001401CA798 48 89 45 48                                   mov     [rbp+48h], rax
.text:00000001401CA79C 48 8B 45 50                                   mov     rax, [rbp+50h];可以看出此时[rbp+50]为CmpAppendDllSection
.text:00000001401CA7A0 48 89 45 78                                   mov     [rbp+78h], rax
.text:00000001401CA7A4 48 8B 45 78                                   mov     rax, [rbp+78h]
.text:00000001401CA7A8 C6 00 2E                                      mov     byte ptr [rax], 2Eh
.text:00000001401CA7AB 48 8B 45 78                                   mov     rax, [rbp+78h]
.text:00000001401CA7AF C6 40 01 48                                   mov     byte ptr [rax+1], 48h
.text:00000001401CA7B3 48 8B 45 78                                   mov     rax, [rbp+78h]
.text:00000001401CA7B7 C6 40 02 31                                   mov     byte ptr [rax+2], 31h
.text:00000001401CA7BB 48 8B 45 78                                   mov     rax, [rbp+78h]
.text:00000001401CA7BF C6 40 03 11                                   mov     byte ptr [rax+3], 11h

.text:00000001401CA7C7 45 33 C9                                      xor     r9d, r9d
.text:00000001401CA7CA 45 33 C0                                      xor     r8d, r8d
.text:00000001401CA7CD 48 8B 55 48                                   mov     rdx, [rbp+48h]
.text:00000001401CA7D1 48 8B 4D 50                                   mov     rcx, [rbp+50h]
.text:00000001401CA7D5 E8 36 17 FF FF                                call    _guard_dispatch_icall;这里涉及到cfg保护










;由于PgInit函数太长，这里分段记录(开始)
									PgInit proc



									
INIT:0000000140992A33                 lea     rax, CmpAppendDllSection
INIT:0000000140992A3A                 movups  xmm0, xmmword ptr [rax]
INIT:0000000140992A3D                 movups  xmmword ptr [r14], xmm0
INIT:0000000140992A41                 movups  xmm1, xmmword ptr [rax+10h]
INIT:0000000140992A45                 movups  xmmword ptr [r14+10h], xmm1
INIT:0000000140992A4A                 movups  xmm0, xmmword ptr [rax+20h]
INIT:0000000140992A4E                 movups  xmmword ptr [r14+20h], xmm0
INIT:0000000140992A53                 movups  xmm1, xmmword ptr [rax+30h]
INIT:0000000140992A57                 movups  xmmword ptr [r14+30h], xmm1
INIT:0000000140992A5C                 movups  xmm0, xmmword ptr [rax+40h]
INIT:0000000140992A60                 movups  xmmword ptr [r14+40h], xmm0
INIT:0000000140992A65                 movups  xmm1, xmmword ptr [rax+50h]
INIT:0000000140992A69                 movups  xmmword ptr [r14+50h], xmm1
INIT:0000000140992A6E                 movups  xmm0, xmmword ptr [rax+60h]
INIT:0000000140992A72                 movups  xmmword ptr [r14+60h], xmm0
INIT:0000000140992A77                 movups  xmm0, xmmword ptr [rax+70h]
								
									  ;根据参数一选择合适的DPC例程
									  ;
INIT:00000001409A5E7D loc_1409A5E7D:                          ; CODE XREF: PgInit+15FA1↑j
INIT:00000001409A5E7D                 mov     eax, [rsp+23E8h+arg_0]
INIT:00000001409A5E84
INIT:00000001409A5E84 loc_1409A5E84:                          ; CODE XREF: PgInit+166B0↓j
INIT:00000001409A5E84                 mov     ecx, 5
INIT:00000001409A5E89                 cmp     eax, ecx
INIT:00000001409A5E8B                 jbe     loc_1409A68F0 ;ExpTimerDpcRoutine
INIT:00000001409A5E91                 lea     r12, KiTimerDispatch
INIT:00000001409A5E98                 cmp     eax, 6
INIT:00000001409A5E9B                 jz      loc_1409A68E7 ;IopTimerDispatch
INIT:00000001409A5EA1                 cmp     eax, 7
INIT:00000001409A5EA4                 jz      loc_1409A68D4 ;CmpLazyFlushDpcRoutine
INIT:00000001409A5EAA                 cmp     eax, 8
INIT:00000001409A5EAD                 jz      loc_1409A68CB ;ExpTimeRefreshDpcRoutine
INIT:00000001409A5EB3                 cmp     eax, 9
INIT:00000001409A5EB6                 jz      loc_1409A68C2	;ExpTimeZoneDpcRoutine

INIT:00000001409A68F0 loc_1409A68F0:                          ; CODE XREF: PgInit+15FEF↑j
INIT:00000001409A68F0                 jz      short loc_1409A6932

INIT:00000001409A6932 loc_1409A6932:                          ; CODE XREF: PgInit:loc_1409A68F0↑j
INIT:00000001409A6932                 lea     rcx, ExpTimerDpcRoutine
INIT:00000001409A6939
INIT:00000001409A6939 loc_1409A6939:                          ; CODE XREF: PgInit+16A49↑j
INIT:00000001409A6939                                         ; PgInit+16A70↑j ...
INIT:00000001409A6939                 mov     [rdi+7C0h], rcx
INIT:00000001409A6940                 mov     r13d, 1
INIT:00000001409A6946                 xor     r11d, r11d
INIT:00000001409A6949 loc_1409A6949:                          ; CODE XREF: PgInit+15FDC↑j
INIT:00000001409A6949                 mov     rax, [rdi+940h]
INIT:00000001409A6950                 or      r14d, 0FFFFFFFFh
INIT:00000001409A6954                 mov     rcx, [rax]
INIT:00000001409A6957                 mov     [rdi+948h], rcx
INIT:00000001409A695E                 mov     [rdi+950h], r14d
INIT:00000001409A6965                 mov     [rdi+954h], r11d
INIT:00000001409A696C                 mov     [rdi+958h], r11
INIT:00000001409A6973                 cli
INIT:00000001409A6974                 cmp     byte ptr cs:KdDebuggerNotPresent, r11b


v172 = __rdtsc();
v4244 = (__ROR8__(v172, 3) ^ v172) * 0x7010008004002001ui64 >> 64;
v173 = v170 + v171 + ((67117057 * (__ROR8__(v172, 3) ^ v172) ^ v4244) & 0x7FF) + 0x80000;
v185 = __rdtsc();
v4247 = (__ROR8__(v185, 3) ^ v185) * 0x7010008004002001ui64 >> 64;
v186 = (v4247 ^ 67117057 * (__ROR8__(v185, 3) ^ v185)) & 0x7FF;
v187 = __rdtsc();
v188 = (__ROR8__(v187, 3) ^ v187) * 0x7010008004002001ui64;
v4248 = *(&v188 + 1);
v189 = (*(&v188 + 1) ^ v188) % (v186 + 1);
v190 = ExAllocatePoolWithTag(0, v186 + v173, v179);v179是tag是随机的
;也就是context是用ExAllocatePoolWithTag分配的，CmpAppendDllsection在分配的一个随机偏移处
PgContext = (v190 + v189);

*(PgContext + 499) = v209;
  *(PgContext + 639) = v210;
  PgContext[246] = v4253;
  *(PgContext + 577) = v3959;
  v322 = (PgContext + 16);
  *PgContext = *CmpAppendDllSection;
  *(PgContext + 1) = *(CmpAppendDllSection + 1);
  *(PgContext + 2) = *(CmpAppendDllSection + 2);
  *(PgContext + 3) = *(CmpAppendDllSection + 3);
  *(PgContext + 4) = *(CmpAppendDllSection + 4);
  *(PgContext + 5) = *(CmpAppendDllSection + 5);
  *(PgContext + 6) = *(CmpAppendDllSection + 6);
  *(v322 - 16) = *(CmpAppendDllSection + 7);
  *v322 = *(CmpAppendDllSection + 8);
  *(v322 + 16) = *(CmpAppendDllSection + 9);
  *(v322 + 32) = *(CmpAppendDllSection + 10);
  *(v322 + 48) = *(CmpAppendDllSection + 11);
  *(v322 + 64) = *(CmpAppendDllSection + 48);
  LODWORD(v322) = v3968;
  *(PgContext + 502) = v3968 + FsXXSmallMcb_offset_initkdbg;
  *(PgContext + 500) = v322 + v3951;
  *(PgContext + 501) = v322 + v3952;
  *(PgContext + 503) = v322 + v3958;

  PgContext[28] = ExAcquireResourceSharedLite;
  PgContext[29] = ExAcquireResourceExclusiveLite;
  PgContext[30] = ExAllocatePoolWithTag; 
  PgContext[31] = ExFreePool;
  PgContext[32] = ExMapHandleToPointer;
  PgContext[33] = ExQueueWorkItem;
  PgContext[34] = ExReleaseResourceLite;
  PgContext[35] = ExUnlockHandleTableEntry;
  PgContext[36] = ExAcquirePushLockExclusiveEx;
  PgContext[37] = ExReleasePushLockExclusiveEx;
  PgContext[38] = ExAcquirePushLockSharedEx;
  PgContext[39] = ExReleasePushLockSharedEx;
  PgContext[40] = KeAcquireInStackQueuedSpinLockAtDpcLevel;
  PgContext[41] = ExAcquireSpinLockSharedAtDpcLevel;
  PgContext[42] = KeBugCheckEx;
  PgContext[43] = KeDelayExecutionThread;
  PgContext[44] = KeEnterCriticalRegionThread;
  PgContext[45] = KeLeaveCriticalRegion;
  PgContext[46] = KeEnterGuardedRegion;
  PgContext[47] = KeLeaveGuardedRegion;
  PgContext[48] = KeReleaseInStackQueuedSpinLockFromDpcLevel;
  PgContext[49] = ExReleaseSpinLockSharedFromDpcLevel;
  PgContext[50] = KeRevertToUserGroupAffinityThread;
  PgContext[51] = KeProcessorGroupAffinity;
  PgContext[52] = KeInitializeEnumerationContext;
  PgContext[53] = KeEnumerateNextProcessor;
  PgContext[54] = KeCountSetBitsAffinityEx;
  PgContext[55] = KeQueryAffinityProcess;
  PgContext[56] = KeQueryAffinityThread;
  PgContext[57] = KeSetSystemGroupAffinityThread;
  PgContext[58] = KeSetCoalescableTimer;
  PgContext[62] = RtlImageNtHeader;
  PgContext[65] = RtlSectionTableFromVirtualAddress;
  PgContext[63] = RtlLookupFunctionTable;
  PgContext[64] = RtlPcToFileHeader;
  PgContext[59] = ObfDereferenceObject;
  PgContext[60] = ObReferenceObjectByName;
  PgContext[61] = RtlImageDirectoryEntryToData;
  PgContext[66] = DbgPrint;
  PgContext[67] = MmAllocateIndependentPages;
  PgContext[68] = MmFreeIndependentPages;
  PgContext[69] = MmSetPageProtection;
  PgContext[75] = RtlLookupFunctionEntry;
  PgContext[76] = KeAcquireSpinLockRaiseToDpc;
  PgContext[77] = KeReleaseSpinLock;
  PgContext[78] = MmGetSessionById;
  PgContext[79] = MmGetNextSession;
  PgContext[80] = MmQuitNextSession;
  PgContext[81] = MmAttachSession;
  PgContext[82] = MmDetachSession;
  PgContext[83] = MmGetSessionIdEx;
  PgContext[84] = MmIsSessionAddress;
  PgContext[85] = MmIsAddressValid;
  PgContext[86] = MmSessionGetWin32Callouts;
  PgContext[87] = KeInsertQueueApc;
  PgContext[88] = KeWaitForSingleObject;
  PgContext[90] = ExReferenceCallBackBlock;
  PgContext[91] = ExGetCallBackBlockRoutine;
  PgContext[92] = ExDereferenceCallBackBlock;
  PgContext[93] = sub_FFFFF8027124E7D0;
  PgContext[94] = PspEnumerateCallback;
  PgContext[95] = CmpEnumerateCallback;
  PgContext[96] = DbgEnumerateCallback;
  PgContext[97] = ExpEnumerateCallback;
  PgContext[98] = ExpGetNextCallback;
  PgContext[99] = xHalTimerWatchdogStop;
  PgContext[100] = KiSchedulerApcTerminate;
  PgContext[101] = KiSchedulerApc;
  PgContext[102] = xHalTimerWatchdogStop;
  PgContext[103] = sub_FFFFF8027124F800;
  PgContext[104] = MmAllocatePagesForMdlEx;
  PgContext[105] = MmAllocateMappingAddress;
  PgContext[106] = MmMapLockedPagesWithReservedMapping;
  PgContext[107] = MmUnmapReservedMapping;
  PgContext[108] = sub_FFFFF8027125BA50;
  PgContext[109] = sub_FFFFF8027125BAC0;
  PgContext[110] = MmAcquireLoadLock;
  PgContext[111] = MmReleaseLoadLock;
  PgContext[112] = KeEnumerateQueueApc;
  PgContext[113] = KeIsApcRunningThread;
  PgContext[114] = sub_FFFFF8027124F6E0;
  PgContext[115] = PsAcquireProcessExitSynchronization;
  PgContext[116] = ObDereferenceProcessHandleTable;
  PgContext[117] = PsGetNextProcess;
  PgContext[118] = PsQuitNextProcessThread;
  PgContext[119] = PsGetNextProcessEx;
  PgContext[120] = MmIsSessionLeaderProcess;
  PgContext[121] = PsInvokeWin32Callout;
  PgContext[122] = MmEnumerateAddressSpaceAndReferenceImages;
  PgContext[123] = PsGetProcessProtection;
  PgContext[124] = PsGetProcessSignatureLevel;
  PgContext[125] = PsGetProcessSectionBaseAddress;
  PgContext[126] = SeCompareSigningLevels;
  PgContext[132] = RtlIsMultiSessionSku;
  PgContext[133] = KiEnumerateCallback;
  PgContext[134] = KeStackAttachProcess;
  PgContext[135] = KeUnstackDetachProcess;
  PgContext[136] = KeIpiGenericCall;
  PgContext[137] = sub_FFFFF8027125B8A0;
  PgContext[138] = MmGetPhysicalAddress;
  PgContext[139] = MmUnlockPages;
  PgContext[127] = KeComputeSha256;
  PgContext[128] = KeComputeParallelSha256;
  PgContext[129] = KeSetEvent;
  PgContext[140] = VslVerifyPage;
  PgContext[143] = PsLookupProcessByProcessId;
  PgContext[144] = PsGetProcessId;
  PgContext[145] = MmCheckProcessShadow;
  PgContext[146] = MmGetImageRetpolineCodePage;
  PgContext[296] = &qword_FFFFF802714BA5C0;
  if ( v4866 )
    PgContext[89] = *(v4866 + 8);
  PgContext[130] = RtlpConvertFunctionEntry;
  PgContext[131] = RtlpLookupPrimaryFunctionEntry;
  PgContext[141] = KiGetInterruptObjectAddress;
  PgContext[150] = &qword_FFFFF802714B6DE0;
  PgContext[151] = &qword_FFFFF802714BA5A8;
  PgContext[152] = &qword_FFFFF802714BA5B0;
  PgContext[153] = &qword_FFFFF802714BA5B8;
  PgContext[154] = PsInitialSystemProcess;
  PgContext[155] = KiWaitAlways;
  PgContext[156] = &KiEntropyTimingRoutine;
  PgContext[157] = &KiProcessListHead;
  PgContext[158] = &KiProcessListLock;
  PgContext[159] = ObpTypeObjectType;
  PgContext[160] = IoDriverObjectType;
  PgContext[161] = PsProcessType;
  PgContext[162] = &PsActiveProcessHead;
  PgContext[163] = &PsInvertedFunctionTable;
  PgContext[164] = &PsLoadedModuleList;
  PgContext[165] = &PsLoadedModuleResource;
  PgContext[166] = &PsLoadedModuleSpinLock;
  PgContext[167] = &PspActiveProcessLock;
  PgContext[168] = &PspCidTable;
  PgContext[169] = &ExpUuidLock;
  PgContext[170] = &AlpcpPortListLock;
  PgContext[171] = &KeServiceDescriptorTable;
  PgContext[172] = &KeServiceDescriptorTableShadow;
  PgContext[173] = &KeServiceDescriptorTableFilter;
  PgContext[174] = &VfThunksExtended;
  PgContext[175] = &PsWin32CallBack;
  PgContext[176] = &qword_FFFFF802714BA588;
  PgContext[177] = &KiTableInformation;
  PgContext[178] = &HandleTableListHead;
  PgContext[179] = &HandleTableListLock;
  PgContext[180] = ObpKernelHandleTable;
  PgContext[181] = -9345848836096i64;
  PgContext[182] = KiWaitNever;
  PgContext[183] = &SeProtectedMapping;
  PgContext[185] = &KiStackProtectNotifyEvent;
  PgContext[186] = MmPteBase;
  PgContext[187] = PsNtosImageBase;
  PgContext[188] = PsHalImageBase;
  PgContext[189] = &KeNumberProcessors_0;
  v332 = &_ti_a;
  PgContext[190] = &::Src;
  v333 = 2i64;
  PgContext[191] = &qword_FFFFF802715F7290;
  PgContext[192] = &RtlpInvertedFunctionTable;
  PgContext[184] = KiInterruptThunk;

  v4863 = a1; 根据参数一选择合适的DPC
v3362 = v4863;
  while ( 2 )
  {
    if ( v3362 <= 5 )
    {
      if ( v3362 == 5 )
      {
        TriggerDpcRoutine = ExpTimerDpcRoutine;
      }
      else if ( v3362 )
      {
        v3461 = v3362 - 1;
        if ( v3461 )
        {
          v3462 = v3461 - 1;
          if ( v3462 )
          {
            if ( v3462 == 1 )
              TriggerDpcRoutine = ExpTimeZoneDpcRoutine;
            else
              TriggerDpcRoutine = ExpCenturyDpcRoutine;
          }
          else
          {
            TriggerDpcRoutine = ExpTimeRefreshDpcRoutine;
          }
        }
        else
        {
          TriggerDpcRoutine = CmpLazyFlushDpcRoutine;
        }
      }
      else
      {
        TriggerDpcRoutine = CmpEnableLazyFlushDpcRoutine;
      }
      goto LABEL_4777;
    }
    switch ( v3362 )
    {
      case 6u:
        TriggerDpcRoutine = IopTimerDispatch;
        goto LABEL_4777;
      case 7u:
        TriggerDpcRoutine = IopIrpStackProfilerDpcRoutine;
        goto LABEL_4777;
      case 8u:
        TriggerDpcRoutine = &KiBalanceSetManagerDeferredRoutine;
        goto LABEL_4777;
      case 9u:
        TriggerDpcRoutine = PopThermalZoneDpc;
        goto LABEL_4777;
    }
    *v3445 = 19;
  *(v3445 + 1) = 1;
  *(v3445 + 2) = 0;
  *(v3445 + 24) = TriggerDpcRoutine;
  *(v3445 + 32) = 0i64;
  *(v3445 + 56) = 0i64;
  *(v3445 + 16) = 0i64;
  *(v3303 + 604) |= 0x100u;
LABEL_4777:
  *(v3303 + 248) = TriggerDpcRoutine;
LABEL_4778:
  *(v3303 + 297) = **(v3303 + 296);
  *(v3303 + 596) = -1;
  *(v3303 + 597) = 0;
  *(v3303 + 299) = 0i64;



;有个标志位
    if ( v372 < 1 )
    *(PgContext + 605) |= 0x20000u;
  if ( KeGuardDispatchICall(PgContext[132], v372) )
    *(PgContext + 605) |= 2u;
  if ( HvlIsHypervisorPresent() )
    *(PgContext + 605) |= 0x40000u;
  if ( MiIsRetpolineEnabled() )
    *(PgContext + 605) |= 0x100000u;

    ;再分配一块内存
  v385 = KeGuardDispatchICall(PgContext[30], 512i64);
  PgContext[331] = v385;

   v395 = KeGuardDispatchICall(PgContext[30], 512i64);
    __23 = v395;
    if ( !v395 )
      return 0;
    *v395 = 0i64;


     PgContext[313] = KiDispatchCallout;
    PgContext[314] = xHalTimerWatchdogStop;















									PgInit ENDP
;*****************************PgInit结束









INITKDBG:0000000140349890 SdbpCheckDll    proc near               ; CODE XREF: KiSwInterruptDispatch+E95↑p
INITKDBG:0000000140349890                                         ; sub_14019BA20+BE3B↑p ...
INITKDBG:0000000140349890
INITKDBG:0000000140349890 arg_20          = qword ptr  28h
INITKDBG:0000000140349890 arg_28          = qword ptr  30h
INITKDBG:0000000140349890 arg_30          = qword ptr  38h
INITKDBG:0000000140349890
INITKDBG:0000000140349890                 mov     rsi, [rsp+arg_28]
INITKDBG:0000000140349895                 mov     rdi, [rsp+arg_20]
INITKDBG:000000014034989A                 mov     r10, [rsp+arg_30]
INITKDBG:000000014034989F                 xor     eax, eax
INITKDBG:00000001403498A1
INITKDBG:00000001403498A1 loc_1403498A1:                          ; CODE XREF: SdbpCheckDll+1B↓j
INITKDBG:00000001403498A1                 mov     [r10], rax
INITKDBG:00000001403498A4                 sub     r10, 8
INITKDBG:00000001403498A8                 cmp     r10, rsp ;此时的rsp还是FsRtlMdlReadCompleteDevEx的栈帧
INITKDBG:00000001403498AB                 jnb     short loc_1403498A1;将栈全部清空
INITKDBG:00000001403498AD                 mov     [rsp+arg_20], rdi
INITKDBG:00000001403498B2                 mov     ebx, eax;寄存器也全部清空
INITKDBG:00000001403498B4                 mov     edi, eax
INITKDBG:00000001403498B6                 mov     ebp, eax
INITKDBG:00000001403498B8                 mov     r10, rax
INITKDBG:00000001403498BB                 mov     r11, rax
INITKDBG:00000001403498BE                 mov     r12, rax
INITKDBG:00000001403498C1                 mov     r13, rax
INITKDBG:00000001403498C4                 mov     r14, rax
INITKDBG:00000001403498C7                 mov     r15, rax
INITKDBG:00000001403498CA                 jmp     rsi
INITKDBG:00000001403498CA SdbpCheckDll    endp




BOOLEAN HalpTimerSchedulePeriodicQueries()
{
    v4 = 120000i64;
    return KeSetTimerEx(&HalpTimerPeriodicTimer, (-10000i64 * v4), v4, &HalpTimerDpc); 120s = 2min
}
也就是说HalpTimerDpcRoutine这个DpcRoutine有时候两分钟运行一次，有时候不是
再看HalpTimerXXXXXXXXXXXX的实现
_RAX = KeQueryPrcbAddress(0i64);
    _RCX = 0i64;
    __asm { xchg    rcx, [rax+0E0h]; Dpc }      ///*0x0E0*/      VOID*        AcpiReserved
    if ( _RCX )
      KeInsertQueueDpc(_RCX, v5, HIDWORD(SystemArgument2a));


void __fastcall HalpMcaQueueDpc(char a1, char a2)
{
  char v2; // bl
  __int64 v3; // rax
  struct _KDPC *v4; // rcx

  v2 = a2;
  if ( a1 && McaWmiCallback )
    McaWmiCallback(1496727831i64, 1i64);
  if ( v2 )
  {
    v3 = KeQueryPrcbAddress(0i64);
    v4 = *(v3 + 0x80); HalReserved[7]
    if ( v4 )
    {
      *(v3 + 128) = 0i64;
      KeInsertQueueDpc(v4, MEMORY[0xFFFFF78000000014], (MEMORY[0xFFFFF78000000014] >> 32));
    }
  }
}



pgcontext的内存分配

      if ( v6 )
    {
      v11 = __rdtsc();
      v8 += (((((__ROR8__(v11, 3) ^ v11) * 0x7010008004002001ui64 >> 64) ^ 67117057 * (__ROR8__(v11, 3) ^ v11)) & 1) << 12)
          + 4096;
      v96 = v8 + v3 + 8i64;
      v12 = KeGuardDispatchICall(PgContext[67], v96);MmAllocateIndependentPages
      if ( !v12 )
        goto LABEL_11;
      if ( !KeGuardDispatchICall(PgContext_[69], v12) );MmSetPageProtection
      {
        KeGuardDispatchICall(PgContext_[68], v12);MmFreeIndependentPages
        goto LABEL_11;
      }
      *v12 = v96;
      v13 = (v12 + 1);
    }
    else
    {                           ;ExallocatePoolWithTag
      v13 = KeGuardDispatchICall(PgContext[30], (PgContext[302] & 0x10000000) != 0 ? 0x200 : 0);
    }