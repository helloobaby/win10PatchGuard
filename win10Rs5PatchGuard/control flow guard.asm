顺便研究一下微软的cfg保护

https://docs.microsoft.com/en-us/windows/win32/secbp/control-flow-guard


.text:FFFFF8027126FF10 _guard_dispatch_icall proc near         ; CODE XREF: IopIoRateStartRateControl+DB↑p
.text:FFFFF8027126FF10                                         ; IoStopIoRateControl+21↑p ...
.text:FFFFF8027126FF10
.text:FFFFF8027126FF10 ; FUNCTION CHUNK AT .text:FFFFF8027126FF65 SIZE 0000003D BYTES
.text:FFFFF8027126FF10
.text:FFFFF8027126FF10                 mov     r11, cs:_guard_icall_bitmap
.text:FFFFF8027126FF17                 test    rax, rax ;rax为要执行的函数指针地址，为0自然出问题
.text:FFFFF8027126FF1A                 jge     loc_FFFFF8027126FF9A
.text:FFFFF8027126FF20                 test    r11, r11
.text:FFFFF8027126FF23                 jz      short loc_FFFFF8027126FF41
.text:FFFFF8027126FF25                 mov     r10, rax
.text:FFFFF8027126FF28                 shr     r10, 9
.text:FFFFF8027126FF2C                 mov     r11, [r11+r10*8]
.text:FFFFF8027126FF30                 mov     r10, rax
.text:FFFFF8027126FF33                 shr     r10, 3
.text:FFFFF8027126FF37                 test    al, 0Fh
.text:FFFFF8027126FF39                 jnz     short loc_FFFFF8027126FF83
.text:FFFFF8027126FF3B                 bt      r11, r10
.text:FFFFF8027126FF3F                 jnb     short loc_FFFFF8027126FF9A
.text:FFFFF8027126FF41
.text:FFFFF8027126FF41 loc_FFFFF8027126FF41:                   ; CODE XREF: _guard_dispatch_icall+13↑j
.text:FFFFF8027126FF41                                         ; _guard_dispatch_icall+88↓j
.text:FFFFF8027126FF41                 mov     r11, cs:_retpoline_image_bitmap
.text:FFFFF8027126FF48                 mov     r10, rax
.text:FFFFF8027126FF4B                 test    r11, r11
.text:FFFFF8027126FF4E                 jz      short loc_FFFFF8027126FF7E;直接jmp到要执行的函数指针
.text:FFFFF8027126FF50                 shr     r10, 10h
.text:FFFFF8027126FF54                 bt      [r11], r10
.text:FFFFF8027126FF58                 jnb     short loc_FFFFF8027126FF65
.text:FFFFF8027126FF5A                 call    sub_FFFFF8027126FF60 ;替换堆栈中的返回地址为要执行的函数指针
.text:FFFFF8027126FF5F                 int     3               ; Trap to Debugger
.text:FFFFF8027126FF5F _guard_dispatch_icall endp

.text:FFFFF8027126FF9A loc_FFFFF8027126FF9A:                   ; CODE XREF: _guard_dispatch_icall+A↑j
.text:FFFFF8027126FF9A                                         ; _guard_dispatch_icall+2F↑j ...
.text:FFFFF8027126FF9A                 mov     rcx, rax        ; BugCheckParameter4
.text:FFFFF8027126FF9D                 jmp     _guard_icall_bugcheck
.text:FFFFF8027126FF9D ; END OF FUNCTION CHUNK FOR _guard_dispatch_icall

.text:FFFFF8027126FF7E loc_FFFFF8027126FF7E:                   ; CODE XREF: _guard_dispatch_icall+3E↑j
.text:FFFFF8027126FF7E                                         ; _guard_dispatch_icall+67↑j
.text:FFFFF8027126FF7E                 lfence
.text:FFFFF8027126FF81                 jmp     rax

.text:FFFFF8027126FF60 sub_FFFFF8027126FF60 proc near          ; CODE XREF: _guard_dispatch_icall+4A↑p
.text:FFFFF8027126FF60                 mov     [rsp+0], rax
.text:FFFFF8027126FF64                 retn