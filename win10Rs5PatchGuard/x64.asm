extern OriginKiProcessExpiredTimerList : qword
extern DpcHandler : proc
extern DummyDpc : proc
.code

SAVE macro
	push rax
	push rcx
	push rdx
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
	push rdi
	push rsi 
	push rbx
	push rbp
endm

RESTOR macro
	pop rbp
	pop rbx
	pop rsi
	pop rdi
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdx
	pop rcx
	pop rax
endm	


DetourKiProcessExpiredTimerList proc

	SAVE
	sub rsp,28h
	mov rcx,rsi
	call DpcHandler
	cmp rax,1
	jne on
	;int 3
	mov rax,DummyDpc
	mov [rsp+232],rax ;E8h
on:
	add rsp,28h
	RESTOR

	jmp [OriginKiProcessExpiredTimerList];

DetourKiProcessExpiredTimerList endp





end