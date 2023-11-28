.data
	id DWORD 000h
	jmptofake QWORD 00000000h

.code 

	setup PROC
		mov id, 000h
		mov id, ecx
		mov jmptofake, 00000000h
		mov jmptofake, rdx
		ret
	setup ENDP

	executioner PROC
		mov r10, rcx
		mov eax, id
		jmp jmptofake
		ret
	executioner ENDP
end
