#include <Windows.h>
BOOL GetSyscallId(PVOID pModuleBase, DWORD* SyscallId, PCHAR fnctolookfor);
extern "C" VOID setup(DWORD id, LPVOID jmptofake);
extern "C" NTSTATUS executioner(...);
LPVOID CustomCopy(LPVOID Destination, CONST LPVOID Source, SIZE_T Length);

typedef NTSTATUS(NTAPI* pTpAllocWait)(TP_WAIT** out, PTP_WAIT_CALLBACK callback, PVOID userdata, TP_CALLBACK_ENVIRON* environment);
typedef VOID(NTAPI* pTpSetWait)(TP_WAIT* wait, HANDLE handle, LARGE_INTEGER* timeout);