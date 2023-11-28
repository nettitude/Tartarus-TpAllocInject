# Tartarus-TpAllocInject

This is a simple loader that was published along with the blog post for Nettitude Labs on "Creating an OPSEC safe loader for Red Team Operations".


## Details

This is a simple loader that uses indirect syscalls via the Tartarus' Gate method.  
This loader executes shellcode with an known WINAPI CreateThreadPoolWait but I have changed things a little bit and instead, I call the underlying Tp* APIs from Ntdll.dll.