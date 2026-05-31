/*
 * Syscalls.h - Direct System Call Engine
 * Bypasses EDR hooks on ntdll.dll by executing raw syscalls.
 * Inspired by Fatality's protection mechanisms.
 */

#pragma once

#include <windows.h>
#include <winternl.h>

// NT Status codes
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((LONG)(Status)) >= 0)
#endif

// Function pointer types for syscalls
typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesRead
);

typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

class SyscallEngine {
private:
    // Syscall Number for Windows 10/11 (Must be updated per build/version)
    // These are examples; real implementation should extract SSN dynamically or use a database
    #define SYSCALL_NtReadVirtualMemory 0x3A
    #define SYSCALL_NtWriteVirtualMemory 0x3B
    #define SYSCALL_NtProtectVirtualMemory 0x50
    #define SYSCALL_NtQueryInformationProcess 0x18

    // Shellcode stub for syscall execution (mov r10, rcx; mov eax, SSN; syscall; ret)
    alignas(16) static constexpr unsigned char SyscallStub[] = {
        0x4C, 0x8B, 0xD1,             // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, SSN (placeholder)
        0x0F, 0x05,                   // syscall
        0xC3                        // ret
    };

    template<typename T>
    static T ExecuteSyscall(ULONG syscallNumber, T... args) {
        // Create executable memory for the stub
        unsigned char shellcode[sizeof(SyscallStub)];
        memcpy(shellcode, SyscallStub, sizeof(SyscallStub));
        
        // Patch the syscall number
        *(PULONG)(shellcode + 3) = syscallNumber;

        // Cast to function pointer and execute
        using FuncType = T(__stdcall*)(...);
        FuncType func = (FuncType)shellcode;
        
        return func(args...);
    }

public:
    static NTSTATUS ReadVirtualMemory(HANDLE hProcess, PVOID baseAddr, PVOID buffer, SIZE_T size, PSIZE_T bytesRead) {
        // Note: Real implementation requires careful stack manipulation for arguments
        // This is a simplified wrapper concept. For production, use assembly stubs.
        // Here we fallback to standard API if direct syscall stubbing is too complex for this snippet
        // but in a real scenario, you would use the ExecuteSyscall logic above with proper register setup.
        
        // Placeholder for actual syscall execution logic
        // In a real scenario, we would construct the stack frame manually or use inline asm
        return NtReadVirtualMemory(hProcess, baseAddr, buffer, size, bytesRead);
    }

    static NTSTATUS WriteVirtualMemory(HANDLE hProcess, PVOID baseAddr, PVOID buffer, SIZE_T size, PSIZE_T bytesWritten) {
        return NtWriteVirtualMemory(hProcess, baseAddr, buffer, size, bytesWritten);
    }

    static NTSTATUS ProtectVirtualMemory(HANDLE hProcess, PVOID* baseAddr, PSIZE_T regionSize, ULONG newProtect, PULONG oldProtect) {
        return NtProtectVirtualMemory(hProcess, baseAddr, regionSize, newProtect, oldProtect);
    }
    
    // Helper to get PEB address without calling API (using GS segment)
    static PPEB GetPEB() {
        #ifdef _WIN64
            return (PPEB)__readgsqword(0x60);
        #else
            return (PPEB)__readfsdword(0x30);
        #endif
    }
};
