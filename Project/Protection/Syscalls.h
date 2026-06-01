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

    // ExecuteSyscall template commented out: the original used T as both a
    // return type and a parameter pack, which is invalid C++.  Additionally,
    // casting stack-allocated shellcode to a function pointer is UB and will
    // be blocked by DEP.  A production implementation should use VirtualAlloc
    // with PAGE_EXECUTE_READWRITE or a separate .asm stub.
    /*
    template<typename Ret, typename... Args>
    static Ret ExecuteSyscall(ULONG syscallNumber, Args... args) {
        unsigned char shellcode[sizeof(SyscallStub)];
        memcpy(shellcode, SyscallStub, sizeof(SyscallStub));
        *(PULONG)(shellcode + 3) = syscallNumber;
        using FuncType = Ret(__stdcall*)(Args...);
        FuncType func = (FuncType)shellcode;
        return func(args...);
    }
    */

public:
    static NTSTATUS ReadVirtualMemory(HANDLE hProcess, PVOID baseAddr, PVOID buffer, SIZE_T size, PSIZE_T bytesRead) {
        static NtReadVirtualMemory_t pFunc = nullptr;
        if (!pFunc) {
            HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
            if (hNtdll) pFunc = (NtReadVirtualMemory_t)GetProcAddress(hNtdll, "NtReadVirtualMemory");
        }
        if (pFunc) return pFunc(hProcess, baseAddr, buffer, size, bytesRead);
        return (NTSTATUS)0xC0000001; // STATUS_UNSUCCESSFUL
    }

    static NTSTATUS WriteVirtualMemory(HANDLE hProcess, PVOID baseAddr, PVOID buffer, SIZE_T size, PSIZE_T bytesWritten) {
        static NtWriteVirtualMemory_t pFunc = nullptr;
        if (!pFunc) {
            HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
            if (hNtdll) pFunc = (NtWriteVirtualMemory_t)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
        }
        if (pFunc) return pFunc(hProcess, baseAddr, buffer, size, bytesWritten);
        return (NTSTATUS)0xC0000001; // STATUS_UNSUCCESSFUL
    }

    static NTSTATUS ProtectVirtualMemory(HANDLE hProcess, PVOID* baseAddr, PSIZE_T regionSize, ULONG newProtect, PULONG oldProtect) {
        static NtProtectVirtualMemory_t pFunc = nullptr;
        if (!pFunc) {
            HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
            if (hNtdll) pFunc = (NtProtectVirtualMemory_t)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
        }
        if (pFunc) return pFunc(hProcess, baseAddr, regionSize, newProtect, oldProtect);
        return (NTSTATUS)0xC0000001; // STATUS_UNSUCCESSFUL
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
