/*
 * ProcessCritical.h - Process Criticality Protection
 * Sets ProcessBreakOnTermination flag to prevent easy termination.
 * Inspired by Fatality's protection mechanisms.
 */

#pragma once

#include <windows.h>
#include <winternl.h>

#ifndef PROCESS_BREAKAWAY_OK
#define PROCESS_BREAKAWAY_OK 0x0200
#endif

#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD 0x0002
#endif

#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION 0x0200
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

// NtSetInformationProcess function pointer
typedef NTSTATUS(NTAPI* NtSetInformationProcess_t)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
);

class ProcessCritical {
private:
    static constexpr ULONG ProcessBreakOnTermination = 0x1D;
    static constexpr ULONG ProcessHandleTracing = 0x1C;
    
    bool _isCritical = false;
    HANDLE _hProcess = nullptr;

public:
    ProcessCritical() : _isCritical(false), _hProcess(nullptr) {}

    // Enable critical process flag
    bool EnableCritical() {
        if (_isCritical) return true;

        _hProcess = GetCurrentProcess();

        // Get NtSetInformationProcess from ntdll
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return false;

        NtSetInformationProcess_t NtSetInformationProcess = 
            (NtSetInformationProcess_t)GetProcAddress(hNtdll, "NtSetInformationProcess");
        
        if (!NtSetInformationProcess) return false;

        // Set ProcessBreakOnTermination flag
        // Value of 1 enables the flag
        ULONG breakOnTerm = 1;
        NTSTATUS status = NtSetInformationProcess(
            _hProcess,
            ProcessBreakOnTermination,
            &breakOnTerm,
            sizeof(ULONG)
        );

        if (status == STATUS_SUCCESS) {
            _isCritical = true;
            return true;
        }

        return false;
    }

    // Disable critical process flag (use with caution!)
    bool DisableCritical() {
        if (!_isCritical || !_hProcess) return false;

        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return false;

        NtSetInformationProcess_t NtSetInformationProcess = 
            (NtSetInformationProcess_t)GetProcAddress(hNtdll, "NtSetInformationProcess");
        
        if (!NtSetInformationProcess) return false;

        // Set ProcessBreakOnTermination flag to 0 to disable
        ULONG breakOnTerm = 0;
        NTSTATUS status = NtSetInformationProcess(
            _hProcess,
            ProcessBreakOnTermination,
            &breakOnTerm,
            sizeof(ULONG)
        );

        if (status == STATUS_SUCCESS) {
            _isCritical = false;
            return true;
        }

        return false;
    }

    // Check if process is currently marked as critical
    bool IsCritical() const {
        return _isCritical;
    }

    // Get last error message for critical process operations
    static std::string GetLastErrorString() {
        DWORD error = GetLastError();
        LPSTR msgBuffer = nullptr;
        
        FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&msgBuffer,
            0,
            NULL
        );

        std::string msg = msgBuffer ? msgBuffer : "Unknown error";
        if (msgBuffer) LocalFree(msgBuffer);
        
        return msg;
    }
};

// Usage example:
// ProcessCritical critical;
// critical.EnableCritical(); // Before injection
// ... perform sensitive operations ...
// critical.DisableCritical(); // After successful injection
