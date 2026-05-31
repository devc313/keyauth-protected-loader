/*
 * EnvironmentBinding.h - Session-Bound Protection
 * Binds the loader to specific system environment (PEB, LDR, timestamps)
 * Inspired by Fatality's protection mechanisms.
 */

#pragma once

#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include "Syscalls.h"

class EnvironmentBinding {
private:
    struct ModuleInfo {
        std::wstring name;
        ULONGLONG loadTime;
        PVOID dllBase;
        DWORD sizeOfImage;
    };

    std::vector<ModuleInfo> _moduleInfos;
    ULONGLONG _pebAddress;
    DWORD _mainThreadId;
    DWORD _processId;

public:
    EnvironmentBinding() : _pebAddress(0), _mainThreadId(0), _processId(0) {
        CaptureEnvironment();
    }

    void CaptureEnvironment() {
        // Get PEB address using GS segment (no API call)
        #ifdef _WIN64
            _pebAddress = (ULONGLONG)__readgsqword(0x60);
        #else
            _pebAddress = (ULONGLONG)__readfsdword(0x30);
        #endif

        // Get current process and thread IDs
        _processId = GetCurrentProcessId();
        _mainThreadId = GetCurrentThreadId();

        // Capture loaded module information from PEB
        CaptureModuleInfo();
    }

    void CaptureModuleInfo() {
        PPEB peb = SyscallEngine::GetPEB();
        if (!peb || !peb->Ldr) return;

        PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
        PLIST_ENTRY curr = head->Flink;

        while (curr != head) {
            PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            
            if (entry->FullDllName.Buffer && entry->FullDllName.Length > 0) {
                ModuleInfo info;
                info.name = std::wstring(entry->FullDllName.Buffer, entry->FullDllName.Length / sizeof(WCHAR));
                info.loadTime = entry->LoadTime.QuadPart;
                info.dllBase = entry->DllBase;
                info.sizeOfImage = entry->SizeOfImage;
                
                _moduleInfos.push_back(info);
            }

            curr = curr->Flink;
        }
    }

    // Generate a unique session fingerprint based on environment
    std::string GenerateSessionFingerprint() {
        char fingerprint[256] = {0};
        
        // Combine PEB address, main thread ID, and module load times
        sprintf_s(fingerprint, sizeof(fingerprint), 
            "PEB:%p|TID:%lu|PID:%lu|", 
            (void*)_pebAddress, _mainThreadId, _processId);

        // Add first 3 module load times for binding
        for (size_t i = 0; i < 3 && i < _moduleInfos.size(); i++) {
            char moduleHash[64];
            sprintf_s(moduleHash, sizeof(moduleHash), 
                "%s:%llX|", 
                _moduleInfos[i].name.c_str(), 
                _moduleInfos[i].loadTime);
            
            // Simple hash concatenation
            strncat_s(fingerprint, sizeof(fingerprint), moduleHash, _TRUNCATE);
        }

        return std::string(fingerprint);
    }

    // Validate current environment against captured state
    bool ValidateEnvironment() {
        // Re-capture and compare critical values
        ULONGLONG currentPeb = 0;
        #ifdef _WIN64
            currentPeb = (ULONGLONG)__readgsqword(0x60);
        #else
            currentPeb = (ULONGLONG)__readfsdword(0x30);
        #endif

        // PEB address should remain constant
        if (currentPeb != _pebAddress) {
            return false;
        }

        // Validate module load times (these change on every reboot/run)
        PPEB peb = SyscallEngine::GetPEB();
        if (!peb || !peb->Ldr) return false;

        PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
        PLIST_ENTRY curr = head->Flink;
        size_t index = 0;

        while (curr != head && index < _moduleInfos.size()) {
            PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            
            if (entry->FullDllName.Buffer && entry->FullDllName.Length > 0) {
                std::wstring moduleName(entry->FullDllName.Buffer, entry->FullDllName.Length / sizeof(WCHAR));
                
                // Compare with captured module info
                if (moduleName == _moduleInfos[index].name) {
                    if (entry->LoadTime.QuadPart != _moduleInfos[index].loadTime) {
                        // Load time mismatch - possible dump/reload attack
                        return false;
                    }
                }
                index++;
            }

            curr = curr->Flink;
        }

        return true;
    }

    // Getters for server-side binding
    ULONGLONG GetPEBAddress() const { return _pebAddress; }
    DWORD GetMainThreadId() const { return _mainThreadId; }
    DWORD GetProcessId() const { return _processId; }
    
    const std::vector<ModuleInfo>& GetModuleInfos() const { 
        return _moduleInfos; 
    }
};
