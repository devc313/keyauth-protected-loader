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

        PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
        PLIST_ENTRY curr = head->Flink;
        int safety = 0;
        const int MAX_MODULES = 256;
        const size_t MAX_NAME_CHARS = 256;

        while (curr != head && safety < MAX_MODULES) {
            safety++;
            if (!curr) break;

            PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

            if (entry &&
                entry->FullDllName.Buffer &&
                entry->FullDllName.Length > 0 &&
                entry->FullDllName.Length < 65536) {

                size_t charCount = entry->FullDllName.Length / sizeof(WCHAR);
                if (charCount > MAX_NAME_CHARS) {
                    charCount = MAX_NAME_CHARS;
                }

                ModuleInfo info;
                try {
                    info.name = std::wstring(entry->FullDllName.Buffer, charCount);
                } catch (...) {
                    break;
                }
                info.loadTime = 0;
                info.dllBase = entry->DllBase;
                info.sizeOfImage = 0;

                _moduleInfos.push_back(info);
            }

            curr = curr->Flink;
        }
    }

    // Generate a unique session fingerprint based on environment
    std::string GenerateSessionFingerprint() {
        char fingerprint[512] = {0};

        // Combine PEB address, main thread ID, and process ID
        // Use snprintf with explicit size to be safe
        int written = snprintf(fingerprint, sizeof(fingerprint),
            "PEB:%p|TID:%lu|PID:%lu|MODS:%zu|",
            (void*)_pebAddress, _mainThreadId, _processId, _moduleInfos.size());

        if (written < 0 || written >= (int)sizeof(fingerprint)) {
            // fallback: PEB/TID/PID only
            return std::string(fingerprint);
        }

        size_t offset = (size_t)written;
        size_t maxAdd = sizeof(fingerprint) - offset - 1;

        // Add first 3 module names (truncated to 32 chars each) for binding
        for (size_t i = 0; i < 3 && i < _moduleInfos.size() && maxAdd > 0; i++) {
            const std::wstring& wname = _moduleInfos[i].name;
            if (wname.empty()) {
                continue;
            }

            // Convert wchar_t -> UTF-8 safely via WideCharToMultiByte
            char nameUtf8[64] = {0};
            int nameLen = WideCharToMultiByte(CP_UTF8, 0,
                wname.c_str(), (int)wname.size(),
                nameUtf8, sizeof(nameUtf8) - 1, NULL, NULL);
            if (nameLen <= 0) {
                continue;
            }
            nameUtf8[nameLen] = '\0';

            // Truncate if too long for our buffer
            if (nameLen > 32) {
                nameUtf8[32] = '\0';
                nameLen = 32;
            }

            int addWritten = snprintf(fingerprint + offset, maxAdd + 1,
                "M%zu:", i);
            if (addWritten < 0 || addWritten > (int)maxAdd) break;
            offset += (size_t)addWritten;
            maxAdd -= (size_t)addWritten;

            // safe strncat-style copy
            size_t copyLen = (size_t)nameLen;
            if (copyLen > maxAdd) copyLen = maxAdd;
            memcpy(fingerprint + offset, nameUtf8, copyLen);
            offset += copyLen;
            maxAdd -= copyLen;

            if (maxAdd == 0) break;
            fingerprint[offset] = '|';
            offset++;
            maxAdd--;
        }

        return std::string(fingerprint);
    }

    // Validate current environment against captured state
    bool ValidateEnvironment() {
        try {
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

            PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
            PLIST_ENTRY curr = head->Flink;
            size_t index = 0;
            int safety = 0;
            const int MAX_ITER = 512;

            while (curr != head && index < _moduleInfos.size() && safety < MAX_ITER) {
                safety++;
                if (!curr) break;

                PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

                if (entry && entry->FullDllName.Buffer && entry->FullDllName.Length > 0 &&
                    entry->FullDllName.Length < 65536) {

                    size_t charCount = entry->FullDllName.Length / sizeof(WCHAR);
                    if (charCount > 256) charCount = 256;

                    std::wstring moduleName(entry->FullDllName.Buffer, charCount);

                    // Compare with captured module info
                    if (moduleName == _moduleInfos[index].name) {
                        if (0 != _moduleInfos[index].loadTime) {
                            // Load time mismatch - possible dump/reload attack
                            return false;
                        }
                    }
                    index++;
                }

                curr = curr->Flink;
            }

            return true;
        } catch (...) {
            return false;
        }
    }

    // Getters for server-side binding
    ULONGLONG GetPEBAddress() const { return _pebAddress; }
    DWORD GetMainThreadId() const { return _mainThreadId; }
    DWORD GetProcessId() const { return _processId; }
    
    const std::vector<ModuleInfo>& GetModuleInfos() const { 
        return _moduleInfos; 
    }
};
