#include "security.hpp"
#include <TlHelp32.h>
#include <Psapi.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <imagehlp.h>
#include <iostream>

// string şifreleme için XOR anahtarı
const unsigned char XOR_KEY[] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
const size_t XOR_KEY_SIZE = sizeof(XOR_KEY);

namespace Security {
    bool SecurityCheck() {
        if (IsDebuggerPresentCheck()) {
            std::cout << "\n [-] Debugger detected!";
            return false;
        }
        
        if (CheckDebugRegisters()) {
            std::cout << "\n [-] Debug registers detected!";
            return false;
        }
        
        if (CheckDebuggerTools()) {
            std::cout << "\n [-] Debugging tools detected!";
            return false;
        }
        
        return true;
    }

    bool IsDebuggerPresentCheck() {
        if (IsDebuggerPresent()) return true;
        
        BOOL isDebugged = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged);
        return isDebugged;
    }

    bool CheckDebugRegisters() {
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        
        if (!GetThreadContext(GetCurrentThread(), &ctx)) return false;
        
        return (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0);
    }

    bool CheckDebuggerTools() {
        const wchar_t* debuggerTools[] = {
            L"ollydbg.exe", L"x64dbg.exe", L"x32dbg.exe",
            L"ida64.exe", L"ida.exe", L"cheatengine-x86_64.exe",
            L"HTTPDebuggerUI.exe", L"ProcessHacker.exe", L"procmon.exe"
        };
        
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32W pe32 = {sizeof(pe32)};
        if (Process32FirstW(snapshot, &pe32)) {
            do {
                for (const auto& tool : debuggerTools) {
                    if (_wcsicmp(pe32.szExeFile, tool) == 0) {
                        CloseHandle(snapshot);
                        return true;
                    }
                }
            } while (Process32NextW(snapshot, &pe32));
        }
        
        CloseHandle(snapshot);
        return false;
    }

    void AntiDump() {
        DWORD oldProtect;
        char* pBaseAddr = (char*)GetModuleHandle(NULL);
        MEMORY_BASIC_INFORMATION mbi;
        VirtualQuery(pBaseAddr, &mbi, sizeof(mbi));
        VirtualProtect(pBaseAddr, mbi.RegionSize, PAGE_READONLY, &oldProtect);
    }

    void ProtectMemory() {
        HANDLE process = GetCurrentProcess();
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        
        MEMORY_BASIC_INFORMATION mbi;
        for (LPVOID addr = si.lpMinimumApplicationAddress; 
             addr < si.lpMaximumApplicationAddress; 
             addr = (LPBYTE)addr + mbi.RegionSize) {
            
            if (VirtualQuery(addr, &mbi, sizeof(mbi))) {
                if (mbi.State == MEM_COMMIT && 
                    (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE)) {
                    DWORD oldProtect;
                    VirtualProtect(addr, mbi.RegionSize, PAGE_NOACCESS, &oldProtect);
                }
            }
        }
    }

    bool IsVirtualMachine() {
        int cpuInfo[4] = {0};
        char vendorID[13] = {0};

        __cpuid(cpuInfo, 0);
        memcpy(vendorID, &cpuInfo[1], 4);
        memcpy(vendorID + 4, &cpuInfo[3], 4);
        memcpy(vendorID + 8, &cpuInfo[2], 4);

        if (strcmp(vendorID, "VMwareVMware") == 0 ||
            strcmp(vendorID, "Microsoft Hv") == 0 ||
            strcmp(vendorID, "VBoxVBoxVBox") == 0) {
            return true;
        }

        __cpuid(cpuInfo, 1);
        bool hypervisorPresent = (cpuInfo[2] & (1 << 31)) != 0;

        if (!hypervisorPresent) {
            return false;
        }

        HANDLE hDevice = CreateFileA("\\\\.\\VmGeneralPort", 
            GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice);
            return true;
        }

        hDevice = CreateFileA("\\\\.\\VBoxMiniRdrDN", 
            GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice);
            return true;
        }

        IP_ADAPTER_INFO adapterInfo[32];
        DWORD dwBufLen = sizeof(adapterInfo);
        if (GetAdaptersInfo(adapterInfo, &dwBufLen) == ERROR_SUCCESS) {
            PIP_ADAPTER_INFO pAdapterInfo = adapterInfo;
            while (pAdapterInfo) {
                if (pAdapterInfo->Address[0] == 0x00 && 
                    pAdapterInfo->Address[1] == 0x0C && 
                    pAdapterInfo->Address[2] == 0x29) {
                    return true;
                }
                if (pAdapterInfo->Address[0] == 0x08 && 
                    pAdapterInfo->Address[1] == 0x00 && 
                    pAdapterInfo->Address[2] == 0x27) {
                    return true;
                }
                pAdapterInfo = pAdapterInfo->Next;
            }
        }

        return false;
    }

    bool VerifyCodeIntegrity() {
        HANDLE hProcess = GetCurrentProcess();
        HMODULE hModule = GetModuleHandle(NULL);
        if (!hModule) return true;

        MODULEINFO moduleInfo;
        if (!GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo))) {
            return true;
        }

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return false;
        }

        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }

        DWORD originalChecksum = ntHeaders->OptionalHeader.CheckSum;
        if (originalChecksum == 0) {
            return true;
        }

        DWORD headerSum = 0;
        DWORD checkSum = 0;
        char* moduleBase = (char*)hModule;
        if (MapFileAndCheckSumA(moduleBase, &headerSum, &checkSum) != CHECKSUM_SUCCESS) {
            return true;
        }

        return true;
    }

    bool AdvancedSecurityCheck() {
        if (IsVirtualMachine()) {
            std::cout << "\n [-] Virtual machine detected!";
            Sleep(1500);
            exit(30);
        }

        if (!VerifyCodeIntegrity()) {
            std::cout << "\n [-] Code integrity check failed!";
            Sleep(1500);
            exit(31);
        }

        static DWORD lastCheck = GetTickCount();
        DWORD currentTime = GetTickCount();
        if (currentTime < lastCheck) {
            std::cout << "\n [-] Time manipulation detected!";
            Sleep(1500);
            exit(32);
        }
        lastCheck = currentTime;

        return true;
    }

    std::string XorEncrypt(const std::string& input) {
        std::string output = input;
        for (size_t i = 0; i < input.length(); i++) {
            output[i] = input[i] ^ XOR_KEY[i % XOR_KEY_SIZE];
        }
        return output;
    }

    std::string XorDecrypt(const std::string& input) {
        return XorEncrypt(input);
    }

    std::wstring XorEncryptW(const std::wstring& input) {
        std::wstring output = input;
        for (size_t i = 0; i < input.length(); i++) {
            output[i] = input[i] ^ XOR_KEY[i % XOR_KEY_SIZE];
        }
        return output;
    }

    std::wstring XorDecryptW(const std::wstring& input) {
        return XorEncryptW(input);
    }

    DWORD CalculateChecksum(const std::vector<BYTE>& data) {
        DWORD checksum = 0;
        for (size_t i = 0; i < data.size(); i++) {
            checksum = ((checksum << 5) | (checksum >> 27)) + data[i];
        }
        return checksum;
    }
} 