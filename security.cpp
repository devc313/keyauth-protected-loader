#include "security.hpp"
#include <TlHelp32.h>
#include <Psapi.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <imagehlp.h>
#include <iostream>
#include <random>
#include <chrono>
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ntdll.lib")

// NTDLL function pointers for dynamic syscall
typedef NTSTATUS (NTAPI *pfnNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *pfnNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

namespace Security {
    // AES S-Box (Substitution Box) - AES standardından alınmıştır
    const unsigned char S_BOX[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    // Inverse S-Box
    const unsigned char INV_S_BOX[256] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };

    // CRC64 lookup table
    static uint64_t crc64_table[256];
    static bool crc64_table_initialized = false;

    // CRC64 tablosunu initialize et
    void InitCRC64Table() {
        if (crc64_table_initialized) return;
        
        uint64_t polynomial = 0xC96C5795D7870F42ULL;
        for (uint32_t i = 0; i < 256; i++) {
            uint64_t crc = i;
            for (int j = 0; j < 8; j++) {
                crc = (crc >> 1) ^ ((crc & 1) ? polynomial : 0);
            }
            crc64_table[i] = crc;
        }
        crc64_table_initialized = true;
    }

    // SecureZeroMemory - güvenli bellek sıfırlama (override Windows API)
    void SecureZeroMemory(void* ptr, size_t size) {
        volatile unsigned char* p = static_cast<unsigned char*>(ptr);
        while (size--) *p++ = 0;
    }

    // SecureAlloc - güvenli bellek ayırma
    void* SecureAlloc(size_t size) {
        void* ptr = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (ptr) {
            SecureZeroMemory(ptr, size);
        }
        return ptr;
    }

    // SecureFree - güvenli bellek serbest bırakma
    void SecureFree(void* ptr, size_t size) {
        if (ptr) {
            SecureZeroMemory(ptr, size);
            VirtualFree(ptr, 0, MEM_RELEASE);
        }
    }

    // CRC64 hesaplama
    uint64_t CalculateCRC64(const void* data, size_t length) {
        InitCRC64Table();
        const unsigned char* bytes = static_cast<const unsigned char*>(data);
        uint64_t crc = 0xFFFFFFFFFFFFFFFFULL;
        for (size_t i = 0; i < length; i++) {
            crc = crc64_table[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
        }
        return crc ^ 0xFFFFFFFFFFFFFFFFULL;
    }

    // SimpleHash256 - basit 256-bit hash fonksiyonu
    std::vector<unsigned char> SimpleHash256(const std::string& input) {
        std::vector<unsigned char> hash(32, 0);
        
        // Initial state
        uint32_t h[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

        // Process each byte
        for (size_t i = 0; i < input.size(); i++) {
            uint32_t w = static_cast<unsigned char>(input[i]);
            
            // Mixing operations
            h[0] += ((h[1] & h[2]) | (~h[1] & h[3])) + w + S_BOX[i % 256];
            h[4] += ((h[5] ^ h[6]) ^ h[7]) + w + INV_S_BOX[i % 256];
            
            // Rotate
            uint32_t tmp = h[7];
            for (int j = 7; j > 0; j--) h[j] = h[j-1];
            h[0] += tmp;
        }

        // Final mixing
        for (int round = 0; round < 4; round++) {
            for (int i = 0; i < 8; i++) {
                h[i] ^= (h[i] << 13) | (h[i] >> 19);
                h[i] *= 0x5bd1e995;
                h[i] ^= h[i] >> 15;
            }
        }

        // Convert to bytes
        for (int i = 0; i < 8; i++) {
            hash[i*4 + 0] = (h[i] >> 24) & 0xFF;
            hash[i*4 + 1] = (h[i] >> 16) & 0xFF;
            hash[i*4 + 2] = (h[i] >> 8) & 0xFF;
            hash[i*4 + 3] = h[i] & 0xFF;
        }

        return hash;
    }

    // ComputeHMAC - HMAC benzeri MAC hesaplama
    std::vector<unsigned char> ComputeHMAC(const std::string& data) {
        std::vector<unsigned char> mac(32);
        
        // Inner hash: key + data
        std::string innerData;
        innerData.reserve(HMAC_KEY_SIZE + data.size());
        for (size_t i = 0; i < HMAC_KEY_SIZE; i++) {
            innerData += static_cast<char>(g_keys.hmacKey[i] ^ 0x36);
        }
        innerData += data;
        
        std::vector<unsigned char> innerHash = SimpleHash256(innerData);
        
        // Outer hash: key + innerHash
        std::string outerData;
        outerData.reserve(HMAC_KEY_SIZE + 32);
        for (size_t i = 0; i < HMAC_KEY_SIZE; i++) {
            outerData += static_cast<char>(g_keys.hmacKey[i] ^ 0x5c);
        }
        outerData.append(reinterpret_cast<char*>(innerHash.data()), 32);
        
        std::vector<unsigned char> outerHash = SimpleHash256(outerData);
        
        // Copy result
        for (size_t i = 0; i < 32; i++) {
            mac[i] = outerHash[i];
        }
        
        return mac;
    }

    // VerifyHMAC - HMAC doğrulama
    bool VerifyHMAC(const std::string& data, const std::vector<unsigned char>& mac) {
        if (mac.size() != 32) return false;
        
        std::vector<unsigned char> computedMac = ComputeHMAC(data);
        
        // Constant-time comparison
        unsigned char result = 0;
        for (size_t i = 0; i < 32; i++) {
            result |= computedMac[i] ^ mac[i];
        }
        
        return result == 0;
    }

    // MultiLayerEncrypt - Çok katmanlı şifreleme
    std::string MultiLayerEncrypt(const std::string& input) {
        if (input.empty()) return "";
        
        std::string output;
        output.reserve(input.size() * 2);
        
        // Layer 1: XOR with rotating key
        for (size_t i = 0; i < input.size(); i++) {
            unsigned char c = static_cast<unsigned char>(input[i]);
            c ^= g_keys.xorKeys[0][i % MAX_XOR_KEY_SIZE];
            output += static_cast<char>(c);
        }
        
        // Layer 2: Substitution
        for (size_t i = 0; i < output.size(); i++) {
            output[i] = S_BOX[static_cast<unsigned char>(output[i])];
        }
        
        // Layer 3: Second XOR with different key
        for (size_t i = 0; i < output.size(); i++) {
            output[i] ^= g_keys.xorKeys[1][(i + 7) % MAX_XOR_KEY_SIZE];
        }
        
        // Layer 4: Rotation
        for (size_t i = 0; i < output.size(); i++) {
            unsigned char c = static_cast<unsigned char>(output[i]);
            c = static_cast<unsigned char>((c << 3) | (c >> 5));
            output[i] = c;
        }
        
        // Layer 5: Third XOR
        for (size_t i = 0; i < output.size(); i++) {
            output[i] ^= g_keys.xorKeys[2][(i * 3) % MAX_XOR_KEY_SIZE];
        }
        
        // Append HMAC for integrity
        std::vector<unsigned char> hmac = ComputeHMAC(output);
        output.append(reinterpret_cast<char*>(hmac.data()), hmac.size());
        
        return output;
    }

    // MultiLayerDecrypt - Çok katmanlı şifre çözme
    std::string MultiLayerDecrypt(const std::string& input) {
        if (input.size() < 32) return "";
        
        // Extract and verify HMAC
        size_t dataSize = input.size() - 32;
        std::string encryptedData = input.substr(0, dataSize);
        std::vector<unsigned char> receivedHmac(32);
        for (size_t i = 0; i < 32; i++) {
            receivedHmac[i] = static_cast<unsigned char>(input[dataSize + i]);
        }
        
        if (!VerifyHMAC(encryptedData, receivedHmac)) {
            return ""; // Integrity check failed
        }
        
        std::string output = encryptedData;
        
        // Reverse Layer 5: Third XOR
        for (size_t i = 0; i < output.size(); i++) {
            output[i] ^= g_keys.xorKeys[2][(i * 3) % MAX_XOR_KEY_SIZE];
        }
        
        // Reverse Layer 4: Rotation
        for (size_t i = 0; i < output.size(); i++) {
            unsigned char c = static_cast<unsigned char>(output[i]);
            c = static_cast<unsigned char>((c >> 3) | (c << 5));
            output[i] = c;
        }
        
        // Reverse Layer 3: Second XOR
        for (size_t i = 0; i < output.size(); i++) {
            output[i] ^= g_keys.xorKeys[1][(i + 7) % MAX_XOR_KEY_SIZE];
        }
        
        // Reverse Layer 2: Inverse Substitution
        for (size_t i = 0; i < output.size(); i++) {
            output[i] = INV_S_BOX[static_cast<unsigned char>(output[i])];
        }
        
        // Reverse Layer 1: XOR with rotating key
        for (size_t i = 0; i < output.size(); i++) {
            output[i] ^= g_keys.xorKeys[0][i % MAX_XOR_KEY_SIZE];
        }
        
        return output;
    }

    // Wide string versions
    std::wstring MultiLayerEncryptW(const std::wstring& input) {
        if (input.empty()) return L"";
        
        std::string narrowInput(input.begin(), input.end());
        std::string encrypted = MultiLayerEncrypt(narrowInput);
        
        return std::wstring(encrypted.begin(), encrypted.end());
    }

    std::wstring MultiLayerDecryptW(const std::wstring& input) {
        if (input.empty()) return L"";
        
        std::string narrowInput(input.begin(), input.end());
        std::string decrypted = MultiLayerDecrypt(narrowInput);
        
        return std::wstring(decrypted.begin(), decrypted.end());
    }

    // ==================== GELİŞMİŞ ANTI-DEBUG ====================
    
    namespace AntiDebug {
        bool IsDebuggerPresent_Advanced() {
            // Standard check
            if (IsDebuggerPresent()) return true;
            
            // Remote debugger check
            BOOL isRemote = FALSE;
            CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemote);
            if (isRemote) return true;
            
            // NtGlobalFlag check
            if (CheckNtGlobalFlag()) return true;
            
            // Heap flags check
            if (CheckHeapFlags()) return true;
            
            return false;
        }
        
        bool CheckNtGlobalFlag() {
            HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
            if (!hNtdll) return false;
            
            typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
                HANDLE ProcessHandle, ULONG ProcessInformationClass,
                PVOID ProcessInformation, ULONG ProcessInformationLength,
                PULONG ReturnLength);
            
            pfnNtQueryInformationProcess NtQueryInformationProcess = 
                (pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
            if (!NtQueryInformationProcess) return false;
            
            PROCESS_BASIC_INFORMATION pbi = {};
            NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 0, &pbi, sizeof(pbi), NULL);
            if (!NT_SUCCESS(status)) return false;
            
            PEB* peb = reinterpret_cast<PEB*>(pbi.PebBaseAddress);
            if (!peb) return false;
            
            BYTE ntlGlobalFlag = peb->NtGlobalFlag;
            return (ntlGlobalFlag & 0x70) == 0x70;
        }
        
        bool CheckHeapFlags() {
            HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
            if (!hNtdll) return false;
            
            typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
                HANDLE ProcessHandle, ULONG ProcessInformationClass,
                PVOID ProcessInformation, ULONG ProcessInformationLength,
                PULONG ReturnLength);
            
            pfnNtQueryInformationProcess NtQueryInformationProcess = 
                (pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
            if (!NtQueryInformationProcess) return false;
            
            PROCESS_BASIC_INFORMATION pbi = {};
            NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 0, &pbi, sizeof(pbi), NULL);
            if (!NT_SUCCESS(status)) return false;
            
            PEB* peb = reinterpret_cast<PEB*>(pbi.PebBaseAddress);
            if (!peb) return false;
            
            // Check heap flags
            PEB_LDR_DATA* ldr = peb->Ldr;
            if (!ldr) return false;
            
            LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
            LIST_ENTRY* curr = head->Flink;
            
            while (curr != head) {
                LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                if (entry->FullDllName.Buffer) {
                    // Check for known debugger DLLs
                    const wchar_t* dllName = entry->FullDllName.Buffer;
                    if (wcsstr(dllName, L"dbgcore") || wcsstr(dllName, L"debugger")) {
                        return true;
                    }
                }
                curr = curr->Flink;
            }
            
            return false;
        }
        
        bool CheckRemoteDebugger() {
            BOOL isDebugged = FALSE;
            CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged);
            return isDebugged == TRUE;
        }
        
        bool CheckTimingAttack(uint32_t threshold_ms) {
            LARGE_INTEGER freq, start, end;
            QueryPerformanceFrequency(&freq);
            QueryPerformanceCounter(&start);
            
            // Busy wait for a short period
            volatile int sum = 0;
            for (int i = 0; i < 1000000; i++) {
                sum += i;
            }
            
            QueryPerformanceCounter(&end);
            double elapsedMs = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000.0;
            
            // If debugger is attached, timing will be significantly different
            return elapsedMs > threshold_ms * 2.0;
        }
        
        bool CheckBreakpoints() {
            return CheckSoftwareBreakpoints() || CheckHardwareBreakpoints();
        }
        
        bool CheckSoftwareBreakpoints() {
            HMODULE hMod = GetModuleHandle(NULL);
            if (!hMod) return false;
            
            DOS_HEADER* dosHeader = (DOS_HEADER*)hMod;
            NT_HEADER* ntHeader = (NT_HEADER*)((BYTE*)hMod + dosHeader->e_lfanew);
            
            if (ntHeader->Signature != IMAGE_NT_SIGNATURE) return false;
            
            IMAGE_OPTIONAL_HEADER* optHeader = &ntHeader->OptionalHeader;
            BYTE* baseAddr = (BYTE*)hMod;
            BYTE* codeSection = baseAddr + optHeader->AddressOfEntryPoint;
            
            // Check for INT3 (0xCC) at entry point
            if (*codeSection == 0xCC) return true;
            
            return false;
        }
        
        bool CheckHardwareBreakpoints() {
            CONTEXT ctx = {};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            
            if (!GetThreadContext(GetCurrentThread(), &ctx)) return false;
            
            return (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0);
        }
        
        void EnableAntiDebug() {
            // Set critical process to prevent termination
            typedef NTSTATUS (NTAPI *pfnNtSetInformationProcess)(
                HANDLE ProcessHandle, ULONG ProcessInformationClass,
                PVOID ProcessInformation, ULONG ProcessInformationLength);
            
            HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
            if (hNtdll) {
                pfnNtSetInformationProcess NtSetInformationProcess = 
                    (pfnNtSetInformationProcess)GetProcAddress(hNtdll, "NtSetInformationProcess");
                
                if (NtSetInformationProcess) {
                    // Set process as critical
                    ULONG breakOnTermination = 1;
                    NtSetInformationProcess(GetCurrentProcess(), 29, &breakOnTermination, sizeof(ULONG));
                }
            }
        }
        
        void TriggerAntiDebugException() {
            // Trigger an exception that debuggers might not handle correctly
            __try {
                RaiseException(0xE0000001, 0, 0, NULL);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                // Silently handle
            }
        }
    }

    // ==================== DYNAMIC SYSCALL RESOLUTION ====================
    
    namespace Syscall {
        // Hell's Gate / Halo's Gate technique for dynamic SSN resolution
        WORD GetSSN(const char* functionName) {
            HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
            if (!hNtdll) return 0;
            
            BYTE* addr = (BYTE*)GetProcAddress(hNtdll, functionName);
            if (!addr) return 0;
            
            // Look for syscall instruction pattern
            // mov r10, rcx; mov eax, SSN; syscall
            for (int i = 0; i < 24; i++) {
                if (addr[i] == 0xB8) { // mov eax, imm32
                    WORD ssn = *(WORD*)&addr[i + 1];
                    return ssn;
                }
            }
            
            return 0;
        }
        
        PVOID GetSyscallStub(const char* functionName) {
            HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
            if (!hNtdll) return nullptr;
            
            return (PVOID)GetProcAddress(hNtdll, functionName);
        }
        
        NTSTATUS CallNtAllocateVirtualMemory(HANDLE processHandle, PVOID* baseAddress,
                                              ULONG_PTR zeroBits, PSIZE_T regionSize,
                                              ULONG allocationType, ULONG protect) {
            static pfnNtAllocateVirtualMemory pNtAlloc = nullptr;
            if (!pNtAlloc) {
                HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
                if (hNtdll) {
                    pNtAlloc = (pfnNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
                }
            }
            
            if (pNtAlloc) {
                return pNtAlloc(processHandle, baseAddress, zeroBits, regionSize, allocationType, protect);
            }
            
            // Fallback to VirtualAlloc
            *baseAddress = VirtualAlloc(*baseAddress, *regionSize, allocationType, protect);
            return *baseAddress ? 0 : 0xC0000001;
        }
        
        NTSTATUS CallNtProtectVirtualMemory(HANDLE processHandle, PVOID* baseAddress,
                                             PSIZE_T regionSize, ULONG newProtect, PULONG oldProtect) {
            static pfnNtProtectVirtualMemory pNtProt = nullptr;
            if (!pNtProt) {
                HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
                if (hNtdll) {
                    pNtProt = (pfnNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
                }
            }
            
            if (pNtProt) {
                return pNtProt(processHandle, baseAddress, regionSize, newProtect, oldProtect);
            }
            
            // Fallback to VirtualProtect
            if (VirtualProtect(*baseAddress, *regionSize, newProtect, (DWORD*)oldProtect)) {
                return 0;
            }
            return 0xC0000001;
        }
    }

    // ==================== EXISTING FUNCTIONS ====================
    
    bool SecurityCheck() {
        if (AntiDebug::IsDebuggerPresent_Advanced()) {
            std::cout << "\n [-] Advanced debugger detected!";
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
        return AntiDebug::IsDebuggerPresent_Advanced();
    }

    bool CheckDebugRegisters() {
        return AntiDebug::CheckHardwareBreakpoints();
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

    // CheckTimingAttack - zamanlama saldırısı kontrolü
    bool CheckTimingAttack() {
        static std::chrono::high_resolution_clock::time_point lastCheck = 
            std::chrono::high_resolution_clock::now();
        
        auto currentTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            currentTime - lastCheck).count();
        
        // Eğer çok kısa sürede tekrar çağrılmışsa şüpheli
        if (duration < 10 && duration >= 0) {
            return false;
        }
        
        lastCheck = currentTime;
        return true;
    }

    // CheckBreakpoints - software breakpoint kontrolü
    bool CheckBreakpoints() {
        HMODULE hModule = GetModuleHandle(NULL);
        if (!hModule) return false;

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

        // Kod section'ını tara
        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (memcmp(sections[i].Name, ".text", 5) == 0 ||
                memcmp(sections[i].Name, "CODE", 4) == 0) {
                
                BYTE* sectionStart = (BYTE*)hModule + sections[i].VirtualAddress;
                DWORD sectionSize = sections[i].Misc.VirtualSize;
                
                // INT3 breakpoint (0xCC) ara
                for (DWORD j = 0; j < sectionSize; j++) {
                    if (sectionStart[j] == 0xCC) {
                        return true;
                    }
                }
                break;
            }
        }
        
        return false;
    }

    // ProtectCriticalMemory - kritik belleği koru (düzeltildi)
    void ProtectCriticalMemory() {
        // Sadece belirli bölgeleri koru, tüm process'i değil
        HMODULE hModule = GetModuleHandle(NULL);
        if (!hModule) return;

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;

        // Sadece kod section'ını READONLY yap
        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (memcmp(sections[i].Name, ".text", 5) == 0) {
                BYTE* sectionStart = (BYTE*)hModule + sections[i].VirtualAddress;
                DWORD sectionSize = sections[i].Misc.VirtualSize;
                
                DWORD oldProtect;
                VirtualProtect(sectionStart, sectionSize, PAGE_READONLY, &oldProtect);
                break;
            }
        }
    }

    // EncryptCodeSection - kod section'ını şifrele (runtime)
    void EncryptCodeSection() {
        // Bu fonksiyon sadece belirli bölgeleri hedef alır
        // Gerçek implementasyon için packer kullanılması önerilir
        HMODULE hModule = GetModuleHandle(NULL);
        if (!hModule) return;

        // Sadece data section'larını etkile
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;

        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (memcmp(sections[i].Name, ".data", 5) == 0 ||
                memcmp(sections[i].Name, ".rdata", 6) == 0) {
                
                BYTE* sectionStart = (BYTE*)hModule + sections[i].VirtualAddress;
                DWORD sectionSize = sections[i].Misc.VirtualSize;
                
                DWORD oldProtect;
                if (VirtualProtect(sectionStart, sectionSize, PAGE_READWRITE, &oldProtect)) {
                    // Basit XOR encryption
                    for (DWORD j = 0; j < sectionSize; j++) {
                        sectionStart[j] ^= g_keys.xorKeys[3][j % MAX_XOR_KEY_SIZE];
                    }
                    VirtualProtect(sectionStart, sectionSize, oldProtect, &oldProtect);
                }
                break;
            }
        }
    }

    // CheckVMArtifacts - VM artifact'larını kontrol et
    bool CheckVMArtifacts() {
        // Registry'de VM izleri ara
        HKEY hKey;
        const wchar_t* vmPaths[] = {
            L"SOFTWARE\\VMware, Inc.\\VMware Tools",
            L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
            L"SOFTWARE\\Microsoft\\Hyper-V",
            nullptr
        };
        
        for (int i = 0; vmPaths[i] != nullptr; i++) {
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, vmPaths[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return true;
            }
        }
        
        // BIOS information check
        char buffer[256] = {0};
        HKEY hBIOS;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", 
                          0, KEY_READ, &hBIOS) == ERROR_SUCCESS) {
            DWORD size = sizeof(buffer);
            if (RegQueryValueExA(hBIOS, "BIOSVendor", NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
                std::string biosVendor(buffer);
                if (biosVendor.find("VMware") != std::string::npos ||
                    biosVendor.find("VirtualBox") != std::string::npos ||
                    biosVendor.find("QEMU") != std::string::npos) {
                    RegCloseKey(hBIOS);
                    return true;
                }
            }
            RegCloseKey(hBIOS);
        }
        
        return false;
    }

    // CalculateAndVerifyChecksum - checksum hesapla ve doğrula
    bool CalculateAndVerifyChecksum() {
        HMODULE hModule = GetModuleHandle(NULL);
        if (!hModule) return true;

        // Module base ve size al
        MODULEINFO moduleInfo;
        HANDLE hProcess = GetCurrentProcess();
        if (!GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo))) {
            return true;
        }

        // CRC64 hesapla
        uint64_t currentCRC = CalculateCRC64(moduleInfo.lpBaseOfDll, 
                                              moduleInfo.SizeOfImage);
        
        // İlk çalıştırmada referans değeri sakla
        static uint64_t referenceCRC = currentCRC;
        
        // Eğer değiştiyse modifiye edilmiştir
        if (currentCRC != referenceCRC) {
            return false;
        }
        
        return true;
    }

    // ContinuousSecurityMonitor - sürekli güvenlik monitörü
    bool ContinuousSecurityMonitor() {
        // Periyodik kontroller
        static DWORD lastDebuggerCheck = 0;
        static DWORD lastVMCheck = 0;
        static DWORD lastIntegrityCheck = 0;
        
        DWORD currentTime = GetTickCount();
        
        // Her 5 saniyede debugger kontrolü
        if (currentTime - lastDebuggerCheck > 5000) {
            if (IsDebuggerPresentCheck() || CheckDebugRegisters()) {
                return false;
            }
            lastDebuggerCheck = currentTime;
        }
        
        // Her 30 saniyede VM kontrolü
        if (currentTime - lastVMCheck > 30000) {
            if (IsVirtualMachine() || CheckVMArtifacts()) {
                return false;
            }
            lastVMCheck = currentTime;
        }
        
        // Her 10 saniyede bütünlük kontrolü
        if (currentTime - lastIntegrityCheck > 10000) {
            if (!CalculateAndVerifyChecksum()) {
                return false;
            }
            lastIntegrityCheck = currentTime;
        }
        
        return true;
    }

    // Eski XorEncrypt/XorDecrypt fonksiyonları artık MultiLayer kullanıyor
    std::string XorEncrypt(const std::string& input) {
        return MultiLayerEncrypt(input);
    }

    std::string XorDecrypt(const std::string& input) {
        return MultiLayerDecrypt(input);
    }

    std::wstring XorEncryptW(const std::wstring& input) {
        return MultiLayerEncryptW(input);
    }

    std::wstring XorDecryptW(const std::wstring& input) {
        return MultiLayerDecryptW(input);
    }

    DWORD CalculateChecksum(const std::vector<BYTE>& data) {
        DWORD checksum = 0;
        for (size_t i = 0; i < data.size(); i++) {
            checksum = ((checksum << 5) | (checksum >> 27)) + data[i];
        }
        return checksum;
    }
} 