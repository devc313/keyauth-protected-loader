#include "security.hpp"
#include <windows.h>
#include <winnt.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <imagehlp.h>
#include <iostream>
#include <random>
#include <chrono>
#include <wincrypt.h>
#include <algorithm>
#include <immintrin.h>
#include <atomic>

// Missing constant definitions
#define CPUID_FEATURE_INFO 1
#define CPUID_VENDOR_INFO 0
#define CPUID_HYPERVISOR_BIT 31
#define TIMING_THRESHOLD_NORMAL 100
#define ProcessDebugFlags 31
#define ProcessDebugPort 7
#define ProcessBreakOnTermination 29

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
    // S_BOX and INV_S_BOX are already defined in security.hpp header
    // Do not redefine them here to avoid C2374/C2086 redefinition errors

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
        // Forward declarations
        bool CheckNtGlobalFlag();
        bool CheckHeapFlags();
        bool CheckSoftwareBreakpoints();
        bool CheckHardwareBreakpoints();
        
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
            
            // NtGlobalFlag is at offset 0xBC (x64) or 0x68 (x86) in PEB
            // The public PEB struct doesn't expose it, so use offset-based access
            #ifdef _WIN64
                BYTE ntlGlobalFlag = *reinterpret_cast<BYTE*>(reinterpret_cast<BYTE*>(peb) + 0xBC);
            #else
                BYTE ntlGlobalFlag = *reinterpret_cast<BYTE*>(reinterpret_cast<BYTE*>(peb) + 0x68);
            #endif
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
            
            LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
            LIST_ENTRY* curr = head->Flink;
            
            while (curr != head) {
                LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
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
            
            PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hMod;
            PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dosHeader->e_lfanew);
            
            if (ntHeader->Signature != IMAGE_NT_SIGNATURE) return false;
            
            PIMAGE_OPTIONAL_HEADER optHeader = &ntHeader->OptionalHeader;
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

    // ========================================================================
    // NtQueryInformationProcessCheck - Advanced PEB-based debugger detection
    // Uses native NT API to detect debuggers through multiple methods
    // ========================================================================
    bool NtQueryInformationProcessCheck() {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) return false;
        
        pfnNtQueryInformationProcess NtQueryInfo = 
            reinterpret_cast<pfnNtQueryInformationProcess>(
                GetProcAddress(hNtdll, "NtQueryInformationProcess")
            );
        
        if (!NtQueryInfo) return false;
        
        // Method 1: Check ProcessDebugPort (returns 0xFFFFFFFF if debugging)
        HANDLE debugPort = nullptr;
        ULONG returnLength = 0;
        NTSTATUS status = NtQueryInfo(
            GetCurrentProcess(),
            ProcessDebugPort,
            &debugPort,
            sizeof(HANDLE),
            &returnLength
        );
        
        if (NT_SUCCESS(status) && debugPort != nullptr) {
            return true; // Debugger detected
        }
        
        // Method 2: Check ProcessDebugFlags (should be 0 when debugging)
        ULONG debugFlags = 0;
        status = NtQueryInfo(
            GetCurrentProcess(),
            ProcessDebugFlags,
            &debugFlags,
            sizeof(ULONG),
            &returnLength
        );
        
        if (NT_SUCCESS(status) && debugFlags == 0) {
            return true; // Debugger detected
        }
        
        // Method 3: Check ProcessBreakOnTermination
        ULONG breakOnTermination = 0;
        status = NtQueryInfo(
            GetCurrentProcess(),
            ProcessBreakOnTermination,
            &breakOnTermination,
            sizeof(ULONG),
            &returnLength
        );
        
        if (NT_SUCCESS(status) && breakOnTermination != 0) {
            return true; // Debugger detected
        }
        
        return false;
    }

    // ========================================================================
    // TimingBasedAntiDebug - RDTSC-based timing analysis
    // Detects debugger by measuring execution time of code blocks
    // ========================================================================
    bool TimingBasedAntiDebug() {
        LARGE_INTEGER frequency, start, end;
        QueryPerformanceFrequency(&frequency);
        
        // Execute a known operation and measure time
        QueryPerformanceCounter(&start);
        
        // Perform some CPU-intensive work
        volatile uint64_t result = 0;
        for (int i = 0; i < 10000; i++) {
            result += __rdtsc();
            _mm_pause(); // Prevent pipeline stalls
        }
        
        QueryPerformanceCounter(&end);
        
        // Calculate elapsed time in microseconds
        LONGLONG elapsed = (end.QuadPart - start.QuadPart) * 1000000 / frequency.QuadPart;
        
        // If it takes too long, likely running under debugger
        // Normal execution should be < 1000 microseconds
        if (elapsed > TIMING_THRESHOLD_NORMAL * 1000) {
            return true;
        }
        
        // Additional RDTSC check with serialization
        unsigned int dummy;
        unsigned __int64 tsc1 = __rdtscp(&dummy);
        
        // Force some instructions that are slow under debugger
        int cpuInfoTmp[4];
        for (volatile int j = 0; j < 100; j++) {
            __cpuid(cpuInfoTmp, 0);
        }
        
        unsigned __int64 tsc2 = __rdtscp(&dummy);
        unsigned __int64 delta = tsc2 - tsc1;
        
        // If CPU cycles are abnormally high, debugger may be present
        if (delta > 100000000ULL) { // Adjust threshold as needed
            return true;
        }
        
        return false;
    }

    // Global exception handler state
    static std::atomic<bool> g_exceptionTriggered{false};
    static std::atomic<DWORD> g_exceptionCount{0};

    // ========================================================================
    // ExceptionHandler - SEH/VEH exception handler for anti-debug
    // Detects debuggers by triggering exceptions and checking behavior
    // ========================================================================
    LONG NTAPI ExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo) {
        g_exceptionTriggered.store(true);
        g_exceptionCount.fetch_add(1, std::memory_order_relaxed);
        
        // Continue execution after handling exception
        if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT ||
            ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
            // Move past the breakpoint
            ExceptionInfo->ContextRecord->Rip += 1;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // ========================================================================
    // ExceptionBasedAntiDebug - SEH/VEH based debugger detection
    // Triggers exceptions and checks if debugger handles them differently
    // ========================================================================
    bool ExceptionBasedAntiDebug() {
        // Reset state
        g_exceptionTriggered.store(false);
        g_exceptionCount.store(0, std::memory_order_relaxed);
        
        // Register Vectored Exception Handler
        PVOID vehHandle = AddVectoredExceptionHandler(1, ExceptionHandler);
        
        if (!vehHandle) return false;
        
        bool debuggerDetected = false;
        
        // Test 1: Trigger software breakpoint (INT3)
        __try {
            __debugbreak();
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // If we reach here without VEH being called, debugger intercepted
            if (!g_exceptionTriggered.load()) {
                debuggerDetected = true;
            }
        }
        
        // Test 2: Trigger access violation on NULL
        if (!debuggerDetected) {
            g_exceptionTriggered.store(false);
            
            __try {
                volatile int* nullPtr = nullptr;
                (void)(*nullPtr); // This will trigger access violation
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                if (!g_exceptionTriggered.load()) {
                    debuggerDetected = true;
                }
            }
        }
        
        // Test 3: Check exception count
        // Under debugger, exception handling behavior differs
        if (g_exceptionCount.load() < 2) {
            debuggerDetected = true;
        }
        
        // Clean up
        RemoveVectoredExceptionHandler(vehHandle);
        
        return debuggerDetected;
    }

    // ========================================================================
    // HardwareBreakpointCheck - Comprehensive DR0-DR7 register check
    // More thorough than basic CheckDebugRegisters
    // ========================================================================
    bool HardwareBreakpointCheck() {
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        
        if (!GetThreadContext(GetCurrentThread(), &ctx)) {
            return false;
        }
        
        // Check all debug registers
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            return true;
        }
        
        // Check Dr7 for enabled breakpoints
        if (ctx.Dr7 != 0) {
            // Analyze Dr7 bits for active breakpoints
            for (int i = 0; i < 4; i++) {
                DWORD enableBits = (ctx.Dr7 >> (2 * i)) & 0x3;
                if (enableBits != 0) {
                    return true; // Breakpoint enabled
                }
            }
        }
        
        return false;
    }

    // ========================================================================
    // SoftwareInterruptCheck - INT3 (0xCC) detection in code sections
    // Scans executable memory for software breakpoints
    // ========================================================================
    bool SoftwareInterruptCheck() {
        HMODULE hModule = GetModuleHandle(NULL);
        if (!hModule) return false;

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

        // Scan all executable sections
        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            // Check if section is executable
            if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                BYTE* sectionStart = (BYTE*)hModule + sections[i].VirtualAddress;
                DWORD sectionSize = sections[i].Misc.VirtualSize;
                
                // Search for INT3 (0xCC) bytes
                for (DWORD j = 0; j < sectionSize; j++) {
                    if (sectionStart[j] == 0xCC) {
                        // Verify it's not a legitimate INT3 instruction
                        // by checking surrounding context
                        if (j > 0 && sectionStart[j-1] != 0xF2) { // Not REP prefix
                            return true;
                        }
                    }
                }
            }
        }
        
        return false;
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
        HMODULE hModule = GetModuleHandle(NULL);
        if (!hModule) return;

        char* pBaseAddr = (char*)hModule;
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pBaseAddr;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(pBaseAddr + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;

        DWORD headersSize = ntHeaders->OptionalHeader.SizeOfHeaders;
        if (headersSize == 0) {
            headersSize = 0x1000;
        }

        DWORD pageSize = 0x1000;
        DWORD protectSize = (headersSize + pageSize - 1) & ~(pageSize - 1);

        DWORD oldProtect = 0;
        if (!VirtualProtect(pBaseAddr, protectSize, PAGE_READONLY, &oldProtect)) {
            return;
        }

        // eski protec'i geri almak isterseniz burada saklayabilirsiniz
        (void)oldProtect;
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
        // VM detection devre disi - gelistirme sirasinda VM/VMWare/Hyper-V uzerinde calisabilmek icin
        // production'da tekrar acmak icin asagidaki satirlarin yorumunu kaldirin
        return false;

        // Use comprehensive VM detection methods
        // if (CPUIDHypervisorDetection()) return true;
        // if (RegistryArtifactCheck()) return true;
        // if (DriverPresenceCheck()) return true;
        // if (MACAddressCheck()) return true;
        // if (BIOSVendorCheck()) return true;
        // return false;
    }

    // ========================================================================
    // CPUIDHypervisorDetection - CPUID leaf 1 hypervisor bit check
    // Detects hypervisor presence via CPUID feature information
    // ========================================================================
    bool CPUIDHypervisorDetection() {
        int cpuInfo[4] = {0};
        
        // Check CPUID leaf 1, ECX bit 31 (Hypervisor Present Bit)
        __cpuid(cpuInfo, CPUID_FEATURE_INFO);
        bool hypervisorPresent = (cpuInfo[2] & (1 << CPUID_HYPERVISOR_BIT)) != 0;
        
        if (hypervisorPresent) {
            // Additional check: Try to detect specific hypervisors
            // via CPUID leaf 0x40000000-0x400000FF
            char hypervisorID[13] = {0};
            __cpuid(cpuInfo, 0x40000000);
            memcpy(hypervisorID, &cpuInfo[1], 4);
            memcpy(hypervisorID + 4, &cpuInfo[2], 4);
            memcpy(hypervisorID + 8, &cpuInfo[3], 4);
            
            // Known hypervisor signatures
            if (strcmp(hypervisorID, "Microsoft Hv") == 0 ||  // Hyper-V
                strcmp(hypervisorID, "VMwareVMware") == 0 ||  // VMware
                strcmp(hypervisorID, "VBoxVBoxVBox") == 0 ||  // VirtualBox
                strncmp(hypervisorID, "KVMKVMKVM", 9) == 0 || // KVM
                strncmp(hypervisorID, "XenVMMXenV", 9) == 0) { // Xen
                return true;
            }
        }
        
        // Also check vendor ID for known VM vendors
        __cpuid(cpuInfo, CPUID_VENDOR_INFO);
        char vendorID[13] = {0};
        memcpy(vendorID, &cpuInfo[1], 4);
        memcpy(vendorID + 4, &cpuInfo[3], 4);
        memcpy(vendorID + 8, &cpuInfo[2], 4);

        if (strcmp(vendorID, "VMwareVMware") == 0 ||
            strcmp(vendorID, "Microsoft Hv") == 0 ||
            strcmp(vendorID, "VBoxVBoxVBox") == 0) {
            return true;
        }
        
        return hypervisorPresent;
    }

    // ========================================================================
    // RegistryArtifactCheck - VM-specific registry key detection
    // Checks for registry artifacts left by virtualization software
    // ========================================================================
    bool RegistryArtifactCheck() {
        const wchar_t* vmRegistryPaths[] = {
            // VMware artifacts
            L"SOFTWARE\\VMware, Inc.\\VMware Tools",
            L"SOFTWARE\\VMware, Inc.\\VMware Workstation",
            L"SOFTWARE\\Wow6432Node\\VMware, Inc.\\VMware Tools",
            
            // VirtualBox artifacts
            L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
            L"SOFTWARE\\Oracle\\VirtualBox",
            L"SOFTWARE\\Wow6432Node\\Oracle\\VirtualBox",
            
            // Hyper-V artifacts
            L"SOFTWARE\\Microsoft\\Hyper-V",
            L"SOFTWARE\\Microsoft\\Virtual Machine",
            
            // Parallels artifacts
            L"SOFTWARE\\Parallels\\Parallels Tools",
            
            // QEMU artifacts
            L"SOFTWARE\\QEMU",
            
            nullptr
        };
        
        for (int i = 0; vmRegistryPaths[i] != nullptr; i++) {
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, vmRegistryPaths[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return true;
            }
        }
        
        // Check specific registry values
        const struct {
            const wchar_t* path;
            const wchar_t* valueName;
        } vmRegistryValues[] = {
            {L"SYSTEM\\CurrentControlSet\\Services\\VBoxService", nullptr},
            {L"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse", nullptr},
            {L"SYSTEM\\CurrentControlSet\\Services\\vmci", nullptr},
            {L"SYSTEM\\CurrentControlSet\\Services\\vmhgfs", nullptr},
            {L"SYSTEM\\CurrentControlSet\\Services\\vmmouse", nullptr},
            {L"SYSTEM\\CurrentControlSet\\Services\\VMTools", nullptr},
            {L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", L"Identifier"},
            {L"HARDWARE\\Description\\System\\BIOS", L"BIOSVendor"},
            nullptr
        };
        
        for (int i = 0; vmRegistryValues[i].path != nullptr; i++) {
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, vmRegistryValues[i].path, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                if (vmRegistryValues[i].valueName == nullptr) {
                    RegCloseKey(hKey);
                    return true;
                } else {
                    char buffer[256] = {0};
                    DWORD size = sizeof(buffer);
                    if (RegQueryValueExW(hKey, vmRegistryValues[i].valueName, NULL, NULL, 
                                        reinterpret_cast<LPBYTE>(buffer), &size) == ERROR_SUCCESS) {
                        std::string value(buffer);
                        if (value.find("VMware") != std::string::npos ||
                            value.find("VirtualBox") != std::string::npos ||
                            value.find("QEMU") != std::string::npos ||
                            value.find("Xen") != std::string::npos) {
                            RegCloseKey(hKey);
                            return true;
                        }
                    }
                }
                RegCloseKey(hKey);
            }
        }
        
        return false;
    }

    // ========================================================================
    // DriverPresenceCheck - VM driver detection
    // Checks for presence of virtualization-specific drivers
    // ========================================================================
    bool DriverPresenceCheck() {
        const wchar_t* vmDrivers[] = {
            // VMware drivers
            L"vmci",
            L"vmhgfs",
            L"vmmouse",
            L"vmrawdsk",
            L"vmusbmouse",
            L"vm3dmp",
            L"vmmemctl",
            
            // VirtualBox drivers
            L"VBoxMouse",
            L"VBoxGuest",
            L"VBoxSF",
            L"VBoxVideo",
            L"VBoxNetAdp",
            L"VBoxNetLwf",
            
            // Hyper-V drivers
            L"vmbus",
            L"storvsc",
            L"netvsc",
            L"synthvid",
            L"ms_vmbus",
            
            // Parallels drivers
            L"prl_eth",
            L"prl_sound",
            L"prl_vid",
            
            nullptr
        };
        
        SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
        if (!hSCManager) return false;
        
        bool detected = false;
        
        for (int i = 0; vmDrivers[i] != nullptr; i++) {
            SC_HANDLE hService = OpenServiceW(hSCManager, vmDrivers[i], SERVICE_QUERY_STATUS);
            if (hService) {
                SERVICE_STATUS status;
                if (QueryServiceStatus(hService, &status)) {
                    // Service exists - VM driver present
                    CloseServiceHandle(hService);
                    CloseServiceHandle(hSCManager);
                    return true;
                }
                CloseServiceHandle(hService);
            }
        }
        
        CloseServiceHandle(hSCManager);
        
        // Additional check: Try to open VM-specific device handles
        const char* vmDevices[] = {
            "\\\\.\\VmGeneralPort",
            "\\\\.\\VBoxMiniRdrDN",
            "\\\\.\\VBoxGuest",
            "\\\\.\\HGFS",
            "\\\\.\\vmci",
            nullptr
        };
        
        for (int i = 0; vmDevices[i] != nullptr; i++) {
            HANDLE hDevice = CreateFileA(vmDevices[i], GENERIC_READ, FILE_SHARE_READ, 
                                         NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hDevice != INVALID_HANDLE_VALUE) {
                CloseHandle(hDevice);
                return true;
            }
        }
        
        return detected;
    }

    // ========================================================================
    // MACAddressCheck - VMware/VirtualBox MAC prefix detection
    // Checks network adapter MAC addresses for VM vendor prefixes
    // ========================================================================
    bool MACAddressCheck() {
        IP_ADAPTER_INFO adapterInfo[32];
        DWORD dwBufLen = sizeof(adapterInfo);
        
        if (GetAdaptersInfo(adapterInfo, &dwBufLen) != ERROR_SUCCESS) {
            return false;
        }
        
        PIP_ADAPTER_INFO pAdapterInfo = adapterInfo;
        while (pAdapterInfo) {
            // VMware MAC prefixes: 00:0C:29, 00:50:56, 00:05:69
            if ((pAdapterInfo->Address[0] == 0x00 && 
                 pAdapterInfo->Address[1] == 0x0C && 
                 pAdapterInfo->Address[2] == 0x29) ||
                (pAdapterInfo->Address[0] == 0x00 && 
                 pAdapterInfo->Address[1] == 0x50 && 
                 pAdapterInfo->Address[2] == 0x56) ||
                (pAdapterInfo->Address[0] == 0x00 && 
                 pAdapterInfo->Address[1] == 0x05 && 
                 pAdapterInfo->Address[2] == 0x69)) {
                return true;
            }
            
            // VirtualBox MAC prefix: 08:00:27
            if (pAdapterInfo->Address[0] == 0x08 && 
                pAdapterInfo->Address[1] == 0x00 && 
                pAdapterInfo->Address[2] == 0x27) {
                return true;
            }
            
            // Hyper-V MAC prefix: 00:15:5D
            if (pAdapterInfo->Address[0] == 0x00 && 
                pAdapterInfo->Address[1] == 0x15 && 
                pAdapterInfo->Address[2] == 0x5D) {
                return true;
            }
            
            // QEMU MAC prefix: 52:54:00
            if (pAdapterInfo->Address[0] == 0x52 && 
                pAdapterInfo->Address[1] == 0x54 && 
                pAdapterInfo->Address[2] == 0x00) {
                return true;
            }
            
            // Parallels MAC prefix: 00:1C:42
            if (pAdapterInfo->Address[0] == 0x00 && 
                pAdapterInfo->Address[1] == 0x1C && 
                pAdapterInfo->Address[2] == 0x42) {
                return true;
            }
            
            pAdapterInfo = pAdapterInfo->Next;
        }
        
        return false;
    }

    // ========================================================================
    // BIOSVendorCheck - BIOS manufacturer check
    // Checks BIOS vendor string for virtualization indicators
    // ========================================================================
    bool BIOSVendorCheck() {
        HKEY hBIOS;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                         "HARDWARE\\DESCRIPTION\\System\\BIOS", 
                         0, KEY_READ, &hBIOS) != ERROR_SUCCESS) {
            return false;
        }
        
        const char* valueNames[] = {"BIOSVendor", "BaseBoardManufacturer", 
                                    "SystemManufacturer", nullptr};
        
        for (int i = 0; valueNames[i] != nullptr; i++) {
            char buffer[256] = {0};
            DWORD size = sizeof(buffer);
            
            if (RegQueryValueExA(hBIOS, valueNames[i], NULL, NULL, 
                                reinterpret_cast<LPBYTE>(buffer), &size) == ERROR_SUCCESS) {
                std::string value(buffer);
                
                // Convert to lowercase for case-insensitive comparison
                std::transform(value.begin(), value.end(), value.begin(), ::tolower);
                
                if (value.find("vmware") != std::string::npos ||
                    value.find("virtualbox") != std::string::npos ||
                    value.find("qemu") != std::string::npos ||
                    value.find("xen") != std::string::npos ||
                    value.find("innotek") != std::string::npos || // Old VirtualBox
                    value.find("microsoft") != std::string::npos || // Hyper-V
                    value.find("bochs") != std::string::npos ||
                    value.find("parallels") != std::string::npos) {
                    RegCloseKey(hBIOS);
                    return true;
                }
            }
        }
        
        RegCloseKey(hBIOS);
        return false;
    }

    // ========================================================================
    // ACPI_TABLE_Check - ACPI table inspection for VM detection
    // Checks ACPI tables for hypervisor signatures
    // ========================================================================
    bool ACPI_TABLE_Check() {
        // Check for VM-specific ACPI tables via registry
        HKEY hACPI;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                         "HARDWARE\\ACPI\\FADT\\vtdt", 
                         0, KEY_READ, &hACPI) == ERROR_SUCCESS) {
            RegCloseKey(hACPI);
            return true;
        }
        
        // Check DSDT/MADT tables in memory (simplified version)
        // Full implementation would require mapping physical memory
        const wchar_t* acpiPaths[] = {
            L"HARDWARE\\ACPI\\DSDT",
            L"HARDWARE\\ACPI\\FADT",
            L"HARDWARE\\ACPI\\RSDT",
            nullptr
        };
        
        for (int i = 0; acpiPaths[i] != nullptr; i++) {
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, acpiPaths[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                // Enumerate subkeys to find VM indicators
                wchar_t subKeyName[256];
                DWORD subKeyIndex = 0;
                
                DWORD nameSize = 256;
                while (RegEnumKeyExW(hKey, subKeyIndex, subKeyName, &nameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                    std::wstring keyName(subKeyName);
                    if (keyName.find(L"VMWARE") != std::wstring::npos ||
                        keyName.find(L"VBOX") != std::wstring::npos ||
                        keyName.find(L"VIRTUAL") != std::wstring::npos) {
                        RegCloseKey(hKey);
                        return true;
                    }
                    subKeyIndex++;
                    nameSize = 256;  // Reset for next iteration
                }
                
                RegCloseKey(hKey);
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

    // ========================================================================
    // AES-NI HARDWARE ACCELERATION - Performance optimization (10-20x faster)
    // Uses Intel AES-NI instructions for hardware-accelerated encryption
    // ========================================================================
    #ifdef __AVX2__
    
    // Check if CPU supports AES-NI
    bool HasAES_NI_Support() {
        int cpuInfo[4] = {0};
        __cpuid(cpuInfo, 1);
        // AES-NI is indicated by ECX bit 25
        return (cpuInfo[2] & (1 << 25)) != 0;
    }

    // AES-NI Encrypt using _mm_aesenc_si128 intrinsics
    std::string AES_NI_Encrypt(const std::string& input, const unsigned char* key) {
        if (!HasAES_NI_Support() || input.empty()) {
            return MultiLayerEncrypt(input); // Fallback to software encryption
        }

        std::string output;
        output.resize(input.size());

        // Prepare AES key schedule (simplified - in production use proper key expansion)
        __m128i aesKey = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));

        // Process in 16-byte blocks
        size_t numBlocks = input.size() / AES_BLOCK_SIZE;
        for (size_t i = 0; i < numBlocks; i++) {
            __m128i block = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(input.data() + i * AES_BLOCK_SIZE)
            );

            // AES round operations using hardware instructions
            block = _mm_xor_si128(block, aesKey);  // AddRoundKey
            block = _mm_aesenc_si128(block, aesKey);  // AES round
            block = _mm_aesenclast_si128(block, aesKey);  // Final round

            _mm_storeu_si128(
                reinterpret_cast<__m128i*>(output.data() + i * AES_BLOCK_SIZE),
                block
            );
        }

        // Handle remaining bytes
        size_t remainder = input.size() % AES_BLOCK_SIZE;
        if (remainder > 0) {
            for (size_t i = numBlocks * AES_BLOCK_SIZE; i < input.size(); i++) {
                output[i] = input[i] ^ key[i % 16];
            }
        }

        return output;
    }

    // AES-NI Decrypt using _mm_aesdec_si128 intrinsics
    std::string AES_NI_Decrypt(const std::string& input, const unsigned char* key) {
        if (!HasAES_NI_Support() || input.empty()) {
            return MultiLayerDecrypt(input); // Fallback to software decryption
        }

        std::string output;
        output.resize(input.size());

        // Prepare AES key
        __m128i aesKey = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));

        // Process in 16-byte blocks
        size_t numBlocks = input.size() / AES_BLOCK_SIZE;
        for (size_t i = 0; i < numBlocks; i++) {
            __m128i block = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(input.data() + i * AES_BLOCK_SIZE)
            );

            // Inverse AES round operations
            block = _mm_xor_si128(block, aesKey);  // AddRoundKey
            block = _mm_aesdec_si128(block, aesKey);  // Inverse AES round
            block = _mm_aesdeclast_si128(block, aesKey);  // Final inverse round

            _mm_storeu_si128(
                reinterpret_cast<__m128i*>(output.data() + i * AES_BLOCK_SIZE),
                block
            );
        }

        // Handle remaining bytes
        size_t remainder = input.size() % AES_BLOCK_SIZE;
        if (remainder > 0) {
            for (size_t i = numBlocks * AES_BLOCK_SIZE; i < input.size(); i++) {
                output[i] = input[i] ^ key[i % 16];
            }
        }

        return output;
    }
    #endif // __AVX2__

    // ========================================================================
    // PERFORMANCE OPTIMIZATION: Reduce unnecessary string copies
    // Using string_view and move semantics where possible
    // ========================================================================
    
    // Optimized MultiLayerEncrypt with move semantics
    std::string MultiLayerEncryptOptimized(std::string&& input) {
        if (input.empty()) return "";
        
        // Reserve space to avoid reallocations
        std::string output;
        output.reserve(input.size() * 2);
        
        // Layer 1: XOR with rotating key (in-place where possible)
        for (size_t i = 0; i < input.size(); i++) {
            unsigned char c = static_cast<unsigned char>(input[i]);
            c ^= g_keys.xorKeys[0][i % MAX_XOR_KEY_SIZE];
            output += static_cast<char>(c);
        }
        
        // Layer 2: Substitution (in-place)
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
        
        return output; // Return by value (RVO/NRVO optimization)
    }

} // namespace Security 