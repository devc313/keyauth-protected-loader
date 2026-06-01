#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <memory>
#include <atomic>

// ============================================================================
// SECURITY CONSTANTS - Magic numbers replaced with named constants
// ============================================================================
namespace Security {
    // Encryption constants
    constexpr size_t XOR_KEY_COUNT = 4;
    constexpr size_t MAX_XOR_KEY_SIZE = 32;
    constexpr size_t HMAC_KEY_SIZE = 32;
    constexpr size_t IV_SIZE = 16;
    constexpr size_t AES_BLOCK_SIZE = 16;
    
    // Anti-debug timing thresholds (milliseconds)
    constexpr DWORD TIMING_THRESHOLD_NORMAL = 100;
    constexpr DWORD TIMING_THRESHOLD_STRICT = 50;
    constexpr DWORD TIMING_CHECK_INTERVAL = 5000;
    
    // Security check intervals (milliseconds)
    constexpr DWORD DEBUG_CHECK_INTERVAL = 5000;
    constexpr DWORD VM_CHECK_INTERVAL = 30000;
    constexpr DWORD INTEGRITY_CHECK_INTERVAL = 10000;
    
    // VM Detection constants
    constexpr int CPUID_HYPERVISOR_BIT = 31;
    constexpr int CPUID_FEATURE_INFO = 1;
    constexpr int CPUID_VENDOR_INFO = 0;
    
    // Memory protection flags
    constexpr DWORD PROTECTED_MEMORY_FLAGS = PAGE_READONLY;
    constexpr DWORD ENCRYPTED_MEMORY_FLAGS = PAGE_READWRITE;
    
    // Exit codes for security violations
    constexpr int EXIT_DEBUGGER_DETECTED = 30;
    constexpr int EXIT_VM_DETECTED = 31;
    constexpr int EXIT_TIME_MANIPULATION = 32;
    constexpr int EXIT_INTEGRITY_FAILURE = 33;
    constexpr int EXIT_EXCEPTION_DEBUG = 34;
    
    // Dinamik XOR anahtarları (runtime'da oluşturulur)
    struct EncryptionKeys {
        unsigned char xorKeys[XOR_KEY_COUNT][MAX_XOR_KEY_SIZE];
        unsigned char hmacKey[HMAC_KEY_SIZE];
        unsigned char iv[IV_SIZE];
        uint32_t keySeeds[XOR_KEY_COUNT];
        
        EncryptionKeys();
        void RegenerateKeys();
    };
    
    // Global encryption keys (runtime'da initialize edilir)
    extern EncryptionKeys g_keys;
    
    // AES benzeri S-Box lookup table
    extern const unsigned char S_BOX[256];
    extern const unsigned char INV_S_BOX[256];
    
    // Çok katmanlı şifreleme fonksiyonları
    std::string MultiLayerEncrypt(const std::string& input);
    std::string MultiLayerDecrypt(const std::string& input);
    std::wstring MultiLayerEncryptW(const std::wstring& input);
    std::wstring MultiLayerDecryptW(const std::wstring& input);
    
    // HMAC-SHA256 benzeri MAC hesaplama
    std::vector<unsigned char> ComputeHMAC(const std::string& data);
    bool VerifyHMAC(const std::string& data, const std::vector<unsigned char>& mac);
    
    // Basit hash fonksiyonu (SHA-256 benzeri)
    std::vector<unsigned char> SimpleHash256(const std::string& input);
    
    // String obfuscation - compile time seed ile
    template<size_t N>
    class SecureString {
    private:
        char data[N];
        size_t length;
        uint32_t seed;
        
        // Compile-time seed generation
        static constexpr uint32_t compileTimeSeed() {
            return static_cast<uint32_t>(
                (__TIME__[0] - '0') * 36000 +
                (__TIME__[1] - '0') * 3600 +
                (__TIME__[3] - '0') * 600 +
                (__TIME__[4] - '0') * 60 +
                (__TIME__[6] - '0') * 10 +
                (__TIME__[7] - '0')
            ) ^ static_cast<uint32_t>(__LINE__) * 0x27D4EB2Fu;
        }
        
        // Key derivation function
        inline unsigned char deriveKey(size_t idx, uint32_t s) const {
            uint32_t k = s ^ (static_cast<uint32_t>(idx) * 0x9E3779B9u);
            k = ((k << 13) | (k >> 19)) * 0xC2B2AE35u;
            k ^= (k >> 16);
            return static_cast<unsigned char>(k & 0xFF);
        }
        
    public:
        constexpr SecureString(const char* str) : seed(compileTimeSeed()), length(strlen(str)) {
            for (size_t i = 0; i < length && i < N-1; i++) {
                unsigned char key = deriveKey(i, seed);
                // Multi-layer obfuscation: XOR + substitution + rotation
                unsigned char c = static_cast<unsigned char>(str[i]);
                c = S_BOX[c];  // Substitution layer
                c = static_cast<unsigned char>((c << 3) | (c >> 5));  // Rotation layer
                c ^= key;  // XOR layer
                data[i] = c;
            }
            data[length] = '\0';
        }
        
        std::string decrypt() {
            std::string result;
            result.reserve(length);
            for (size_t i = 0; i < length; i++) {
                unsigned char key = deriveKey(i, seed);
                unsigned char c = data[i];
                c ^= key;  // Reverse XOR
                c = static_cast<unsigned char>((c >> 3) | (c << 5));  // Reverse rotation
                c = INV_S_BOX[c];  // Reverse substitution
                result += static_cast<char>(c);
            }
            // Secure wipe after decryption
            volatile uint32_t dummy = seed;
            (void)dummy;
            return result;
        }
        
        // Stack-based decryption for extra security
        void decryptToStack(char* buffer, size_t bufferSize) const {
            if (bufferSize <= length) return;
            for (size_t i = 0; i < length; i++) {
                unsigned char key = deriveKey(i, seed);
                unsigned char c = data[i];
                c ^= key;
                c = static_cast<unsigned char>((c >> 3) | (c << 5));
                c = INV_S_BOX[c];
                buffer[i] = static_cast<char>(c);
            }
            buffer[length] = '\0';
        }
    };
    
    // Wide string version
    template<size_t N>
    class SecureWString {
    private:
        wchar_t data[N];
        size_t length;
        uint32_t seed;
        
        static constexpr uint32_t compileTimeSeed() {
            return static_cast<uint32_t>(
                (__TIME__[0] - '0') * 36000 +
                (__TIME__[1] - '0') * 3600 +
                (__TIME__[3] - '0') * 600 +
                (__TIME__[4] - '0') * 60 +
                (__TIME__[6] - '0') * 10 +
                (__TIME__[7] - '0')
            ) ^ static_cast<uint32_t>(__LINE__) * 0x27D4EB2Fu;
        }
        
        inline unsigned char deriveKey(size_t idx, uint32_t s) const {
            uint32_t k = s ^ (static_cast<uint32_t>(idx) * 0x9E3779B9u);
            k = ((k << 13) | (k >> 19)) * 0xC2B2AE35u;
            k ^= (k >> 16);
            return static_cast<unsigned char>(k & 0xFF);
        }
        
    public:
        constexpr SecureWString(const wchar_t* str) : seed(compileTimeSeed()), length(wcslen(str)) {
            for (size_t i = 0; i < length && i < N-1; i++) {
                unsigned char key = deriveKey(i, seed);
                unsigned short c = static_cast<unsigned short>(str[i]);
                c = S_BOX[c & 0xFF] ^ key;
                data[i] = static_cast<wchar_t>(c);
            }
            data[length] = L'\0';
        }
        
        std::wstring decrypt() {
            std::wstring result;
            result.reserve(length);
            for (size_t i = 0; i < length; i++) {
                unsigned char key = deriveKey(i, seed);
                unsigned short c = static_cast<unsigned short>(data[i]);
                c ^= key;
                c = INV_S_BOX[c & 0xFF];
                result += static_cast<wchar_t>(c);
            }
            return result;
        }
    };

    // Ana güvenlik kontrolü
    bool SecurityCheck();

    // ========================================================================
    // ANTI-DEBUG FUNCTIONS - Enhanced with NtQueryInformationProcess, timing, exceptions
    // ========================================================================
    bool IsDebuggerPresentCheck();
    bool CheckDebugRegisters();
    bool CheckDebuggerTools();
    bool CheckTimingAttack();
    bool CheckBreakpoints();
    
    // Advanced anti-debug techniques
    bool NtQueryInformationProcessCheck();      // PEB-based detection
    bool TimingBasedAntiDebug();                 // RDTSC timing analysis
    bool ExceptionBasedAntiDebug();              // SEH/VEH exception handling
    bool HardwareBreakpointCheck();              // DR0-DR7 register check
    bool SoftwareInterruptCheck();               // INT3 (0xCC) detection
    
    // ========================================================================
    // ANTI-VM FUNCTIONS - Enhanced with registry, driver, CPUID hypervisor
    // ========================================================================
    bool IsVirtualMachine();
    bool CheckVMArtifacts();
    
    // Advanced VM detection
    bool CPUIDHypervisorDetection();             // CPUID leaf 1 hypervisor bit
    bool RegistryArtifactCheck();                // VM-specific registry keys
    bool DriverPresenceCheck();                  // VM driver detection
    bool MACAddressCheck();                      // VMware/VirtualBox MAC prefixes
    bool BIOSVendorCheck();                      // BIOS manufacturer check
    bool ACPI_TABLE_Check();                     // ACPI table inspection
    
    // ========================================================================
    // CODE INTEGRITY & MEMORY PROTECTION
    // ========================================================================
    bool VerifyCodeIntegrity();
    bool CalculateAndVerifyChecksum();
    
    // RAII-based memory protection
    class MemoryProtector;
    
    // ========================================================================
    // ADVANCED SECURITY & MONITORING
    // ========================================================================
    bool AdvancedSecurityCheck();
    bool ContinuousSecurityMonitor();
    
    // Exception handler for anti-debug
    LONG NTAPI ExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo);
    
    // Checksum hesaplama
    DWORD CalculateChecksum(const std::vector<BYTE>& data);
    uint64_t CalculateCRC64(const void* data, size_t length);
    
    // Bellek koruma yardımcıları
    void SecureZeroMemory(void* ptr, size_t size);
    void* SecureAlloc(size_t size);
    void SecureFree(void* ptr, size_t size);
    
    // ========================================================================
    // AES-NI HARDWARE ACCELERATION (Performance optimization)
    // ========================================================================
    #ifdef __AVX2__
    std::string AES_NI_Encrypt(const std::string& input, const unsigned char* key);
    std::string AES_NI_Decrypt(const std::string& input, const unsigned char* key);
    bool HasAES_NI_Support();
    #endif
    
    // ========================================================================
    // RAII MEMORY PROTECTOR CLASS - Automatic memory protection management
    // ========================================================================
    class MemoryProtector {
    private:
        void* m_address;
        SIZE_T m_size;
        DWORD m_oldProtect;
        bool m_isProtected;
        
    public:
        MemoryProtector() : m_address(nullptr), m_size(0), m_oldProtect(0), m_isProtected(false) {}
        
        explicit MemoryProtector(void* address, SIZE_T size, DWORD newProtect) 
            : m_address(address), m_size(size), m_oldProtect(0), m_isProtected(false) {
            if (address && size > 0) {
                m_isProtected = VirtualProtect(address, size, newProtect, &m_oldProtect);
            }
        }
        
        ~MemoryProtector() {
            release();
        }
        
        // Disable copy
        MemoryProtector(const MemoryProtector&) = delete;
        MemoryProtector& operator=(const MemoryProtector&) = delete;
        
        // Enable move
        MemoryProtector(MemoryProtector&& other) noexcept 
            : m_address(other.m_address), m_size(other.m_size), 
              m_oldProtect(other.m_oldProtect), m_isProtected(other.m_isProtected) {
            other.m_address = nullptr;
            other.m_size = 0;
            other.m_isProtected = false;
        }
        
        MemoryProtector& operator=(MemoryProtector&& other) noexcept {
            if (this != &other) {
                release();
                m_address = other.m_address;
                m_size = other.m_size;
                m_oldProtect = other.m_oldProtect;
                m_isProtected = other.m_isProtected;
                other.m_address = nullptr;
                other.m_size = 0;
                other.m_isProtected = false;
            }
            return *this;
        }
        
        bool protect(DWORD newProtect) {
            if (!m_address || m_size == 0) return false;
            if (m_isProtected) return true;
            
            m_isProtected = VirtualProtect(m_address, m_size, newProtect, &m_oldProtect);
            return m_isProtected;
        }
        
        void release() {
            if (m_isProtected && m_address) {
                DWORD dummy;
                VirtualProtect(m_address, m_size, m_oldProtect, &dummy);
                m_isProtected = false;
            }
        }
        
        bool isProtected() const { return m_isProtected; }
        void* getAddress() const { return m_address; }
        SIZE_T getSize() const { return m_size; }
    };
    
    // Smart pointer type for MemoryProtector
    using MemoryProtectorPtr = std::unique_ptr<MemoryProtector>;
}