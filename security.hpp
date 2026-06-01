#pragma once
#include <Windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <random>

// BCrypt library linkage
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

// ============================================================================
// SECURITY CONSTANTS - Magic numbers replaced with named constants
// ============================================================================
namespace Security {
    // AES-256 Sabitleri
    constexpr size_t AES_KEY_SIZE = 32;
    constexpr size_t AES_BLOCK_SIZE = 16;
    constexpr size_t SALT_SIZE = 16;
    constexpr size_t HMAC_KEY_SIZE = 32;
    constexpr size_t MAX_XOR_KEY_SIZE = 64;
    
    // Çok katmanlı şifreleme anahtarları (runtime generated)
    struct EncryptionKeys {
        BYTE hmacKey[HMAC_KEY_SIZE];
        BYTE xorKeys[8][MAX_XOR_KEY_SIZE]; // 8 katmanlı XOR için
        
        EncryptionKeys() {
            SecureRandom::Generate(HMAC_KEY_SIZE).copy(hmacKey, HMAC_KEY_SIZE);
            for (int i = 0; i < 8; i++) {
                auto key = SecureRandom::Generate(MAX_XOR_KEY_SIZE);
                key.copy(xorKeys[i], MAX_XOR_KEY_SIZE);
            }
        }
    };
    
    static EncryptionKeys g_keys;
    
    // Güvenli Rastgele Sayı Üretici (CNG)
    class SecureRandom {
    public:
        static std::vector<BYTE> Generate(size_t length) {
            std::vector<BYTE> buffer(length);
            BCRYPT_ALG_HANDLE hAlg = NULL;
            NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, NULL, 0);
            
            if (!BCRYPT_SUCCESS(status)) {
                throw std::runtime_error("BCryptOpenAlgorithmProvider failed");
            }

            status = BCryptGenRandom(hAlg, buffer.data(), static_cast<ULONG>(length), 0);
            BCryptCloseAlgorithmProvider(hAlg, 0);

            if (!BCRYPT_SUCCESS(status)) {
                throw std::runtime_error("BCryptGenRandom failed");
            }

            return buffer;
        }
        
        // RDRAND tabanlı hızlı rastgele (Intel/AMD)
        static UINT64 GetRDRAND() {
            UINT64 val;
            int retry = 10;
            while (_rdrand64_step(&val) == 0 && --retry > 0) {}
            return val;
        }
    };
    
    /**
     * @brief AES-256 CBC Şifreleme Sınıfı
     * BCrypt API kullanarak güvenli şifreleme yapar
     */
    class AESCrypt {
    public:
        // Anahtar türetme (PBKDF2 benzeri basit KDF)
        static void DeriveKey(const std::string& password, const std::vector<BYTE>& salt, 
                             std::vector<BYTE>& outKey, std::vector<BYTE>& outIV) {
            BCRYPT_ALG_HANDLE hAlg = NULL;
            BCRYPT_HASH_HANDLE hHash = NULL;
            BYTE hashObj[1024];
            
            outKey.resize(AES_KEY_SIZE);
            outIV.resize(AES_BLOCK_SIZE);
            
            NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
            if (!BCRYPT_SUCCESS(status)) throw std::runtime_error("Hash Alg Open Failed");
            
            status = BCryptCreateHash(hAlg, &hHash, hashObj, sizeof(hashObj), NULL, 0, 0);
            if (!BCRYPT_SUCCESS(status)) {
                BCryptCloseAlgorithmProvider(hAlg, 0);
                throw std::runtime_error("Hash Create Failed");
            }
            
            // Password + Salt hashle
            std::vector<BYTE> data(password.begin(), password.end());
            data.insert(data.end(), salt.begin(), salt.end());
            BCryptHashData(hHash, data.data(), static_cast<ULONG>(data.size()), 0);
            
            DWORD hashLen = 0;
            BCryptFinishHash(hHash, outKey.data(), static_cast<ULONG>(outKey.size()), &hashLen);
            
            // IV için tekrar hashle
            std::vector<BYTE> ivData = outKey;
            BCryptHashData(hHash, ivData.data(), static_cast<ULONG>(ivData.size()), 0);
            BCryptFinishHash(hHash, outIV.data(), static_cast<ULONG>(outIV.size()), &hashLen);
            
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
        }
        
        static std::string Encrypt(const std::string& plaintext, const std::string& password) {
            auto salt = SecureRandom::Generate(SALT_SIZE);
            std::vector<BYTE> key, iv;
            DeriveKey(password, salt, key, iv);
            
            BCRYPT_ALG_HANDLE hAlg = NULL;
            BCRYPT_KEY_HANDLE hKey = NULL;
            BYTE keyObj[2048];
            
            NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
            if (!BCRYPT_SUCCESS(status)) throw std::runtime_error("AES Alg Open Failed");
            
            status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, 
                                       (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
            if (!BCRYPT_SUCCESS(status)) {
                BCryptCloseAlgorithmProvider(hAlg, 0);
                throw std::runtime_error("AES Mode Set Failed");
            }
            
            status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj, sizeof(keyObj), 
                                                key.data(), static_cast<ULONG>(key.size()), 0);
            if (!BCRYPT_SUCCESS(status)) {
                BCryptCloseAlgorithmProvider(hAlg, 0);
                throw std::runtime_error("Key Gen Failed");
            }
            
            // PKCS7 Padding
            size_t paddedLen = plaintext.length() + (AES_BLOCK_SIZE - (plaintext.length() % AES_BLOCK_SIZE));
            std::vector<BYTE> paddedData(paddedLen);
            memcpy_s(paddedData.data(), paddedData.size(), plaintext.c_str(), plaintext.length());
            BYTE padValue = static_cast<BYTE>(AES_BLOCK_SIZE - (plaintext.length() % AES_BLOCK_SIZE));
            for (size_t i = plaintext.length(); i < paddedLen; ++i)
                paddedData[i] = padValue;
            
            DWORD cipherLen = 0;
            status = BCryptEncrypt(hKey, paddedData.data(), static_cast<ULONG>(paddedData.size()), 
                                   NULL, iv.data(), static_cast<ULONG>(iv.size()), 
                                   NULL, 0, &cipherLen, 0);
            std::vector<BYTE> cipherText(cipherLen);
            status = BCryptEncrypt(hKey, paddedData.data(), static_cast<ULONG>(paddedData.size()), 
                                   NULL, iv.data(), static_cast<ULONG>(iv.size()), 
                                   cipherText.data(), static_cast<ULONG>(cipherText.size()), &cipherLen, 0);
            
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            
            if (!BCRYPT_SUCCESS(status)) throw std::runtime_error("Encryption Failed");
            
            // Hex encode: Salt + IV + CipherText
            std::ostringstream oss;
            for (BYTE b : salt) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
            for (BYTE b : iv) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
            for (BYTE b : cipherText) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
            return oss.str();
        }
        
        static std::string Decrypt(const std::string& hexData, const std::string& password) {
            auto hexToBytes = [](const std::string& hex) -> std::vector<BYTE> {
                std::vector<BYTE> bytes(hex.length() / 2);
                for (size_t i = 0; i < hex.length(); i += 2)
                    bytes[i / 2] = static_cast<BYTE>(std::stoi(hex.substr(i, 2), nullptr, 16));
                return bytes;
            };
            
            std::vector<BYTE> raw = hexToBytes(hexData);
            if (raw.size() < SALT_SIZE + AES_BLOCK_SIZE) throw std::runtime_error("Invalid data");
            
            std::vector<BYTE> salt(raw.begin(), raw.begin() + SALT_SIZE);
            std::vector<BYTE> iv(raw.begin() + SALT_SIZE, raw.begin() + SALT_SIZE + AES_BLOCK_SIZE);
            std::vector<BYTE> cipherText(raw.begin() + SALT_SIZE + AES_BLOCK_SIZE, raw.end());
            
            std::vector<BYTE> key;
            DeriveKey(password, salt, key, iv);
            
            BCRYPT_ALG_HANDLE hAlg = NULL;
            BCRYPT_KEY_HANDLE hKey = NULL;
            BYTE keyObj[2048];
            
            NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
            if (!BCRYPT_SUCCESS(status)) throw std::runtime_error("AES Alg Open Failed");
            
            status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, 
                                       (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
            if (!BCRYPT_SUCCESS(status)) {
                BCryptCloseAlgorithmProvider(hAlg, 0);
                throw std::runtime_error("AES Mode Set Failed");
            }
            
            status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj, sizeof(keyObj), 
                                                key.data(), static_cast<ULONG>(key.size()), 0);
            if (!BCRYPT_SUCCESS(status)) {
                BCryptCloseAlgorithmProvider(hAlg, 0);
                throw std::runtime_error("Key Gen Failed");
            }
            
            DWORD plainLen = 0;
            status = BCryptDecrypt(hKey, cipherText.data(), static_cast<ULONG>(cipherText.size()), 
                                   NULL, iv.data(), static_cast<ULONG>(iv.size()), 
                                   NULL, 0, &plainLen, 0);
            std::vector<BYTE> plainText(plainLen);
            status = BCryptDecrypt(hKey, cipherText.data(), static_cast<ULONG>(cipherText.size()), 
                                   NULL, iv.data(), static_cast<ULONG>(iv.size()), 
                                   plainText.data(), static_cast<ULONG>(plainText.size()), &plainLen, 0);
            
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            
            if (!BCRYPT_SUCCESS(status)) throw std::runtime_error("Decryption Failed");
            
            // Unpad
            BYTE padValue = plainText[plainLen - 1];
            if (padValue > AES_BLOCK_SIZE) throw std::runtime_error("Invalid padding");
            return std::string(plainText.begin(), plainText.begin() + (plainLen - padValue));
        }
    };
    
    /**
     * @brief Güvenli String Sınıfı - Hafızada şifreli tutar
     */
    template<size_t N>
    class SecureString {
    private:
        char data[N];
        size_t length;
        uint32_t seed;
        
        // Runtime seed generation with RDRAND
        static uint32_t runtimeSeed() {
            return static_cast<uint32_t>(SecureRandom::GetRDRAND() ^ 
                    (reinterpret_cast<uintptr_t>(&data) & 0xFFFFFFFF));
        }
        
        inline unsigned char deriveKey(size_t idx, uint32_t s) const {
            uint32_t k = s ^ (static_cast<uint32_t>(idx) * 0x9E3779B9u);
            k = ((k << 13) | (k >> 19)) * 0xC2B2AE35u;
            k ^= (k >> 16);
            return static_cast<unsigned char>(k & 0xFF);
        }
        
    public:
        constexpr SecureString() : seed(runtimeSeed()), length(0) {
            memset(data, 0, N);
        }
        
        SecureString(const char* str) : seed(runtimeSeed()), length(strlen(str)) {
            if (length >= N) length = N - 1;
            for (size_t i = 0; i < length; i++) {
                unsigned char key = deriveKey(i, seed);
                unsigned char c = static_cast<unsigned char>(str[i]);
                c = S_BOX[c];
                c = static_cast<unsigned char>((c << 3) | (c >> 5));
                c ^= key;
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
                c ^= key;
                c = static_cast<unsigned char>((c >> 3) | (c << 5));
                c = INV_S_BOX[c];
                result += static_cast<char>(c);
            }
            return result;
        }
        
        void clear() {
            SecureZeroMemory(data, N);
            length = 0;
        }
        
        ~SecureString() {
            clear();
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