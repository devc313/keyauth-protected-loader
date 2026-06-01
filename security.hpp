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
#include <memory>

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
    
    // AES S-Box and Inverse S-Box for encryption
    const uint8_t S_BOX[256] = {
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
    
    const uint8_t INV_S_BOX[256] = {
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
    
    // Güvenli Rastgele Sayı Üretici (CNG) - Must be declared before EncryptionKeys
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
    
    // Çok katmanlı şifreleme anahtarları (runtime generated)
    struct EncryptionKeys {
        BYTE hmacKey[HMAC_KEY_SIZE];
        BYTE xorKeys[8][MAX_XOR_KEY_SIZE]; // 8 katmanlı XOR için
        
        EncryptionKeys() {
            auto hmacData = SecureRandom::Generate(HMAC_KEY_SIZE);
            memcpy(hmacKey, hmacData.data(), HMAC_KEY_SIZE);
            for (int i = 0; i < 8; i++) {
                auto key = SecureRandom::Generate(MAX_XOR_KEY_SIZE);
                memcpy(xorKeys[i], key.data(), MAX_XOR_KEY_SIZE);
            }
        }
    };
    
    static EncryptionKeys g_keys;
    
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
            BCryptFinishHash(hHash, outKey.data(), static_cast<ULONG>(outKey.size()), 0);
            
            // IV için tekrar hashle
            std::vector<BYTE> ivData = outKey;
            BCryptHashData(hHash, ivData.data(), static_cast<ULONG>(ivData.size()), 0);
            BCryptFinishHash(hHash, outIV.data(), static_cast<ULONG>(outIV.size()), 0);
            
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
                    (static_cast<uintptr_t>(__LINE__) * 0x27D4EB2Fu));
        }
        
        inline unsigned char deriveKey(size_t idx, uint32_t s) const {
            uint32_t k = s ^ (static_cast<uint32_t>(idx) * 0x9E3779B9u);
            k = ((k << 13) | (k >> 19)) * 0xC2B2AE35u;
            k ^= (k >> 16);
            return static_cast<unsigned char>(k & 0xFF);
        }
        
    public:
        SecureString() : seed(runtimeSeed()), length(0) {
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
        
        // Decrypt to stack buffer (for avoiding heap allocation)
        void decryptToStack(char* buffer, size_t bufferSize) {
            if (bufferSize < length + 1) return;
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
        SecureWString(const wchar_t* str) : seed(compileTimeSeed()), length(wcslen(str)) {
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
    
    // Anti-dump and memory protection
    void AntiDump();
    void ProtectMemory();
    
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
    // MULTI-LAYER ENCRYPTION (AES + XOR + HMAC)
    // ========================================================================
    std::string MultiLayerEncrypt(const std::string& input);
    std::string MultiLayerDecrypt(const std::string& input);
    std::wstring MultiLayerEncryptW(const std::wstring& input);
    std::wstring MultiLayerDecryptW(const std::wstring& input);
    
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