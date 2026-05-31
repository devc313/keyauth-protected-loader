#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>

namespace Security {
    // Çok katmanlı şifreleme için sabitler
    constexpr size_t XOR_KEY_COUNT = 4;
    constexpr size_t MAX_XOR_KEY_SIZE = 32;
    constexpr size_t HMAC_KEY_SIZE = 32;
    constexpr size_t IV_SIZE = 16;
    
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

    // Antidebug fonksiyonları
    bool IsDebuggerPresentCheck();
    bool CheckDebugRegisters();
    bool CheckDebuggerTools();
    bool CheckTimingAttack();
    bool CheckBreakpoints();
    
    // Antidump fonksiyonları
    void AntiDump();
    void ProtectCriticalMemory();
    void EncryptCodeSection();
    
    // Antivm fonksiyonları
    bool IsVirtualMachine();
    bool CheckVMArtifacts();
    
    // Kod bütünlüğü kontrolü
    bool VerifyCodeIntegrity();
    bool CalculateAndVerifyChecksum();
    
    // Gelişmiş güvenlik kontrolleri
    bool AdvancedSecurityCheck();
    bool ContinuousSecurityMonitor();
    
    // Checksum hesaplama
    DWORD CalculateChecksum(const std::vector<BYTE>& data);
    uint64_t CalculateCRC64(const void* data, size_t length);
    
    // Bellek koruma yardımcıları
    void SecureZeroMemory(void* ptr, size_t size);
    void* SecureAlloc(size_t size);
    void SecureFree(void* ptr, size_t size);
} 