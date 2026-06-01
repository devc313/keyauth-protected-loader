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

namespace Security {
    // AES-256 Sabitleri
    constexpr size_t AES_KEY_SIZE = 32;
    constexpr size_t AES_BLOCK_SIZE = 16;
    constexpr size_t SALT_SIZE = 16;
    constexpr size_t HMAC_KEY_SIZE = 32;
    constexpr size_t MAX_XOR_KEY_SIZE = 64;
    constexpr size_t XOR_LAYERS = 8; // 8-katmanlı XOR şifreleme
    
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
    
    // Çok katmanlı şifreleme anahtarları (runtime generated)
    struct EncryptionKeys {
        BYTE hmacKey[HMAC_KEY_SIZE];
        BYTE xorKeys[XOR_LAYERS][MAX_XOR_KEY_SIZE];
        
        EncryptionKeys() {
            // BCrypt ile güvenli key generation
            auto rng = SecureRandom::Generate(HMAC_KEY_SIZE);
            memcpy_s(hmacKey, HMAC_KEY_SIZE, rng.data(), HMAC_KEY_SIZE);
            
            for (size_t i = 0; i < XOR_LAYERS; i++) {
                auto key = SecureRandom::Generate(MAX_XOR_KEY_SIZE);
                memcpy_s(xorKeys[i], MAX_XOR_KEY_SIZE, key.data(), MAX_XOR_KEY_SIZE);
            }
        }
        
        // Keys are automatically zeroed on destruction
        ~EncryptionKeys() {
            SecureZeroMemory(hmacKey, HMAC_KEY_SIZE);
            for (size_t i = 0; i < XOR_LAYERS; i++) {
                SecureZeroMemory(xorKeys[i], MAX_XOR_KEY_SIZE);
            }
        }
    };
    
    static EncryptionKeys g_keys;
