#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include <random>
#include <functional>
#include <atomic>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

// ============================================================================
// CONFIGURATION & CONSTANTS
// ============================================================================

namespace SecureConfig {
    // KeyAuth.win SSL Pinning Hashes (SHA-256)
    constexpr const char* CERT_HASH[] = {
        "d7864f2520cef30934c873a7bf6e10be414ec6ae9c45d35b39b319879ed9f9ca", // Certificate
        "07d6fed49881218506064dba779b903405d56cc7826a24b15c763cc64ab98356"  // Public Key
    };
    
    constexpr const wchar_t* HOSTS_PATH = L"C:\\Windows\\System32\\drivers\\etc\\hosts";
    constexpr const wchar_t* PROXY_REG_PATH = L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    
    // Anti-Debug Timing Thresholds (nanoseconds)
    constexpr uint64_t RDTSC_THRESHOLD = 50000; 
}

// ============================================================================
// LAYER 1: COMPILE-TIME OBFUSCATION (Oxorany Style)
// ============================================================================

#define XSTR(x) #x
#define STR(x) XSTR(x)

namespace Obfuscation {
    // Compile-time random seed generator
    constexpr uint32_t CompileTimeSeed() {
        return static_cast<uint32_t>(__TIME__[7]) + 
               static_cast<uint32_t>(__TIME__[6]) * 10 +
               static_cast<uint32_t>(__TIME__[4]) * 60 +
               static_cast<uint32_t>(__TIME__[3]) * 600 +
               static_cast<uint32_t>(__TIME__[1]) * 3600 +
               static_cast<uint32_t>(__TIME__[0]) * 36000;
    }

    constexpr uint32_t SEED = CompileTimeSeed();

    // Pseudo-random number generator for compile time
    constexpr uint32_t Random(uint32_t s) {
        return (s * 1103515245 + 12345) & 0x7FFFFFFF;
    }

    // String Encryption Macro (Usage: OBFUSCATE("SecretString"))
    template <size_t N>
    struct EncryptedString {
        char data[N];
        uint32_t key;

        constexpr EncryptedString(const char* str) : key(Random(SEED ^ N)) {
            for (size_t i = 0; i < N; ++i) {
                data[i] = str[i] ^ (key + i);
            }
        }

        constexpr const char* Decrypt() {
            static char decrypted[N];
            for (size_t i = 0; i < N - 1; ++i) {
                decrypted[i] = data[i] ^ (key + i);
            }
            decrypted[N - 1] = '\0';
            return decrypted;
        }
    };
}

#define OBFUSCATE(str) []() { \
    constexpr auto encrypted = Obfuscation::EncryptedString<sizeof(str)>(str); \
    return encrypted.Decrypt(); \
}()

// ============================================================================
// LAYER 2-8: MULTI-LAYER CRYPTO ENGINE (9 Layers Total)
// ============================================================================

namespace CryptoEngine {
    // S-Box for Substitution Layer (Layer 2 & 6)
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

    // Helper: Rotate Left
    inline uint8_t RotL(uint8_t x, uint8_t n) {
        return (x << n) | (x >> (8 - n));
    }

    // Helper: Rotate Right
    inline uint8_t RotR(uint8_t x, uint8_t n) {
        return (x >> n) | (x << (8 - n));
    }

    class MultiLayerCipher {
    private:
        std::vector<uint8_t> key;
        uint64_t macKey[4]; // For simple HMAC-like tag

        void GenerateKey(const std::string& password) {
            key.resize(32);
            // Simple key derivation from password (for demo, use BCrypt in prod)
            for (size_t i = 0; i < 32; i++) {
                key[i] = (uint8_t)(password[i % password.length()] ^ (i * 7) ^ 0xAA);
            }
            
            // Generate MAC key
            for(int i=0; i<4; i++) macKey[i] = 0;
            for(size_t i=0; i<password.length(); i++) {
                macKey[i%4] ^= (uint64_t)password[i] << ((i%8)*8);
            }
        }

    public:
        MultiLayerCipher(const std::string& password) {
            GenerateKey(password);
        }

        // 9-Layer Encryption
        std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& input) {
            std::vector<uint8_t> data = input;
            size_t len = data.size();

            // Layer 1: XOR with Key Stream
            for (size_t i = 0; i < len; i++) data[i] ^= key[i % 32];

            // Layer 2: S-Box Substitution
            for (size_t i = 0; i < len; i++) data[i] = S_BOX[data[i]];

            // Layer 3: Bit Rotation (Left by 3)
            for (size_t i = 0; i < len; i++) data[i] = RotL(data[i], 3);

            // Layer 4: XOR with Inverted Key Stream
            for (size_t i = 0; i < len; i++) data[i] ^= (~key[(i + 17) % 32]);

            // Layer 5: Permutation (Swap neighbors based on index)
            for (size_t i = 0; i < len - 1; i += 2) {
                if (i % 4 == 0) std::swap(data[i], data[i+1]);
            }

            // Layer 6: Second S-Box (Inverse direction logic for complexity)
            for (size_t i = 0; i < len; i++) data[i] = S_BOX[data[i] ^ (i % 256)];

            // Layer 7: Bit Flip (Every 5th bit)
            for (size_t i = 0; i < len; i++) data[i] ^= (i % 5 == 0 ? 0x20 : 0x00);

            // Layer 8: Final Rotation (Right by 2)
            for (size_t i = 0; i < len; i++) data[i] = RotR(data[i], 2);

            // Layer 9: Append Simple MAC Tag (4 bytes)
            uint32_t mac = 0;
            for (size_t i = 0; i < len; i++) mac += data[i] * (i + 1);
            mac ^= (uint32_t)macKey[0];
            
            data.push_back((mac >> 24) & 0xFF);
            data.push_back((mac >> 16) & 0xFF);
            data.push_back((mac >> 8) & 0xFF);
            data.push_back(mac & 0xFF);

            return data;
        }

        // 9-Layer Decryption
        std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& input) {
            if (input.size() < 4) return {}; // Too short for MAC

            std::vector<uint8_t> data(input.begin(), input.end() - 4);
            size_t len = data.size();

            // Verify MAC (Layer 9 Check)
            uint32_t expectedMac = 0;
            for (size_t i = 0; i < len; i++) expectedMac += data[i] * (i + 1);
            expectedMac ^= (uint32_t)macKey[0];

            uint32_t receivedMac = 
                (input[len] << 24) | (input[len+1] << 16) | 
                (input[len+2] << 8) | input[len+3];

            if (expectedMac != receivedMac) {
                // Integrity failure - clear memory and return empty
                SecureZeroMemory(data.data(), data.size());
                return {};
            }

            // Reverse Layer 8: Rotation Right -> Left
            for (size_t i = 0; i < len; i++) data[i] = RotL(data[i], 2);

            // Reverse Layer 7: Bit Flip
            for (size_t i = 0; i < len; i++) data[i] ^= (i % 5 == 0 ? 0x20 : 0x00);

            // Reverse Layer 6: S-Box
            for (size_t i = 0; i < len; i++) data[i] = INV_S_BOX[data[i] ^ (i % 256)];

            // Reverse Layer 5: Permutation
            for (size_t i = 0; i < len - 1; i += 2) {
                if (i % 4 == 0) std::swap(data[i], data[i+1]);
            }

            // Reverse Layer 4: XOR Inverted Key
            for (size_t i = 0; i < len; i++) data[i] ^= (~key[(i + 17) % 32]);

            // Reverse Layer 3: Rotation Left -> Right
            for (size_t i = 0; i < len; i++) data[i] = RotR(data[i], 3);

            // Reverse Layer 2: Inverse S-Box
            for (size_t i = 0; i < len; i++) data[i] = INV_S_BOX[data[i]];

            // Reverse Layer 1: XOR Key
            for (size_t i = 0; i < len; i++) data[i] ^= key[i % 32];

            return data;
        }
    };
}

// ============================================================================
// LAYER 9: CONTROL FLOW FLATTENING & OPAQUE PREDICATES (Cloakwork Style)
// ============================================================================

namespace ControlFlow {
    // Opaque Predicate: Always returns true but looks complex to static analysis
    inline bool AlwaysTrue() {
        volatile int a = 1;
        volatile int b = 2;
        volatile int c = a + b;
        return (c == 3) && ((a ^ b) == 3);
    }

    // Opaque Predicate: Always returns false
    inline bool AlwaysFalse() {
        volatile int a = 1;
        volatile int b = 1;
        return (a == b) && ((a & b) == 0);
    }

    // Control Flow Flattening Dispatcher
    template<typename Func>
    void ExecuteFlattened(Func f) {
        int state = 0;
        while (true) {
            switch (state) {
                case 0:
                    if (AlwaysTrue()) state = 1;
                    else state = 99; // Dead code
                    break;
                case 1:
                    f();
                    state = 2;
                    break;
                case 2:
                    if (!AlwaysFalse()) state = 3;
                    else state = 99;
                    break;
                case 3:
                    return;
                default:
                    return; // Should never reach here
            }
        }
    }
}

// ============================================================================
// ANTI-ANALYSIS & SYSTEM INTEGRITY
// ============================================================================

namespace SecurityGuard {
    
    // 1. Hosts File Check
    inline bool IsHostsModified() {
        HANDLE hFile = CreateFileW(SecureConfig::HOSTS_PATH, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize > 10000) { // Suspiciously large hosts file
            CloseHandle(hFile);
            return true;
        }

        std::vector<char> buffer(fileSize);
        DWORD bytesRead;
        ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL);
        CloseHandle(hFile);

        std::string content(buffer.begin(), buffer.end());
        // Check for common blocklist entries
        std::vector<std::string> dangerous = {"keyauth", "cheater", "block", "127.0.0.1"};
        for (const auto& word : dangerous) {
            if (content.find(word) != std::string::npos) return true;
        }
        return false;
    }

    // 2. Proxy Check
    inline bool IsProxyEnabled() {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, SecureConfig::PROXY_REG_PATH, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD proxyEnable = 0;
            DWORD size = sizeof(proxyEnable);
            if (RegQueryValueExW(hKey, L"ProxyEnable", NULL, NULL, (LPBYTE)&proxyEnable, &size) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return (proxyEnable == 1);
            }
            RegCloseKey(hKey);
        }
        return false;
    }

    // 3. Debugger Detection (Advanced)
    inline bool IsDebuggerPresent_Advanced() {
        if (IsDebuggerPresent()) return true;
        
        // Check RemoteDebugger
        PROCESS_BASIC_INFORMATION pbi;
        NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
        if (status == 0 && pbi.Reserved3 != 0) return true;

        // Timing Check (RDTSC)
        uint64_t start = __rdtsc();
        for (volatile int i = 0; i < 1000; i++);
        uint64_t end = __rdtsc();
        
        if ((end - start) > SecureConfig::RDTSC_THRESHOLD) return true;

        return false;
    }

    // 4. VM Detection (Basic BIOS/Registry)
    inline bool IsVirtualMachine() {
        HKEY hKey;
        // Check for VMware tools registry key
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
        
        // Check for VirtualBox Guest Additions
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
        return false;
    }

    // 5. SSL Pinning Implementation
    inline bool VerifyCertificate(HINTERNET hRequest) {
        // Note: Full implementation requires WinHTTP context flags
        // This is a logic placeholder for the pinning mechanism
        // In real usage, you'd query CERT_CONTEXT and hash it with BCrypt
        
        // Simulating the check against hardcoded hashes
        // If the hash of the server cert doesn't match SecureConfig::CERT_HASH[0] or [1] -> Terminate
        return true; // Placeholder: Real implementation needs async HTTP handle
    }
}

// ============================================================================
// SECURE STRING CLASS (Runtime Decryption)
// ============================================================================

class SecureString {
private:
    std::vector<char> encryptedData;
    CryptoEngine::MultiLayerCipher& cipher;
    bool isDecrypted;

public:
    SecureString(const char* str, CryptoEngine::MultiLayerCipher& c) : cipher(c), isDecrypted(false) {
        std::vector<uint8_t> raw(str, str + strlen(str));
        encryptedData.resize(raw.size());
        // Initial encrypt at construction
        auto enc = cipher.Encrypt(raw);
        encryptedData.assign(enc.begin(), enc.end());
    }

    ~SecureString() {
        if (!encryptedData.empty()) {
            SecureZeroMemory(encryptedData.data(), encryptedData.size());
        }
    }

    std::string Get() {
        if (isDecrypted) {
            // Return cached if already decrypted (risky but fast)
            // Better: Re-decrypt every time or use scoped unlock
             std::vector<uint8_t> dec = cipher.Decrypt(std::vector<uint8_t>(encryptedData.begin(), encryptedData.end()));
             return std::string(dec.begin(), dec.end());
        }
        
        std::vector<uint8_t> dec = cipher.Decrypt(std::vector<uint8_t>(encryptedData.begin(), encryptedData.end()));
        if (dec.empty()) return ""; // Integrity fail
        
        return std::string(dec.begin(), dec.end());
    }
};

// ============================================================================
// MACROS FOR EASY USAGE
// ============================================================================

#define SECURE_INIT(key) CryptoEngine::MultiLayerCipher crypto(key);
#define SECURE_STR(str) SecureString(OBFUSCATE(str), crypto)
#define CHECK_SECURITY() if (SecurityGuard::IsDebuggerPresent_Advanced() || SecurityGuard::IsVirtualMachine() || SecurityGuard::IsHostsModified() || SecurityGuard::IsProxyEnabled()) { ExitProcess(1); }
#define RUN_PROTECTED(code) ControlFlow::ExecuteFlattened([&]() { code; })

// ============================================================================
// EXAMPLE USAGE
// ============================================================================
/*
int main() {
    // Initialize Security Core
    SECURE_INIT("MySuperSecretAppKey123!");

    // Run Integrity Checks
    CHECK_SECURITY();

    // Use Obfuscated Strings
    RUN_PROTECTED({
        std::string apiEndpoint = SECURE_STR("https://keyauth.win/api/");
        std::string secretMsg = SECURE_STR("Sensitive Data Loaded");
        
        // Output (in real app, send to API)
        printf("Endpoint: %s\n", apiEndpoint.c_str());
        printf("Message: %s\n", secretMsg.c_str());
    });

    return 0;
}
*/
