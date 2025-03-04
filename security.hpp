#pragma once
#include <Windows.h>
#include <string>
#include <vector>

namespace Security {
    // string şifreleme için sabitler
    constexpr unsigned char XOR_KEY[] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    constexpr size_t XOR_KEY_SIZE = sizeof(XOR_KEY);

    // string şifreleme
    std::string XorEncrypt(const std::string& input);
    std::string XorDecrypt(const std::string& input);
    std::wstring XorEncryptW(const std::wstring& input);
    std::wstring XorDecryptW(const std::wstring& input);
    
    // string obfuscation
    template<size_t N>
    class SecureString {
    private:
        char data[N];
        size_t length;
        
    public:
        SecureString(const char* str) : length(strlen(str)) {
            for (size_t i = 0; i < length && i < N-1; i++) {
                data[i] = str[i] ^ XOR_KEY[i % XOR_KEY_SIZE];
            }
            data[length] = '\0';
        }
        
        std::string decrypt() {
            std::string result;
            result.reserve(length);
            for (size_t i = 0; i < length; i++) {
                result += data[i] ^ XOR_KEY[i % XOR_KEY_SIZE];
            }
            return result;
        }
    };

    // ana güvenlik kontrolü
    bool SecurityCheck();

    // antidebug fonksiyonları
    bool IsDebuggerPresentCheck();
    bool CheckDebugRegisters();
    bool CheckDebuggerTools();
    
    // antidump fonksiyonları
    void AntiDump();
    void ProtectMemory();
    
    // antivm fonksiyonları
    bool IsVirtualMachine();
    
    // kod bütünlüğü kontrolü
    bool VerifyCodeIntegrity();
    
    // gelişmiş güvenlik kontrolleri
    bool AdvancedSecurityCheck();
    
    // checksum hesaplama
    DWORD CalculateChecksum(const std::vector<BYTE>& data);
} 