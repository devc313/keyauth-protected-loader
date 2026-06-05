#pragma once
#include "includes.hpp"
#include "secure_literals.hpp"

// Şifrelenmiş lisans anahtarını registry'de saklamak için kullanılan SecureString'ler
// main.cpp'de tanımlı olmalı (extern)
namespace Security {
    class SecureStringBase; // forward decl
}

extern Security::SecureString<32> REGISTRY_PATH;
extern Security::SecureString<32> REGISTRY_KEY;

// lisans anahtarını registry'ye yaz (çok katmanlı şifreleme ile)
inline bool SaveLicenseToRegistry(const std::string& license) {
    HKEY hKey;
    char regPathBuffer[64] = {0};
    char regKeyBuffer[32] = {0};

    REGISTRY_PATH.decryptToStack(regPathBuffer, sizeof(regPathBuffer));
    REGISTRY_KEY.decryptToStack(regKeyBuffer, sizeof(regKeyBuffer));

    std::string regPath(regPathBuffer);
    std::string regKey(regKeyBuffer);

    Security::SecureZeroMemory(regPathBuffer, sizeof(regPathBuffer));
    Security::SecureZeroMemory(regKeyBuffer, sizeof(regKeyBuffer));

    LONG result = RegCreateKeyExA(HKEY_CURRENT_USER, regPath.c_str(), 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);

    if (result != ERROR_SUCCESS) {
        return false;
    }

    // Çok katmanlı şifreleme + HMAC
    std::string encryptedLicense = Security::MultiLayerEncrypt(license);

    // Base64 encode for registry storage
    static const char* base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string base64Encoded;
    base64Encoded.reserve(((encryptedLicense.size() + 2) / 3) * 4);

    for (size_t i = 0; i < encryptedLicense.size(); i += 3) {
        uint32_t octet_a = i < encryptedLicense.size() ? (unsigned char)encryptedLicense[i] : 0;
        uint32_t octet_b = i + 1 < encryptedLicense.size() ? (unsigned char)encryptedLicense[i+1] : 0;
        uint32_t octet_c = i + 2 < encryptedLicense.size() ? (unsigned char)encryptedLicense[i+2] : 0;

        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        base64Encoded += base64_chars[(triple >> 18) & 0x3F];
        base64Encoded += base64_chars[(triple >> 12) & 0x3F];
        base64Encoded += base64_chars[(triple >> 6) & 0x3F];
        base64Encoded += base64_chars[triple & 0x3F];
    }

    // Padding
    size_t mod = encryptedLicense.size() % 3;
    if (mod == 1) {
        base64Encoded[base64Encoded.size()-2] = '=';
        base64Encoded[base64Encoded.size()-1] = '=';
    } else if (mod == 2) {
        base64Encoded[base64Encoded.size()-1] = '=';
    }

    result = RegSetValueExA(hKey, regKey.c_str(), 0, REG_SZ,
        (const BYTE*)base64Encoded.c_str(), base64Encoded.length() + 1);
    RegCloseKey(hKey);

    return result == ERROR_SUCCESS;
}

// registry'den lisans anahtarını oku
inline std::string GetLicenseFromRegistry() {
    HKEY hKey;
    char buffer[1024] = {0};
    DWORD bufferSize = sizeof(buffer);
    char regPathBuffer[64] = {0};
    char regKeyBuffer[32] = {0};

    REGISTRY_PATH.decryptToStack(regPathBuffer, sizeof(regPathBuffer));
    REGISTRY_KEY.decryptToStack(regKeyBuffer, sizeof(regKeyBuffer));

    std::string regPath(regPathBuffer);
    std::string regKey(regKeyBuffer);

    Security::SecureZeroMemory(regPathBuffer, sizeof(regPathBuffer));
    Security::SecureZeroMemory(regKeyBuffer, sizeof(regKeyBuffer));

    if (RegOpenKeyExA(HKEY_CURRENT_USER, regPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return "";
    }

    if (RegQueryValueExA(hKey, regKey.c_str(), NULL, NULL, (LPBYTE)buffer, &bufferSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return "";
    }

    RegCloseKey(hKey);

    // Base64 decode
    auto base64_decode = [](const std::string& input) -> std::string {
        static const int decode_table[256] = {
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
            52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
            -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
            15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
            -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
            41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
        };

        std::string output;
        if (input.length() % 4 != 0) return "";

        size_t decoded_len = (input.length() / 4) * 3;
        if (input[input.length()-1] == '=') decoded_len--;
        if (input[input.length()-2] == '=') decoded_len--;

        output.reserve(decoded_len);

        for (size_t i = 0; i < input.length(); i += 4) {
            uint32_t sextet_a = input[i] == '=' ? 0 : decode_table[static_cast<unsigned char>(input[i])];
            uint32_t sextet_b = input[i+1] == '=' ? 0 : decode_table[static_cast<unsigned char>(input[i+1])];
            uint32_t sextet_c = input[i+2] == '=' ? 0 : decode_table[static_cast<unsigned char>(input[i+2])];
            uint32_t sextet_d = input[i+3] == '=' ? 0 : decode_table[static_cast<unsigned char>(input[i+3])];

            uint32_t triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;

            output += static_cast<char>((triple >> 16) & 0xFF);
            if (input[i+2] != '=') output += static_cast<char>((triple >> 8) & 0xFF);
            if (input[i+3] != '=') output += static_cast<char>(triple & 0xFF);
        }

        return output;
    };

    std::string decodedBase64 = base64_decode(std::string(buffer));

    Security::SecureZeroMemory(buffer, sizeof(buffer));

    return Security::MultiLayerDecrypt(decodedBase64);
}
