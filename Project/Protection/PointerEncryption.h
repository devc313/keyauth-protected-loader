/*
 * PointerEncryption.h - Dynamic Pointer Encryption System
 * Encrypts function pointers and decrypts them at runtime with server-provided keys.
 * Inspired by Fatality's protection mechanisms.
 */

#pragma once

#include <windows.h>
#include <cstdint>
#include <unordered_map>
#include <functional>
#include <random>

class PointerEncryption {
private:
    // Encrypted pointer storage
    struct EncryptedEntry {
        uintptr_t encryptedPtr;
        uint64_t key;
        bool isValid;
    };

    std::unordered_map<std::string, EncryptedEntry> _encryptedPointers;
    uint64_t _masterKey;

    // Generate a random 64-bit key
    static uint64_t GenerateKey() {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        return gen();
    }

    // XOR-based encryption for pointers
    static uintptr_t EncryptPointer(void* ptr, uint64_t key) {
        uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
        // Multi-layer encryption: XOR + rotation + XOR
        addr ^= key;
        addr = ((addr << 13) | (addr >> 51)) & 0xFFFFFFFFFFFFFFFF;
        addr ^= (key >> 32);
        addr = ((addr << 7) | (addr >> 57)) & 0xFFFFFFFFFFFFFFFF;
        return addr;
    }

    static void* DecryptPointer(uintptr_t encrypted, uint64_t key) {
        uintptr_t addr = encrypted;
        // Reverse the encryption layers
        addr = ((addr << 7) | (addr >> 57)) & 0xFFFFFFFFFFFFFFFF;
        addr ^= (key >> 32);
        addr = ((addr >> 13) | (addr << 51)) & 0xFFFFFFFFFFFFFFFF;
        addr ^= key;
        return reinterpret_cast<void*>(addr);
    }

public:
    PointerEncryption() : _masterKey(GenerateKey()) {}

    // Encrypt a function pointer with a unique ID
    void EncryptFunction(const std::string& id, void* funcPtr) {
        if (!funcPtr) return;

        uint64_t key = GenerateKey();
        uintptr_t encrypted = EncryptPointer(funcPtr, key ^ _masterKey);

        EncryptedEntry entry;
        entry.encryptedPtr = encrypted;
        entry.key = key ^ _masterKey;
        entry.isValid = true;

        _encryptedPointers[id] = entry;
    }

    // Decrypt a function pointer by ID
    void* DecryptFunction(const std::string& id) {
        auto it = _encryptedPointers.find(id);
        if (it == _encryptedPointers.end() || !it->second.isValid) {
            return nullptr;
        }

        return DecryptPointer(it->second.encryptedPtr, it->second.key);
    }

    // Update encryption key (simulates server-provided key update)
    void RotateKey(const std::string& id, uint64_t newKey) {
        auto it = _encryptedPointers.find(id);
        if (it == _encryptedPointers.end() || !it->second.isValid) {
            return;
        }

        // Decrypt with old key
        void* ptr = DecryptPointer(it->second.encryptedPtr, it->second.key);
        
        // Re-encrypt with new key
        it->second.key = newKey ^ _masterKey;
        it->second.encryptedPtr = EncryptPointer(ptr, it->second.key);
    }

    // Invalidate a pointer (one-time use)
    void Invalidate(const std::string& id) {
        auto it = _encryptedPointers.find(id);
        if (it != _encryptedPointers.end()) {
            it->second.isValid = false;
            it->second.encryptedPtr = 0;
            it->second.key = 0;
        }
    }

    // Validate all pointers (integrity check)
    bool ValidateAll() {
        for (const auto& pair : _encryptedPointers) {
            if (!pair.second.isValid) continue;

            void* ptr = DecryptPointer(pair.second.encryptedPtr, pair.second.key);
            
            // Check if decrypted pointer is in valid memory range
            if (!ptr || reinterpret_cast<uintptr_t>(ptr) < 0x10000) {
                return false; // Invalid pointer detected
            }
        }
        return true;
    }

    // Get encrypted data for serialization (send to server or store)
    struct SerializedData {
        std::string id;
        uintptr_t encryptedPtr;
        uint64_t key;
    };

    std::vector<SerializedData> Serialize() {
        std::vector<SerializedData> data;
        for (const auto& pair : _encryptedPointers) {
            if (pair.second.isValid) {
                SerializedData item;
                item.id = pair.first;
                item.encryptedPtr = pair.second.encryptedPtr;
                item.key = pair.second.key;
                data.push_back(item);
            }
        }
        return data;
    }

    // Deserialize and restore encrypted pointers
    void Deserialize(const std::vector<SerializedData>& data) {
        for (const auto& item : data) {
            EncryptedEntry entry;
            entry.encryptedPtr = item.encryptedPtr;
            entry.key = item.key;
            entry.isValid = true;
            _encryptedPointers[item.id] = entry;
        }
    }
};

// Helper macros for easy usage
#define ENCRYPT_FUNC(encObj, id, funcPtr) \
    encObj.EncryptFunction(id, reinterpret_cast<void*>(funcPtr))

#define DECRYPT_FUNC(encObj, id, FuncType) \
    reinterpret_cast<FuncType>(encObj.DecryptFunction(id))

#define ROTATE_KEY(encObj, id, newKey) \
    encObj.RotateKey(id, newKey)

#define INVALIDATE_PTR(encObj, id) \
    encObj.Invalidate(id)
