/*
 * AdvancedProtection.h - Unified Advanced Protection System
 * Integrates all Fatality-inspired protection mechanisms.
 */

#pragma once

#include "Syscalls.h"
#include "EnvironmentBinding.h"
#include "DelayedCrash.h"
#include "ProcessCritical.h"
#include "PointerEncryption.h"

class AdvancedProtection {
private:
    EnvironmentBinding _envBinding;
    ProcessCritical _processCritical;
    PointerEncryption _ptrEncryption;
    bool _initialized = false;
    bool _criticalEnabled = false;

public:
    AdvancedProtection() {}

    // Initialize all protection systems
    bool Initialize() {
        if (_initialized) return true;

        // Capture environment for binding
        _envBinding.CaptureEnvironment();

        _initialized = true;
        return true;
    }

    // Enable critical process mode (before sensitive operations)
    void EnableCriticalMode() {
        if (_processCritical.EnableCritical()) {
            _criticalEnabled = true;
        }
    }

    // Disable critical process mode (after sensitive operations)
    void DisableCriticalMode() {
        if (_criticalEnabled) {
            _processCritical.DisableCritical();
            _criticalEnabled = false;
        }
    }

    // Get session fingerprint for server binding
    std::string GetSessionFingerprint() {
        return _envBinding.GenerateSessionFingerprint();
    }

    // Validate environment (call periodically)
    bool ValidateEnvironment() {
        return _envBinding.ValidateEnvironment();
    }

    // Trigger delayed crash on failed validation
    void OnValidationFailed(const char* reason) {
        TRIGGER_DELAYED_CRASH(reason);
    }

    // Encrypt a function pointer
    void EncryptFunction(const std::string& id, void* funcPtr) {
        ENCRYPT_FUNC(_ptrEncryption, id, funcPtr);
    }

    // Decrypt a function pointer
    template<typename T>
    T DecryptFunction(const std::string& id) {
        return DECRYPT_FUNC(_ptrEncryption, id, T);
    }

    // Rotate encryption key (server-provided)
    void RotateKey(const std::string& id, uint64_t newKey) {
        ROTATE_KEY(_ptrEncryption, id, newKey);
    }

    // Check pending crashes (call in main loop)
    void Update() {
        CHECK_PENDING_CRASHES();
        
        // Periodically validate environment
        static DWORD lastValidate = 0;
        DWORD currentTime = GetTickCount();
        
        if (currentTime - lastValidate > 10000) { // Every 10 seconds
            if (!ValidateEnvironment()) {
                OnValidationFailed("Environment validation failed");
            }
            lastValidate = currentTime;
        }
    }

    // Get environment info
    const EnvironmentBinding& GetEnvironment() const {
        return _envBinding;
    }

    // Check if system is compromised
    bool IsCompromised() {
        // Check pointer integrity
        if (!_ptrEncryption.ValidateAll()) {
            return true;
        }

        // Check environment binding
        if (!_envBinding.ValidateEnvironment()) {
            return true;
        }

        return false;
    }
};

// Global protection instance
static AdvancedProtection g_AdvancedProtection;

// Initialization macro
#define INIT_ADVANCED_PROTECTION() \
    do { \
        if (!g_AdvancedProtection.Initialize()) { \
            /* Handle initialization failure */ \
        } \
    } while(0)

// Critical section macro
#define BEGIN_CRITICAL_SECTION() \
    do { \
        g_AdvancedProtection.EnableCriticalMode(); \
    } while(0)

#define END_CRITICAL_SECTION() \
    do { \
        g_AdvancedProtection.DisableCriticalMode(); \
    } while(0)

// Protection update macro (call in main loop)
#define UPDATE_PROTECTION() \
    do { \
        g_AdvancedProtection.Update(); \
    } while(0)

// Function encryption macro
#define ENCRYPT_FUNCTION(id, funcPtr) \
    do { \
        g_AdvancedProtection.EncryptFunction(id, reinterpret_cast<void*>(funcPtr)); \
    } while(0)

// Function decryption macro
#define DECRYPT_FUNCTION(id, FuncType) \
    g_AdvancedProtection.DecryptFunction<FuncType>(id)
