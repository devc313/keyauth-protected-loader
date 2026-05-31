/*
 * DelayedCrash.h - Anti-Analysis Delayed Penalty System
 * Instead of immediate crashes, corrupts memory/state to cause delayed failures.
 * Inspired by Fatality's protection mechanisms.
 */

#pragma once

#include <windows.h>
#include <winternl.h>
#include <random>
#include <vector>

class DelayedCrash {
private:
    // TLS corruption markers
    static constexpr int TLS_SLOT_COUNT = 5;
    int _tlsSlots[TLS_SLOT_COUNT];
    bool _corruptionActive = false;

    // Deferred crash types
    enum class CrashType {
        NONE = 0,
        TLS_CORRUPTION,
        HEAP_CORRUPTION,
        STACK_CORRUPTION,
        INVALID_POINTER,
        DIVIDE_BY_ZERO,
        PRIVILEGE_INSTRUCTION
    };

    struct PendingCrash {
        CrashType type;
        DWORD triggerTime;
        bool triggered;
    };

    std::vector<PendingCrash> _pendingCrashes;

public:
    DelayedCrash() {
        // Initialize TLS slots
        for (int i = 0; i < TLS_SLOT_COUNT; i++) {
            _tlsSlots[i] = 0;
        }
    }

    // Trigger a delayed crash instead of immediate termination
    void TriggerDelayedCrash(const char* reason = nullptr) {
        if (_corruptionActive) return; // Already corrupted
        
        _corruptionActive = true;

        // Randomly select crash type and delay
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> delayDist(5000, 30000); // 5-30 seconds
        std::uniform_int_distribution<> typeDist(1, 6);

        PendingCrash crash;
        crash.type = (CrashType)typeDist(gen);
        crash.triggerTime = GetTickCount() + delayDist(gen);
        crash.triggered = false;

        _pendingCrashes.push_back(crash);

        // Start corruption thread
        HANDLE hThread = CreateThread(nullptr, 0, CorruptionThread, this, 0, nullptr);
        if (hThread) {
            CloseHandle(hThread);
        }
    }

    // Corrupt TLS to cause future crashes
    void CorruptTLS() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(0, TLS_SLOT_COUNT - 1);

        int slot = dist(gen);
        
        // Write random data to TLS slot
        #ifdef _WIN64
            ULONGLONG* tlsBase = (ULONGLONG*)__readgsqword(0x58); // TEB->TlsSlots
        #else
            DWORD* tlsBase = (DWORD*)__readfsdword(0x2C); // TEB->TlsSlots
        #endif

        if (tlsBase) {
            tlsBase[slot] = (ULONGLONG)(gen() ^ 0xDEADBEEF);
            _tlsSlots[slot] = 1; // Mark as corrupted
        }
    }

    // Corrupt heap metadata subtly
    void CorruptHeap() {
        // Allocate and free with invalid size to corrupt heap
        void* ptr = HeapAlloc(GetProcessHeap(), 0, 256);
        if (ptr) {
            // Write beyond allocated boundary (subtle corruption)
            unsigned char* bytes = (unsigned char*)ptr;
            bytes[260] = 0xCC; // Overflow by 4 bytes
            HeapFree(GetProcessHeap(), 0, ptr);
        }
    }

    // Check if any pending crash should be triggered
    void CheckPendingCrashes() {
        DWORD currentTime = GetTickCount();

        for (auto& crash : _pendingCrashes) {
            if (!crash.triggered && currentTime >= crash.triggerTime) {
                ExecuteCrash(crash.type);
                crash.triggered = true;
            }
        }
    }

private:
    static DWORD WINAPI CorruptionThread(LPVOID lpParam) {
        DelayedCrash* self = (DelayedCrash*)lpParam;
        
        while (true) {
            Sleep(1000); // Check every second
            self->CheckPendingCrashes();
            
            // Periodically corrupt more state
            if (self->_corruptionActive) {
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<> dist(0, 100);

                if (dist(gen) > 70) { // 30% chance
                    self->CorruptTLS();
                }
            }
        }

        return 0;
    }

    void ExecuteCrash(CrashType type) {
        switch (type) {
            case CrashType::TLS_CORRUPTION:
                CorruptTLS();
                // Let the corruption cause natural crash later
                break;

            case CrashType::HEAP_CORRUPTION:
                CorruptHeap();
                // Heap corruption will manifest later
                break;

            case CrashType::STACK_CORRUPTION:
                {
                    volatile char buffer[64];
                    // Write beyond buffer (will crash on return)
                    for (int i = 0; i < 128; i++) {
                        buffer[i] = 0x90;
                    }
                }
                break;

            case CrashType::INVALID_POINTER:
                {
                    // Jump to invalid address
                    typedef void (*FuncPtr)();
                    FuncPtr invalidFunc = (FuncPtr)0x00000000;
                    invalidFunc(); // Will crash
                }
                break;

            case CrashType::DIVIDE_BY_ZERO:
                {
                    volatile int zero = 0;
                    volatile int result = 100 / zero; // Divide by zero
                }
                break;

            case CrashType::PRIVILEGE_INSTRUCTION:
                {
                    // Execute privileged instruction (will fault in user mode)
                    __try {
                        __writecr8(0); // Ring 0 only
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        // If exception handler catches it, try another method
                        __debugbreak();
                    }
                }
                break;

            default:
                break;
        }
    }
};

// Global instance for easy access
static DelayedCrash g_DelayedCrash;

// Macro to trigger delayed crash on failed checks
#define TRIGGER_DELAYED_CRASH(reason) \
    do { \
        g_DelayedCrash.TriggerDelayedCrash(reason); \
    } while(0)

// Macro to check pending crashes (call periodically in main loop)
#define CHECK_PENDING_CRASHES() \
    do { \
        g_DelayedCrash.CheckPendingCrashes(); \
    } while(0)
