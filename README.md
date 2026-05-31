# 🔐 KeyAuth Protected Loader - Advanced Security Implementation

[![Build Status](https://github.com/devc313/keyauth-protected-loader/workflows/Build%20Protected%20Loader/badge.svg)](https://github.com/devc313/keyauth-protected-loader/actions)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.0-green.svg)](https://github.com/devc313/keyauth-protected-loader/releases)

**Advanced multi-layer protected loader application with KeyAuth integration.**

This project is a **loader application** with **advanced security layers** for applications using the KeyAuth API. It includes multiple protection mechanisms against reverse engineering, debugging, cracking, and analysis tools.

## ⚠️ Important Notice

This is **not a protection library**, but a **secure loader application** with KeyAuth integration. It performs security checks before running your application, establishes encrypted communication, and blocks unauthorized access.

## 🚀 Features

### 🔒 Multi-Layer Encryption
- **9-Layer Hybrid Encryption**: XOR + S-Box + Bit Rotation + Permutation + MAC
- **Compile-Time String Obfuscation**: Compile-time string encryption
- **SecureString Class**: Automatic encryption/decryption for sensitive data
- **HMAC-Like MAC**: Data integrity verification
- **Dynamic Pointer Encryption**: Runtime function pointer encryption with server-provided keys

### 🛡️ Anti-Debug & Anti-Analysis (Fatality-Inspired)
- **Checkpoint Anti-Debug Techniques**: Timing-based detection, PEB analysis
- **Direct Syscall Engine**: Bypasses EDR hooks on ntdll.dll
- **Breakpoint Detection**: INT3, hardware breakpoint scanning
- **Timing Attack Detection**: Detecting debugger-induced delays
- **VM Detection**: VMware, VirtualBox, QEMU detection
- **Emulator Detection**: Bochs, DOSBox detection
- **Delayed Crash System**: Corrupts memory state instead of immediate crashes for harder analysis
- **Process Criticality Protection**: ProcessBreakOnTermination flag prevents easy termination (BSOD on forced kill)

### 🔍 System Integrity Checks
- **Hosts File Check**: Modified hosts file detection
- **Proxy Detection**: System proxy settings check
- **Registry Integrity**: License key security
- **Process Scanning**: Detection of Cheat Engine, x64dbg, IDA Pro, etc.
- **Code Integrity**: CRC64 code integrity verification
- **Environment Binding**: Binds session to PEB, LDR timestamps, module load times

### 🔐 SSL Pinning & Secure Communication
- **Certificate Pinning**: KeyAuth.win certificates pinned
  - Certificate Hash: `d7864f2520cef30934c873a7bf6e10be414ec6ae9c45d35b39b319879ed9f9ca`
  - Public Key Hash: `07d6fed49881218506064dba779b903405d56cc7826a24b15c763cc64ab98356`
- **Secure HTTP Requests**: WinHTTP secure API communication
- **Man-in-the-Middle Protection**: Protection against SSL stripping attacks

### 🎯 Control Flow Obfuscation
- **Control Flow Flattening**: Control flow flattening
- **Opaque Predicates**: Compiler optimization-bypassing conditions
- **Dead Code Insertion**: Analysis-obstructing dead code blocks

### 🔄 Session-Bound Protection (Fatality-Inspired)
- **PEB/LDR Binding**: Captures and validates PEB address, module load times
- **Thread/Process ID Binding**: Ties session to specific thread and process IDs
- **LoadTime Validation**: Detects dump/reload attacks by validating module timestamps
- **Server-Side Fingerprinting**: Generates unique session fingerprints for server validation
- **Dynamic Key Rotation**: Server-provided XOR keys for pointer decryption

## 📦 Installation

### Requirements
- Windows 10/11
- Visual Studio 2019 or later (MSVC)
- CMake 3.15+
- KeyAuth account and application keys

### Manual Build

```bash
# Clone repository
git clone https://github.com/devc313/keyauth-protected-loader.git
cd keyauth-protected-loader

# Build with CMake
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

### GitHub Actions Auto-Build

The project automatically builds using GitHub Actions:
- Build on windows-2025 for every push
- Release artifact as EXE output
- Auto-create release when tag is pushed

Build files can be downloaded from **Actions** tab or **Releases** page.

## 🔧 Configuration

### KeyAuth Settings

Enter your KeyAuth credentials in `main.cpp`:

```cpp
// In main.cpp
keyauth_data.name = SECURE_STR("YOUR_APP_NAME");
keyauth_data.ownerid = SECURE_STR("YOUR_OWNER_ID");
keyauth_data.secret = SECURE_STR("YOUR_APP_SECRET");
keyauth_data.version = SECURE_STR("1.0");
keyauth_data.url = SECURE_STR("https://keyauth.win/api/1.2/");
```

### Security Level Configuration

```cpp
// Customize security checks
#define ENABLE_DEBUG_CHECK      true
#define ENABLE_VM_CHECK         true
#define ENABLE_HOSTS_CHECK      true
#define ENABLE_PROXY_CHECK      true
#define ENABLE_PROCESS_SCAN     true
```

## 📖 Usage

### Basic Usage

```cpp
#include "SecureCore.h"
#include "KeyAuthManager.h"
#include "AdvancedProtection.h"

int main() {
    // 1. Initialize advanced protection
    INIT_ADVANCED_PROTECTION();
    
    // 2. Enable critical process mode before sensitive operations
    BEGIN_CRITICAL_SECTION();
    
    // 3. Capture environment fingerprint for server binding
    std::string fingerprint = g_AdvancedProtection.GetSessionFingerprint();
    // Send fingerprint to server for session-bound compilation
    
    // 4. Initialize security engine
    SECURE_INIT("YourMasterSecretKey123!");
    
    // 5. Run security checks
    CHECK_SECURITY();
    
    // 6. Initialize KeyAuth manager
    KeyAuthManager auth;
    
    if (!auth.Initialize()) {
        MessageBoxA(NULL, "Initialization failed!", "Error", MB_ICONERROR);
        return 1;
    }
    
    // 7. Disable critical mode after sensitive operations
    END_CRITICAL_SECTION();
    
    // 8. Run in protected area
    RUN_PROTECTED({
        // Login operations
        if (auth.Login(username, password)) {
            // Post-login operations
            RunApplication();
        }
    });
    
    // 9. Update protection in main loop
    UPDATE_PROTECTION();
    
    return 0;
}
```

### Secure String Usage

```cpp
// Strings are automatically obfuscated
std::string apiUrl = SECURE_STR("https://api.example.com/endpoint");
std::string secretKey = SECURE_STR("super-secret-key-123");

// Resolved at runtime, erased from memory after use
```

### Function Pointer Encryption

```cpp
// Encrypt function pointers at initialization
ENCRYPT_FUNCTION("CreateMove", &CL_CreateMove);
ENCRYPT_FUNCTION("RunAimbot", &CAimbot::Run);

// Decrypt and call at runtime (requires server-provided key)
auto CreateMoveFunc = DECRYPT_FUNCTION<void(__fastcall*)(void*, void*)>("CreateMove");
CreateMoveFunc(edx, ecx);
```

### Custom Security Checks

```cpp
// Debugger check
if (SecurityChecker::IsDebuggerPresent_Advanced()) {
    // Log or silently exit
    ExitProcess(0);
}

// VM check
if (SecurityChecker::IsVirtualMachine()) {
    // Show different behavior
    ShowFakeError();
    ExitProcess(0);
}

// Hosts file check
if (SecurityChecker::IsHostsModified()) {
    // DNS hijacking attempt
    ExitProcess(0);
}

// Environment validation (periodic)
if (!g_AdvancedProtection.ValidateEnvironment()) {
    g_AdvancedProtection.OnValidationFailed("Environment mismatch");
    // Delayed crash will trigger
}
```

## 🔬 Technical Details

### Encryption Layers

1. **Layer 1**: XOR with Cryptographically Secure Key Stream
2. **Layer 2**: S-Box Substitution (AES-inspired)
3. **Layer 3**: Bit Rotation Left (3 bits)
4. **Layer 4**: XOR with Inverted Key
5. **Layer 5**: Data Permutation
6. **Layer 6**: Second S-Box Substitution
7. **Layer 7**: Conditional Bit Flipping
8. **Layer 8**: Final Bit Rotation Right (2 bits)
9. **Layer 9**: HMAC-SHA256-like MAC Tag Addition

### Compile-Time String Obfuscation

```cpp
// Encryption with __TIME__ seed at compile-time
#define OBFUSCATE(str) []() { \
    constexpr auto key = []() { /* compile-time hash */ }(); \
    /* XOR encryption with key */ \
}()
```

### Anti-Debug Techniques

- **Timing-Based Detection**: RDTSC/RDTSCP instruction timing
- **PEB Analysis**: Process Environment Block debugging flags
- **Hardware Breakpoints**: DR0-DR7 register check
- **INT3 Detection**: Memory 0xCC byte scanning
- **Parent Process Verification**: Non-explorer.exe parents
- **Window Title Scanning**: Debug tool window titles
- **Delayed Crash**: Memory corruption instead of immediate crash

### Environment Binding

- **PEB Address**: Captured via GS segment (no API call)
- **LDR LoadTime**: Module load timestamps from PEB_LDR_DATA
- **Thread/Process IDs**: Unique session identifiers
- **Validation**: Periodic re-checking to detect dump/reload attacks

## 🛡️ Security Best Practices

1. **Key Management**: Never store master keys as plaintext in source code
2. **Layered Defense**: Don't rely on single protection, use multiple layers
3. **Updates**: Regularly update security checks
4. **Monitoring**: Log and report suspicious activities
5. **Obfuscation**: Obfuscate all sensitive strings
6. **Session Binding**: Use server-side fingerprinting for each session
7. **Critical Processes**: Enable critical flag only during sensitive operations

## ⚠️ Legal Disclaimer

This software is for **educational and legal purposes only**. Developers should use this code only to protect their own applications. Unauthorized reverse engineering, crack creation, or malicious use is prohibited.

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. Fork the project
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 🐛 Issue Reporting

If you find a bug or security vulnerability, please report it via [Issues](https://github.com/devc313/keyauth-protected-loader/issues). We kindly ask you to report security vulnerabilities privately before public disclosure.

## 📬 Contact

- **GitHub**: [@devc313](https://github.com/devc313)
- **Discord**: [Community Server](https://discord.gg/yourserver)
- **Email**: your.email@example.com

---

**⚠️ Remember**: No security system is 100% unbreakable. This loader is designed to make reverse engineering difficult and increase attacker effort. Implement a defense-in-depth strategy.

