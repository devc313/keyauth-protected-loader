# KeyAuth Protected Loader

[![Build Status](https://github.com/devc313/keyauth-protected-loader/workflows/Build%20Protected%20Loader/badge.svg)](https://github.com/devc313/keyauth-protected-loader/actions)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.0-green.svg)](https://github.com/devc313/keyauth-protected-loader/releases)

Advanced multi-layer protected loader application with KeyAuth integration. Performs security checks before launching your application, establishes encrypted communication, and blocks unauthorized access.

---

## Features

### Multi-Layer Encryption
- **9-Layer Hybrid Encryption** — XOR, S-Box substitution, bit rotation, permutation, and MAC verification
- **Compile-Time String Obfuscation** — Strings are encrypted at compile time, never exposed in binary
- **SecureString Class** — Automatic in-memory encryption and decryption for sensitive values
- **HMAC-Like MAC** — Data integrity verification on all critical payloads
- **Dynamic Pointer Encryption** — Runtime function pointer encryption using server-provided keys

### Anti-Debug & Anti-Analysis
- **Timing-Based Detection** — RDTSC/RDTSCP instruction timing to detect debugger-induced delays
- **PEB Analysis** — Process Environment Block inspection for debugging flags
- **Breakpoint Detection** — INT3 scanning and hardware breakpoint (DR0–DR7) inspection
- **VM Detection** — Identifies VMware, VirtualBox, and QEMU environments
- **Emulator Detection** — Identifies Bochs and DOSBox environments
- **Direct Syscall Engine** — Bypasses EDR hooks on `ntdll.dll`
- **Delayed Crash System** — Corrupts memory state rather than crashing immediately, making analysis harder
- **Process Criticality Flag** — Sets `ProcessBreakOnTermination`; forced kills result in BSOD

### System Integrity Checks
- **Hosts File Verification** — Detects DNS hijacking via modified hosts file
- **Proxy Detection** — Checks system proxy settings for MITM attempts
- **Registry Integrity** — Validates license key registry entries
- **Process Scanning** — Detects known analysis tools (Cheat Engine, x64dbg, IDA Pro, etc.)
- **Code Integrity** — CRC64 checksum verification on critical code regions
- **Environment Binding** — Ties each session to PEB address, LDR timestamps, and module load times

### SSL Pinning & Secure Communication
- **Certificate Pinning** — KeyAuth.win server certificates are pinned
  - Certificate Hash: `d7864f2520cef30934c873a7bf6e10be414ec6ae9c45d35b39b319879ed9f9ca`
  - Public Key Hash: `07d6fed49881218506064dba779b903405d56cc7826a24b15c763cc64ab98356`
- **WinHTTP API** — All communication uses the secure WinHTTP stack
- **MITM Protection** — Guards against SSL stripping and downgrade attacks

### Control Flow Obfuscation
- **Control Flow Flattening** — Restructures execution paths to defeat static analysis
- **Opaque Predicates** — Injects conditions that defeat compiler optimizations
- **Dead Code Insertion** — Adds misleading code blocks to slow manual analysis

### Session-Bound Protection
- **PEB/LDR Binding** — Captures and validates PEB address and module load timestamps each session
- **Thread/Process ID Binding** — Ties session context to specific thread and process IDs
- **Load Time Validation** — Detects dump and reload attacks via module timestamp checks
- **Server-Side Fingerprinting** — Unique session fingerprints sent to and validated by the server
- **Dynamic Key Rotation** — XOR keys for pointer decryption are provided per-session by the server

---

## Requirements

- Windows 10 or 11
- Visual Studio 2019 or later (MSVC)
- CMake 3.15+
- KeyAuth account with application credentials

---

## Building

```bash
git clone https://github.com/devc313/keyauth-protected-loader.git
cd keyauth-protected-loader

mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

The project also builds automatically via GitHub Actions on every push. Pre-built binaries are available under the **Actions** tab or **Releases** page.

---

## Configuration

### KeyAuth Credentials

Set your credentials in `main.cpp`:

```cpp
keyauth_data.name    = SECURE_STR("YOUR_APP_NAME");
keyauth_data.ownerid = SECURE_STR("YOUR_OWNER_ID");
keyauth_data.secret  = SECURE_STR("YOUR_APP_SECRET");
keyauth_data.version = SECURE_STR("1.0");
keyauth_data.url     = SECURE_STR("https://keyauth.win/api/1.2/");
```

### Security Toggles

```cpp
#define ENABLE_DEBUG_CHECK      true
#define ENABLE_VM_CHECK         true
#define ENABLE_HOSTS_CHECK      true
#define ENABLE_PROXY_CHECK      true
#define ENABLE_PROCESS_SCAN     true
```

---

## Usage

### Basic Integration

```cpp
#include "SecureCore.h"
#include "KeyAuthManager.h"
#include "AdvancedProtection.h"

int main() {
    // Initialize protection layers
    INIT_ADVANCED_PROTECTION();

    // Enable critical process mode before sensitive operations
    BEGIN_CRITICAL_SECTION();

    // Capture environment fingerprint for server-side binding
    std::string fingerprint = g_AdvancedProtection.GetSessionFingerprint();

    // Initialize security engine with master key
    SECURE_INIT("YourMasterSecretKey123!");

    // Run all security checks
    CHECK_SECURITY();

    // Initialize KeyAuth
    KeyAuthManager auth;
    if (!auth.Initialize()) {
        MessageBoxA(NULL, "Initialization failed!", "Error", MB_ICONERROR);
        return 1;
    }

    END_CRITICAL_SECTION();

    // Run login logic inside protected context
    RUN_PROTECTED({
        if (auth.Login(username, password)) {
            RunApplication();
        }
    });

    // Keep protection active in main loop
    UPDATE_PROTECTION();

    return 0;
}
```

### Secure Strings

```cpp
// Strings are obfuscated at compile time and resolved at runtime
std::string apiUrl    = SECURE_STR("https://api.example.com/endpoint");
std::string secretKey = SECURE_STR("super-secret-key-123");
// Memory is cleared automatically after use
```

### Encrypted Function Pointers

```cpp
// Register function pointers at startup
ENCRYPT_FUNCTION("CreateMove", &CL_CreateMove);
ENCRYPT_FUNCTION("RunAimbot", &CAimbot::Run);

// Decrypt and invoke at runtime using server-provided key
auto fn = DECRYPT_FUNCTION<void(__fastcall*)(void*, void*)>("CreateMove");
fn(edx, ecx);
```

### Manual Security Checks

```cpp
if (SecurityChecker::IsDebuggerPresent_Advanced()) {
    ExitProcess(0);
}

if (SecurityChecker::IsVirtualMachine()) {
    ShowFakeError();
    ExitProcess(0);
}

if (SecurityChecker::IsHostsModified()) {
    ExitProcess(0);
}

if (!g_AdvancedProtection.ValidateEnvironment()) {
    g_AdvancedProtection.OnValidationFailed("Environment mismatch");
    // Delayed crash will trigger
}
```

---

## Technical Details

### Encryption Layers

| Layer | Operation |
|-------|-----------|
| 1 | XOR with cryptographically secure key stream |
| 2 | S-Box substitution (AES-inspired) |
| 3 | Bit rotation left (3 bits) |
| 4 | XOR with inverted key |
| 5 | Data permutation |
| 6 | Second S-Box substitution |
| 7 | Conditional bit flipping |
| 8 | Bit rotation right (2 bits) |
| 9 | HMAC-SHA256-like MAC tag addition |

### Compile-Time String Obfuscation

Strings are encrypted using a compile-time seed derived from `__TIME__`, ensuring each build produces unique encrypted constants:

```cpp
#define OBFUSCATE(str) []() {                     \
    constexpr auto key = /* compile-time hash */; \
    /* XOR each character against key at compile time */ \
}()
```

### Environment Binding

- **PEB Address** — Read directly via the GS segment register; no API calls involved
- **LDR Load Times** — Module load timestamps extracted from `PEB_LDR_DATA`
- **Thread/Process IDs** — Captured at session start and revalidated periodically
- **Validation** — Continuous background checks detect dump, reload, or injection attempts

---

## Security Best Practices

- Never store master keys as plaintext in source code
- Apply multiple independent protection layers; do not rely on any single check
- Keep security check signatures updated regularly
- Log and report suspicious activity to a server-side endpoint
- Obfuscate all strings that touch sensitive logic
- Use server-side fingerprint validation for every session
- Enable the critical process flag only during sensitive operations

---

## Legal Notice

This software is intended for protecting legitimate applications that you own or have explicit authorization to protect. Any use for unauthorized access, circumvention of third-party protections, or malicious purposes is strictly prohibited.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add your feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

## Bug Reports

Open an issue via [GitHub Issues](https://github.com/devc313/keyauth-protected-loader/issues). For security vulnerabilities, please report privately before public disclosure.

---

## Contact

- **GitHub**: [@devc313](https://github.com/devc313)
- **Discord**: [Community Server](https://discord.gg/yourserver)
- **Email**: your.email@example.com
