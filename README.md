<div align="center">

# 🔐 KeyAuth Protected Loader

**A production-ready C++ loader template with KeyAuth 1.3 API integration and multi-layer protection.**

Anti-debug, anti-VM, compile-time string obfuscation, 9-layer encryption, and NTP time validation. Targets Windows x64.

[![Build](https://img.shields.io/github/actions/workflow/status/devc313/keyauth-protected-loader/build.yml?branch=main&logo=githubactions&logoColor=white&label=Build&style=for-the-badge)](https://github.com/devc313/keyauth-protected-loader/actions)
[![Language](https://img.shields.io/badge/C%2B%2B-17-00599C?style=for-the-badge&logo=cplusplus&logoColor=white)](https://en.cppreference.com)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D4?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/devc313/keyauth-protected-loader)
[![License](https://img.shields.io/github/license/devc313/keyauth-protected-loader?style=for-the-badge&color=22C55E)](LICENSE)
[![Stars](https://img.shields.io/github/stars/devc313/keyauth-protected-loader?style=for-the-badge&color=FFD700)](https://github.com/devc313/keyauth-protected-loader/stargazers)

</div>

---

## Overview

A hardened loader template built on top of the [KeyAuth](https://keyauth.win) licensing API. It wraps license validation behind multiple anti-analysis layers and binds each session on both the client and server sides.

**Intended use:** A secure starting point for applications that use KeyAuth for licensing, so you don't have to implement the protection layer from scratch.

---

## Repository Structure

```
keyauth-protected-loader/
├── main.cpp                    # Entry point, auth flow, console UI
├── SecureCore.h                # 9-layer cipher engine, compile-time obfuscation
├── security.hpp / security.cpp # Anti-debug, anti-VM, process scanner
├── security_enhanced.hpp       # BCrypt-based secure RNG, runtime key generation
├── secure_literals.hpp         # CW_STR / CW_WSTR compile-time string encryption
├── skStr.h                     # Stack string obfuscation helpers
├── auth.hpp                    # KeyAuth C++ SDK (v1.3)
├── ntp.hpp / ntp.cpp           # NTP time sync (pool.ntp.org, UDP/123)
├── console.hpp / console.cpp   # Console color, animation, layout helpers
├── utils.hpp                   # Time conversion utilities
├── includes.hpp                # Global include aggregator
├── library_x64.lib             # KeyAuth precompiled library (x64)
├── Project/Protection/
│   └── AdvancedProtection.h    # INIT/BEGIN/END/UPDATE_PROTECTION macros
├── CMakeLists.txt
└── KeyAuthLoader.sln / .vcxproj
```

---

## Security Architecture

### 1. Compile-Time String Obfuscation

The `CW_STR` / `CW_WSTR` macros in `secure_literals.hpp` and `skStr.h` encrypt string literals at compile time. The encryption key is derived from the `__TIME__` constant — each build produces unique encrypted constants.

```cpp
// "ollydbg.exe" is never visible as plaintext in the binary
const wchar_t* tool = CW_WSTR(L"ollydbg.exe").decrypt();

// KeyAuth credentials are obfuscated the same way
Security::SecureString<32> NAME("appname");
Security::SecureString<64> URL("https://keyauth.win/api/1.3/");
```

The `SecureString<N>` template class keeps strings encrypted on the heap. `decryptToStack()` temporarily decrypts to a stack buffer and wipes it with `SecureZeroMemory` after use.

---

### 2. 9-Layer Cipher Engine (`CryptoEngine::MultiLayerCipher`)

The license key is passed through 9 sequential transforms before being written to the registry:

| Layer | Operation |
|-------|-----------|
| 1 | XOR — 32-byte key stream |
| 2 | S-Box substitution (AES S-Box) |
| 3 | Bit rotation left (3 bits) |
| 4 | XOR — inverted key stream |
| 5 | Adjacent byte permutation (index-based swap) |
| 6 | Second S-Box substitution (XOR with index) |
| 7 | Conditional bit flip (every 5th byte XOR `0x20`) |
| 8 | Bit rotation right (2 bits) |
| 9 | MAC tag append (4-byte HMAC-like integrity tag) |

During decryption the MAC is verified first. On failure, the buffer is wiped with `SecureZeroMemory` and an empty result is returned. The encrypted payload is Base64-encoded before being stored in the registry.

---

### 3. Runtime Key Generation (`security_enhanced.hpp`)

`SecureRandom` uses **BCrypt CNG** (`BCryptGenRandom`) to generate fresh keys on every process start. On Intel/AMD hardware, `_rdrand64_step` is used for hardware RNG.

`EncryptionKeys` zeroes all key material in its destructor:

```
EncryptionKeys:
  hmacKey[32]       ← BCryptGenRandom
  xorKeys[8][64]    ← 8 independent XOR keys (one per layer)
```

---

### 4. Anti-Debug & Anti-Analysis

**Debugger Detection**
- `IsDebuggerPresent()` + `CheckRemoteDebuggerPresent()`
- `CONTEXT.Dr0–Dr3` hardware breakpoint register scan
- `NtQueryInformationProcess` PEB debug flag check
- RDTSC timing analysis — threshold: `50,000 ns` (`SecureConfig::RDTSC_THRESHOLD`)

**Tool Detection** (via process snapshot)
- OllyDbg, x64dbg, x32dbg, IDA Pro (`ida.exe` / `ida64.exe`)
- Cheat Engine, Process Hacker, HTTPDebuggerUI, Procmon

**Anti-Dump**
- `VirtualProtect` sets PE header pages to `PAGE_READONLY`

---

### 5. Anti-VM Detection

Three independent methods combined:

**CPUID Vendor String**
- `"VMwareVMware"`, `"Microsoft Hv"`, `"VBoxVBoxVBox"`

**Hypervisor Bit + Device Handle**
- CPUID `ECX[31]` hypervisor flag check
- Open attempts on `\\.\VmGeneralPort` and `\\.\VBoxMiniRdrDN`

**MAC Address OUI Check**
- VMware: `00:0C:29` / VirtualBox: `08:00:27`

**Registry Keys**
- `SOFTWARE\VMware, Inc.\VMware Tools`
- `SOFTWARE\Oracle\VirtualBox Guest Additions`

---

### 6. System Integrity Checks

| Check | Method |
|-------|--------|
| Hosts file | Size (`> 10 KB`) + content scan for `"keyauth"`, `"127.0.0.1"` |
| Proxy detection | `HKCU\...\Internet Settings\ProxyEnable` registry read |
| NTP time sync | `pool.ntp.org:123` UDP — ±5 minute tolerance against system clock |
| Response timing | KeyAuth API `< 100 ms` → emulator suspected → `exit(3)` |
| API endpoint | URL must contain `keyauth.win` |

---

### 7. Control Flow Obfuscation

**Opaque Predicates:** `AlwaysTrue()` / `AlwaysFalse()` — volatile conditions that always resolve the same way but appear complex to static analysis.

**Control Flow Flattening:** `ExecuteFlattened<Func>` — wraps execution inside a `switch/state` dispatcher to break linear flow analysis.

```cpp
RUN_PROTECTED({
    // This block runs through the flattened dispatcher
    KeyAuthApp.license(key);
});
```

---

### 8. Session Binding (`AdvancedProtection`)

`INIT_ADVANCED_PROTECTION()` captures the following fingerprint at startup:

- PEB address (read via GS segment register — no API calls)
- LDR module load timestamps (`PEB_LDR_DATA`)
- Thread and process IDs

`UPDATE_PROTECTION()` runs on a background thread at 1-second intervals and revalidates the environment continuously.

**Critical Section:** `BEGIN_CRITICAL_SECTION()` / `END_CRITICAL_SECTION()` toggles `ProcessBreakOnTermination` — a forced kill triggers a BSOD.

---

### 9. License Persistence (Registry)

After successful validation, the key is encrypted and written to the registry:

```
HKCU\SOFTWARE\KeyAuthLoader\License  ←  Base64( MultiLayerEncrypt(license_key) )
```

On subsequent launches it is read, decrypted, and passed directly to `KeyAuthApp.license()` — no re-entry required.

---

## Execution Flow

```
main()
 │
 ├─ INIT_ADVANCED_PROTECTION()         → capture PEB/LDR fingerprint
 ├─ BEGIN_CRITICAL_SECTION()           → set ProcessBreakOnTermination
 ├─ Security::AntiDump()               → PE header → PAGE_READONLY
 ├─ Security::SecurityCheck()          → debugger / DR registers / tool scan
 ├─ Security::AdvancedSecurityCheck()  → VM / code integrity / time manipulation
 ├─ END_CRITICAL_SECTION()
 ├─ NTP::CheckTimeSync()               → pool.ntp.org ±5min validation
 │
 ├─ [Background Thread] ─────────────→ UPDATE_PROTECTION() + SecurityCheck() every 1s
 │
 ├─ KeyAuthApp.init()                  → timing check (< 100ms → exit(3))
 │
 ├─ License in registry?
 │    ├─ Yes → MultiLayerDecrypt → KeyAuthApp.license()
 │    └─ No  → prompt user → KeyAuthApp.license() → save to registry
 │
 └─ Main loop
      ├─ sessionStatus() thread → KeyAuthApp.check() every 20s
      └─ [1] Load Application / [0] Exit
```

---

## Requirements

- Windows 10 / 11 (x64)
- Visual Studio 2019+ (MSVC, C++17)
- CMake 3.15+
- [KeyAuth](https://keyauth.win) account with application credentials

---

## Building

**Visual Studio:**
```
KeyAuthLoader.sln → Configuration: Release | Platform: x64 → Build Solution
```

**CMake:**
```bash
git clone https://github.com/devc313/keyauth-protected-loader
cd keyauth-protected-loader
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -A x64
cmake --build . --config Release
```

> ⚠️ **Only `Release x64` is supported.** In Debug builds several protection layers are disabled and anti-debug checks may fire against your own process.

---

## Configuration

Replace the `SecureString` definitions in `main.cpp` with your own KeyAuth credentials:

```cpp
namespace {
    Security::SecureString<32> NAME("YOUR_APP_NAME");
    Security::SecureString<32> OWNERID("YOUR_OWNER_ID");
    Security::SecureString<32> VERSION("1.0");
    Security::SecureString<64> URL("https://keyauth.win/api/1.3/");
    Security::SecureString<32> REGISTRY_PATH("SOFTWARE\\YourAppName");
    Security::SecureString<32> REGISTRY_KEY("License");
}
```

Individual checks can be toggled in `security.hpp`:

```cpp
#define ENABLE_DEBUG_CHECK      true
#define ENABLE_VM_CHECK         true
#define ENABLE_HOSTS_CHECK      true
#define ENABLE_PROXY_CHECK      true
#define ENABLE_PROCESS_SCAN     true
```

---

## SSL Pinning

`SecureConfig` hardcodes the KeyAuth server certificate hashes:

```cpp
constexpr const char* CERT_HASH[] = {
    "d7864f2520cef30934c873a7bf6e10be414ec6ae9c45d35b39b319879ed9f9ca",  // Certificate
    "07d6fed49881218506064dba779b903405d56cc7826a24b15c763cc64ab98356"   // Public Key
};
```

---

## Contributing

```bash
# Before opening a PR:
cl /std:c++17 /W4 /WX *.cpp /link    # zero warnings target
```

- Keep each security module independent (`security.cpp` must not depend on `main.cpp`)
- All new strings must use `CW_STR()` or `Security::SecureString<N>` — no raw literals in sensitive paths
- Registry paths and keys must be defined as `SecureString`, never hardcoded plaintext

---

## License

MIT — see [LICENSE](LICENSE).

> **Disclaimer:** This template is intended solely for protecting applications **you own or have explicit authorization to protect**. Using it for unauthorized access or to circumvent third-party software protections is prohibited and may violate applicable law.

---

<div align="center">
Built by <a href="https://github.com/devc313">devc313</a> &nbsp;·&nbsp; Discord: <code>ecvdxd98</code>
</div>
