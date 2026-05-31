# 🔒 SecureCore v3.0 - Ultimate Protection Suite

**Advanced Multi-Layer Obfuscation & Anti-Reverse Engineering Library for C++**

## 🚀 Features

### 🔐 Cryptographic Engine
- **9-Layer Hybrid Encryption**: XOR + S-Box + Bit Rotation + Permutation + MAC
- **Dynamic S-Boxes**: Runtime-generated substitution boxes with entropy
- **Message Authentication Code (MAC)**: Integrity verification for all encrypted data
- **Secure Memory Management**: Automatic zeroing of sensitive data

### 🛡️ Advanced Anti-Debug (Checkpoint & XAntiDebug Inspired)
1. `IsDebuggerPresent()` - Standard API check
2. `CheckRemoteDebuggerPresent()` - Hidden debugger detection
3. `NtQueryInformationProcess(ProcessDebugPort)` - Port check
4. `NtQueryInformationProcess(ProcessDebugFlags)` - Flags check
5. `NtQueryInformationProcess(ProcessBreakOnTermination)` - Termination break
6. `OutputDebugString Trap` - Exception-based detection
7. **RDTSC Timing Attack** - Detects step-over/step-into delays
8. **Hidden Thread Detection** - Thread list anomaly checks
9. **Parent Process Verification** - Spoofing detection

### 🖥️ System Integrity (Kernel Process Protector Logic)
- **Privilege Stripping**: Removes SeDebugPrivilege from token
- **Crack Tool Detection**: Scans for x64dbg, IDA, CheatEngine, etc.
- **Hosts File Monitoring**: Detects modifications (>1KB threshold)
- **Proxy Detection**: Checks IE proxy configuration
- **VM/Sandbox Detection**: VMware, VirtualBox, VBOX artifacts

### 🔗 KeyAuth Integration
- **HWID Generation**: Volume serial + CPU ID binding
- **Initialization Vector (IV)**: Random IV per request
- **SSL Pinning Ready**: Certificate hash verification structure
- **Encrypted Payloads**: All API calls encrypted before transmission

### 🎭 Compile-Time Obfuscation (Oxorany/Cloakwork)
- **String Encryption**: All strings obfuscated at compile-time
- **Opaque Predicates**: Control flow flattening
- **Random Seeds**: Based on `__TIME__` and `__COUNTER__`
- **No Static Strings**: Nothing readable in binary

---

## 📦 Installation

1. Copy `SecureCore.h` to your project directory
2. Include in your main file:
```cpp
#include "SecureCore.h"
```
3. Link required libraries (auto-included via pragma):
   - `bcrypt.lib`
   - `winhttp.lib`
   - `ntdll.lib`
   - `dbghelp.lib`

---

## 💻 Usage Example

### Basic Initialization
```cpp
#include "SecureCore.h"

int main() {
    // Initialize all security checks
    SECURE_INIT();
    
    // Your protected code here
    PROTECTED_BLOCK({
        std::cout << "Application running securely!" << std::endl;
    });
    
    return 0;
}
```

### KeyAuth Integration
```cpp
#include "SecureCore.h"

int main() {
    SECURE_INIT();
    
    KeyAuth::Client client;
    
    // Initialize with obfuscated strings
    client.Init(
        SECURE_STR("YourAppName"),
        SECURE_STR("YourOwnerID"),
        SECURE_STR("YourSecret"),
        SECURE_STR("1.0")
    );
    
    // Protected login
    PROTECTED_BLOCK({
        auto resp = client.Login(
            SECURE_STR("username"),
            SECURE_STR("password")
        );
        
        if (resp.success) {
            std::cout << "Session: " << resp.session_id << std::endl;
            std::cout << "HWID: " << resp.hwid << std::endl;
        } else {
            std::cout << "Error: " << resp.message << std::endl;
            ExitProcess(0);
        }
    });
    
    return 0;
}
```

### Custom Security Checks
```cpp
// Run specific checks manually
if (AntiDebug::CheckTiming()) {
    // Timing anomaly detected
    ExitProcess(0);
}

if (SystemIntegrity::CheckCrackTools()) {
    // Cracking tool detected
    ExitProcess(0);
}

if (SystemIntegrity::IsVM()) {
    // Virtual machine detected
    ExitProcess(0);
}
```

---

## 🔧 Configuration

### SSL Pinning (KeyAuth Certificates)
Update certificate hashes in `SSLPinning` class:
```cpp
// KeyAuth.win certificates
const char* CERT_HASH = "d7864f2520cef30934c873a7bf6e10be414ec6ae9c45d35b39b319879ed9f9ca";
const char* PUB_KEY_HASH = "07d6fed49881218506064dba779b903405d56cc7826a24b15c763cc64ab98356";
```

### Custom Crack Tool List
Add more tools to detect in `SystemIntegrity::CheckCrackTools()`:
```cpp
const char* badNames[] = {
    "x64dbg", "x32dbg", "ida", "ollydbg", 
    "cheatengine", "processhacker", "wireshark",
    "fiddler", "httpdebugger", "dnspy", "ghidra",
    "your_custom_tool_here" // Add yours
};
```

---

## 🏗️ Architecture

### MultiLayerCipher (9 Layers)
1. **XOR with Key Stream** - Basic confusion
2. **S-Box Substitution** - Non-linear transformation
3. **Left Rotate 3 bits** - Bit diffusion
4. **Inverted Key XOR** - Additional layer
5. **Permutation (Reverse)** - Position shuffling
6. **Second S-Box** - Enhanced confusion
7. **Bit Flip Pattern** - Conditional XOR
8. **Right Rotate 2 bits** - Final diffusion
9. **MAC Tag** - Integrity verification

### SecureString Class
- Generates unique 32-byte random key per instance
- Encrypts string immediately on construction
- Decrypts only when `.Get()` is called
- Automatically zeroes memory on destruction

### AntiDebug Class
- Wraps 8+ different detection methods
- `RunAllChecks()` executes comprehensive scan
- Individual methods available for granular control

### SystemIntegrity Class
- Privilege management (strip debug rights)
- Process scanning (crack tools)
- Network tamper detection (hosts/proxy)
- VM artifact detection (registry keys)

---

## ⚠️ Important Notes

1. **False Positives**: Some anti-debug checks may trigger on legitimate debugging tools. Test thoroughly.
2. **Performance**: Timing checks add minimal overhead but run frequently in protected blocks.
3. **Admin Rights**: Privilege stripping requires appropriate token permissions.
4. **Network**: Proxy/Hosts checks require file system access permissions.
5. **Production**: Replace mock KeyAuth implementation with actual API calls using WinHTTP + AES.

---

## 📚 References

This library integrates techniques from:
- [Checkpoint Anti-Debug](https://anti-debug.checkpoint.com/)
- [Windows Kernel Process Protector](https://github.com/Rhydon1337/windows-kernel-process-protector)
- [XAntiDebug](https://github.com/strivexjun/XAntiDebug)
- [obfusheader.h](https://github.com/ac3ss0r/obfusheader.h)
- [oxorany](https://github.com/llxiaoyuan/oxorany)
- [Cloakwork](https://github.com/ck0i/Cloakwork)
- [KeyAuth CPP Example](https://github.com/KeyAuth/KeyAuth-CPP-Example)

---

## 📄 License

MIT License - Free for personal and commercial use.

---

## 🤝 Contributing

Feel free to submit PRs with:
- New anti-debug techniques
- Improved encryption layers
- Better obfuscation macros
- Additional VM detection methods

---

**Built with ❤️ for the security community**
