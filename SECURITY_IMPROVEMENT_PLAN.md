# Güvenlik İyileştirme Planı - KeyAuthLoader

## 📋 Tespit Edilen Güvenlik Açıkları ve Çözüm Planı

### 1. 🔴 Zayıf Registry Şifreleme (KRİTİK)

**Mevcut Durum:**
- Custom AES-benzeri şifreleme kullanılıyor ancak S-Box hardcoded
- HMAC implementasyonu custom ve kriptografik olarak zayıf
- Anahtarlar runtime'da üretiliyor ama entropy yetersiz

**Çözüm:**
```cpp
// Windows Crypto API (CNG) kullanılmalı
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

// BCryptGenerateSymmetricKey ile AES-256
// BCryptEncrypt/BCryptDecrypt ile CBC mode
// Random IV her encrypt işleminde
```

**Uygulama Adımları:**
1. `security.hpp` - BCrypt fonksiyonlarını ekle
2. `security.cpp` - Aes256Encrypt/Aes256Decrypt fonksiyonları yaz
3. Mevcut MultiLayerEncrypt yerine CNG tabanlı şifreleme kullan
4. HMAC-SHA256 için BCryptHash kullan

---

### 2. 🔴 Güvensiz memcpy Kullanımı - Buffer Overflow (KRİTİK)

**Mevcut Durum:**
```cpp
memcpy(vendorID, &cpuInfo[1], 4);  // Boyut kontrolü yok
```

**Çözüm:**
```cpp
// memcpy_s kullan (Windows secure version)
memcpy_s(vendorID, vendorIDSize, &cpuInfo[1], 4);

// Veya span kullan (C++20)
std::span<char> vendorSpan(vendorID, vendorIDSize);
std::copy_n(reinterpret_cast<char*>(&cpuInfo[1]), 4, vendorSpan.begin());
```

**Uygulama Adımları:**
1. Tüm memcpy çağrılarını memcpy_s ile değiştir
2. Buffer boyutlarını her zaman geçir
3. Static analysis tool ekle (PVS-Studio veya Cppcheck)

---

### 3. 🔴 Stack Shellcode Execution (KRİTİK)

**Mevcut Durum:**
- Kodda doğrudan shellcode execution tespiti yok ama VirtualAlloc/VirtualProtect kullanımı var

**Çözüm:**
```cpp
// DEP (Data Execution Prevention) uyumlu kod
// Stack executable değil, sadece heap/code segment kullan

// Safe memory execution için:
void* ExecuteInIsolatedContext(const std::vector<BYTE>& code) {
    void* execMem = VirtualAlloc(nullptr, code.size(), 
                                  MEM_COMMIT | MEM_RESERVE, 
                                  PAGE_EXECUTE_READ);
    if (!execMem) return nullptr;
    
    // Copy code
    memcpy(execMem, code.data(), code.size());
    
    // Execute via function pointer
    using FuncType = void(*)();
    FuncType func = reinterpret_cast<FuncType>(execMem);
    func();
    
    // Cleanup - PAGE_NOACCESS yap sonra free et
    DWORD oldProtect;
    VirtualProtect(execMem, code.size(), PAGE_NOACCESS, &oldProtect);
    VirtualFree(execMem, 0, MEM_RELEASE);
    return nullptr;
}
```

**Uygulama Adımları:**
1. Memory protection flag'lerini sıkılaştır
2. Code integrity check ekle
3. Control Flow Guard (CFG) aktif et

---

### 4. 🔴 Zayıf Anti-Debug (KRİTİK)

**Mevcut Durum:**
```cpp
IsDebuggerPresent()  // Kolay bypass edilir
CheckRemoteDebuggerPresent()  // Bilinen API
GetThreadContext(Dr0-Dr3)  // Kolay spoof edilir
```

**Çözüm:**
```cpp
// Advanced anti-debug teknikleri:

// 1. Timing-based detection
bool TimingCheck() {
    auto start = std::chrono::high_resolution_clock::now();
    __asm__ volatile ("cpuid" ::: "rax", "rbx", "rcx", "rdx");
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    return duration.count() > 5000;  // Debugger varsa yavaşlar
}

// 2. Exception-based detection
bool ExceptionCheck() {
    __try {
        // Invalid instruction
        __asm__ volatile ("int3");
        return true;  // Debugger yakaladı
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;  // Normal execution
    }
}

// 3. PEB/PTEB checks (hardcoded offsetler yerine dinamik)
bool PEBCheck() {
    PPEB peb = (PPEB)__readgsqword(0x60);
    if (peb->BeingDebugged) return true;
    
    // NtGlobalFlag check
    DWORD flags = *(PDWORD)((PBYTE)peb + 0xBC);  // Dynamic offset
    if (flags & (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK)) 
        return true;
    
    return false;
}

// 4. Hardware breakpoint detection (advanced)
bool HardwareBreakpointCheck() {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);
    
    // Debug register'ların MSR'dan okunması (kernel mode gerekir)
    // User mode'da alternatif: exception timing
    return CheckDebugRegisters();
}
```

**Uygulama Adımları:**
1. security.cpp'ye advanced anti-debug fonksiyonları ekle
2. RDTSC tabanlı timing check'leri ekle
3. Multiple check'leri randomize sırayla çalıştır
4. False positive handling ekle

---

### 5. 🔴 Hardcoded Syscall Numaraları (KRİTİK)

**Mevcut Durum:**
- Syscall numaraları Windows versiyonuna göre değişir
- Hardcoded değerler BSOD veya crash'e neden olur

**Çözüm:**
```cpp
// Dinamik syscall resolution:

typedef NTSTATUS (NTAPI* NtQueryInformationProcess_t)(
    HANDLE ProcessHandle,
    PROCESS_INFORMATION_CLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

NtQueryInformationProcess_t pNtQueryInformationProcess = nullptr;

void ResolveSyscalls() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        pNtQueryInformationProcess = 
            (NtQueryInformationProcess_t)GetProcAddress(hNtdll, 
                "NtQueryInformationProcess");
    }
}

// Hell's Gate / Halo's Gate technique for SSN resolution
WORD GetSSN(const char* functionName) {
    // ntdll.dll'in .text section'ını parse et
    // Syscall instruction (0F 05) öncesi MOV R10, RCX bul
    // Önceki byte SSN'dir
}
```

**Uygulama Adımları:**
1. Syscall resolver sınıfı oluştur
2. Runtime'da ntdll.dll parse et
3. Windows version detection ekle
4. Fallback mekanizması oluştur

---

### 6. 🔴 Command Injection - system() Çağrıları (KRİTİK)

**Mevcut Durum:**
```cpp
system("color 0F");   // Command injection riski
system("cls");        // Path traversal riski
```

**Çözüm:**
```cpp
// Win32 API kullan, system() kullanma!

// Console color için:
void SetConsoleColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

// Clear screen için:
void ClearScreen() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD coordScreen = {0, 0};
    DWORD cCharsWritten;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    
    if (GetConsoleScreenBufferInfo(hConsole, &csbi)) {
        DWORD dwSize = csbi.dwSize.X * csbi.dwSize.Y;
        FillConsoleOutputCharacterA(hConsole, ' ', dwSize, coordScreen, &cCharsWritten);
        FillConsoleOutputAttribute(hConsole, csbi.wAttributes, dwSize, coordScreen, &cCharsWritten);
        SetConsoleCursorPosition(hConsole, coordScreen);
    }
}

// Eğer external command çalıştırmak şart ise:
BOOL RunCommandSafe(const wchar_t* command, const wchar_t* args[]) {
    STARTUPINFOW si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);
    
    // Command'i validate et
    if (!IsValidCommand(command)) return FALSE;
    
    // CreateProcessW kullan (system() yerine)
    return CreateProcessW(command, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}
```

**Uygulama Adımları:**
1. Tüm system() çağrılarını kaldır
2. Win32 Console API kullan
3. Input validation ekle
4. Whitelist-based command execution

---

### 7. 🔴 TOCTOU Vulnerability (KRİTİK)

**Mevcut Durum:**
- Registry okuma/yazma arasında time-of-check-time-of-use açığı var
- File operations'da race condition riski

**Çözüm:**
```cpp
// Atomic operations kullan:

// Registry için transactional API:
bool SaveLicenseAtomic(const std::string& license) {
    HANDLE hTransaction = CreateTransaction(NULL, 0, 0, 0, 0, 0, L"LicenseTransaction");
    if (hTransaction == INVALID_HANDLE_VALUE) return false;
    
    HKEY hKey;
    LONG result = RegCreateKeyTransactedA(HKEY_CURRENT_USER, 
        "SOFTWARE\\KeyAuthLoader", 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, hTransaction, &hKey, NULL);
    
    if (result != ERROR_SUCCESS) {
        RollbackTransaction(hTransaction);
        CloseHandle(hTransaction);
        return false;
    }
    
    // Write operation
    result = RegSetValueExA(hKey, "License", 0, REG_SZ, 
        (const BYTE*)license.c_str(), license.length() + 1);
    
    if (result == ERROR_SUCCESS) {
        CommitTransaction(hTransaction);
    } else {
        RollbackTransaction(hTransaction);
    }
    
    RegCloseKey(hKey);
    CloseHandle(hTransaction);
    return result == ERROR_SUCCESS;
}

// File operations için lock mechanism:
class FileLock {
    HANDLE hFile;
    OVERLAPPED overlapped;
public:
    bool Lock(const std::wstring& path) {
        hFile = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;
        
        overlapped.Offset = 0;
        overlapped.OffsetHigh = 0;
        return LockFileEx(hFile, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD, &overlapped);
    }
    
    void Unlock() {
        if (hFile != INVALID_HANDLE_VALUE) {
            UnlockFileEx(hFile, 0, MAXDWORD, MAXDWORD, &overlapped);
            CloseHandle(hFile);
        }
    }
};
```

**Uygulama Adımları:**
1. Transactional Registry API kullan
2. File locking mekanizması ekle
3. Atomic swap operations kullan
4. Retry logic with exponential backoff

---

### 8. 🔴 Weak String Obfuscation (KRİTİK)

**Mevcut Durum:**
- Compile-time seed kolay reverse engineer edilir
- S-Box lookup table static
- XOR key generation predictable

**Çözüm:**
```cpp
// Advanced string obfuscation:

template<size_t N>
class SecureStringV2 {
private:
    char data[N];
    size_t length;
    uint64_t runtimeKey;  // Runtime'da üretilir
    
    // Runtime key generation - RDRAND kullan
    static uint64_t GenerateRuntimeKey() {
        uint64_t key;
        if (__rdrand64(&key)) {
            // Mix with timestamp and address entropy
            key ^= static_cast<uint64_t>(
                std::chrono::high_resolution_clock::now().time_since_epoch().count());
            key ^= reinterpret_cast<uint64_t>(&key);
            return key;
        }
        // Fallback
        return std::random_device{}();
    }
    
    // Polynomial key derivation
    inline unsigned char deriveKey(size_t idx, uint64_t baseKey) const {
        uint64_t k = baseKey ^ (idx * 0x9E3779B97F4A7C15ULL);
        k = (k << 13) | (k >> 51);
        k *= 0xC2B2AE3D27D4EB4FULL;
        k ^= k >> 33;
        return static_cast<unsigned char>(k & 0xFF);
    }
    
public:
    constexpr SecureStringV2(const char* str) : runtimeKey(0), length(strlen(str)) {
        // Initialization delayed to runtime
    }
    
    void Initialize() {
        runtimeKey = GenerateRuntimeKey();
        for (size_t i = 0; i < length && i < N-1; i++) {
            unsigned char key = deriveKey(i, runtimeKey);
            unsigned char c = static_cast<unsigned char>(str[i]);
            // Multi-layer: Substitution + Permutation + XOR
            c = S_BOX[c];
            c = ((c << 3) | (c >> 5)) ^ key;
            c ^= S_BOX[(i + runtimeKey) & 0xFF];
            data[i] = c;
        }
        data[length] = '\0';
    }
    
    std::string decrypt() {
        if (runtimeKey == 0) return "";
        
        std::string result;
        result.reserve(length);
        for (size_t i = 0; i < length; i++) {
            unsigned char key = deriveKey(i, runtimeKey);
            unsigned char c = data[i];
            c ^= S_BOX[(i + runtimeKey) & 0xFF];
            c ^= key;
            c = (c >> 3) | (c << 5);
            c = INV_S_BOX[c];
            result += static_cast<char>(c);
        }
        // Secure wipe
        SecureZeroMemory(&runtimeKey, sizeof(runtimeKey));
        return result;
    }
};
```

**Uygulama Adımları:**
1. SecureString template'ini güncelle
2. Runtime key generation ekle
3. RDRAND/RDSEED kullan (Intel hardware RNG)
4. Constant folding prevention ekle

---

### 9. 🔴 Information Disclosure (KRİTİK)

**Mevcut Durum:**
- Logo ve mesajlar bilgi sızdırıyor
- Error messages too verbose
- Version information exposed

**Çözüm:**
```cpp
// Minimal information disclosure:

// Generic error messages
const char* GetGenericError() {
    static const char* errors[] = {
        "Operation failed",
        "Access denied",
        "Invalid state",
        "Resource unavailable"
    };
    // Random selection to prevent fingerprinting
    return errors[std::random_device{}() % 4];
}

// Remove version info from binary resources
// Strip PDB paths in release build
// Remove console banners in production

// Logging without sensitive info
void SafeLog(const std::string& category, LogLevel level) {
    // No timestamps that could leak system info
    // No file paths
    // No user-specific data
    std::cout << "[" << category << "] " << GetGenericMessage(level) << std::endl;
}
```

**Uygulama Adımları:**
1. Error message standardization
2. Build configuration cleanup
3. PDB stripping in release
4. Banner/logo removal option

---

### 10. 🟡 sprintf Format String Riski (ORTA)

**Çözüm:**
```cpp
// snprintf veya std::format kullan (C++20)

char buffer[256];
snprintf(buffer, sizeof(buffer), "User: %s", username.c_str());

// C++20 ile:
std::string msg = std::format("User: {}", username);

// Veya stringstream:
std::ostringstream oss;
oss << "User: " << username;
```

---

### 11. 🟡 HKCU Registry Yetki Sorunu (ORTA)

**Çözüm:**
```cpp
// Proper ACL setting:

bool SetRegistryACL(HKEY hKey) {
    EXPLICIT_ACCESS_W ea = {};
    ea.grfAccessPermissions = KEY_READ | KEY_WRITE;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
    
    PSID pSID = nullptr;
    SID_IDENTIFIER_AUTHORITY SIDAuth = SECURITY_NT_AUTHORITY;
    AllocateAndInitializeSid(&SIDAuth, 2, 
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS,
        0, 0, 0, 0, 0, 0, &pSID);
    
    ea.Trustee.ptstrName = (LPSTR)pSID;
    
    PACL pACL = nullptr;
    SetEntriesInAclW(1, &ea, NULL, &pACL);
    
    LONG result = SetSecurityInfo(hKey, SE_REGISTRY_KEY, 
        DACL_SECURITY_INFORMATION, NULL, NULL, pACL, NULL);
    
    LocalFree(pACL);
    FreeSid(pSID);
    
    return result == ERROR_SUCCESS;
}
```

---

### 12. 🟡 SSL Certificate Pinning Eksikliği (ORTA)

**Çözüm:**
```cpp
// WinHTTP ile certificate pinning:

bool VerifyCertificate(HINTERNET hRequest) {
    PCCERT_CONTEXT pCert = nullptr;
    DWORD certSize = sizeof(pCert);
    
    if (!WinHttpQueryOption(hRequest, WINHTTP_OPTION_SERVER_CERT_CONTEXT, 
                            &pCert, &certSize)) {
        return false;
    }
    
    // Expected certificate hash (SHA256)
    const BYTE expectedHash[] = {
        0xAB, 0xCD, 0xEF, ... // Your cert hash
    };
    
    // Calculate actual hash
    BYTE actualHash[32];
    DWORD hashSize = sizeof(actualHash);
    CryptHashCertificate(0, CALG_SHA_256, 0, pCert->pbCertEncoded, 
                         pCert->cbCertEncoded, actualHash, &hashSize);
    
    CertFreeCertificateContext(pCert);
    
    return memcmp(expectedHash, actualHash, sizeof(expectedHash)) == 0;
}
```

---

### 13. 🟡 Exit Code Information Leak (ORTA)

**Çözüm:**
```cpp
// Generic exit codes:

enum class ExitCode : int {
    Success = 0,
    GenericError = 1,
    // No specific error codes that leak info
};

int main() {
    try {
        // ... code
        return static_cast<int>(ExitCode::Success);
    } catch (...) {
        // Log internally but return generic code
        return static_cast<int>(ExitCode::GenericError);
    }
}
```

---

## 📝 Uygulama Önceliklendirmesi

### Phase 1 (Kritik - İlk 2 hafta):
1. ✅ System() çağrılarını kaldır
2. ✅ memcpy_s kullanımı
3. ✅ BCrypt entegrasyonu
4. ✅ Advanced anti-debug

### Phase 2 (Kritik - 2-4 hafta):
5. ✅ Syscall resolver
6. ✅ TOCTOU fix
7. ✅ String obfuscation v2
8. ✅ Information disclosure cleanup

### Phase 3 (Orta - 4-6 hafta):
9. ✅ sprintf → snprintf/std::format
10. ✅ Registry ACL
11. ✅ Certificate pinning
12. ✅ Exit code standardization

### Phase 4 (Test & Validation):
- Static analysis (Cppcheck, PVS-Studio)
- Dynamic analysis (Valgrind, AddressSanitizer)
- Penetration testing
- Code review

---

## 🛠️ Gerekli Kütüphaneler

```cmake
# CMakeLists.txt güncellemesi
target_link_libraries(KeyAuthLoader PRIVATE
    bcrypt.lib      # CNG encryption
    crypt32.lib     # Certificate handling
    ws2_32.lib      # Network (secure)
    advapi32.lib    # Registry transactions
    ntdll.lib       # Syscall access
)
```

---

## 📊 Güvenlik Metrikleri

| Metrik | Mevcut | Hedef |
|--------|--------|-------|
| Critical Vulnerabilities | 10 | 0 |
| Medium Vulnerabilities | 4 | 0 |
| Code Coverage (Security Tests) | ~30% | >90% |
| Static Analysis Issues | High | 0 Critical |
| Anti-Debug Effectiveness | Low | High |
| Encryption Strength | Weak | AES-256-GCM |

---

## ✅ Checklist

- [ ] BCrypt entegrasyonu tamamlandı
- [ ] Tüm memcpy → memcpy_s
- [ ] system() çağrıları kaldırıldı
- [ ] Advanced anti-debug eklendi
- [ ] Syscall resolver implement edildi
- [ ] Transactional registry kullanımı
- [ ] String obfuscation güncellendi
- [ ] Information disclosure temizlendi
- [ ] Format string fix'leri
- [ ] Registry ACL ayarlandı
- [ ] Certificate pinning eklendi
- [ ] Exit code standardization
- [ ] Static analysis passed
- [ ] Penetration test completed
