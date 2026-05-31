# 🔐 KeyAuth Protected Loader - Advanced Security Implementation

[![Build Status](https://github.com/yourusername/keyauth-protected-loader/workflows/Build%20Protected%20Loader/badge.svg)](https://github.com/yourusername/keyauth-protected-loader/actions)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0-green.svg)](https://github.com/yourusername/keyauth-protected-loader/releases)

**Güvenli bir KeyAuth entegrasyonu için geliştirilmiş, çok katmanlı korumalı loader uygulaması.**

Bu proje, KeyAuth API'sini kullanan uygulamalar için **gelişmiş güvenlik katmanları** ekleyen bir loader (yükleyici) uygulamasıdır. Reverse engineering, debug, crack ve analiz araçlarına karşı çoklu koruma mekanizmaları içerir.

## ⚠️ Önemli Not

Bu bir **koruma kütüphanesi değil**, KeyAuth entegrasyonlu **güvenli bir loader uygulamasıdır**. Uygulamanızı çalıştırmadan önce güvenlik kontrolleri yapar, şifrelenmiş iletişim kurar ve yetkisiz erişimleri engeller.

## 🚀 Özellikler

### 🔒 Çok Katmanlı Şifreleme
- **9-Katmanlı Hibrit Şifreleme**: XOR + S-Box + Bit Rotation + Permutation + MAC
- **Compile-Time String Obfuscation**: Oxorany benzeri tekniklerle derleme zamanında string şifreleme
- **SecureString Class**: Hassas veriler için otomatik şifreleme/deşifreleme
- **HMAC Benzeri MAC**: Veri bütünlüğü doğrulama

### 🛡️ Anti-Debug & Anti-Analysis
- **Checkpoint Anti-Debug Teknikleri**: Timing-based detection, PEB analizi
- **Kernel-Level Protection**: Process koruma mekanizmaları
- **Breakpoint Detection**: INT3, hardware breakpoint taraması
- **Timing Attack Detection**: Debugger kaynaklı gecikmeleri algılama
- **VM Detection**: VMware, VirtualBox, QEMU tespiti
- **Emulator Detection**: Bochs, DOSBox tespiti

### 🔍 Sistem Bütünlüğü Kontrolleri
- **Hosts File Check**: Modified hosts dosyası tespiti
- **Proxy Detection**: Sistem proxy ayarları kontrolü
- **Registry Integrity**: Lisans anahtarı güvenliği
- **Process Scanning**: Cheat Engine, x64dbg, IDA Pro gibi araçların tespiti
- **Code Integrity**: CRC64 ile kod bütünlüğü doğrulama

### 🔐 SSL Pinning & Güvenli İletişim
- **Certificate Pinning**: KeyAuth.win sertifikaları sabitlenmiş
  - Sertifika Hash: `d7864f2520cef30934c873a7bf6e10be414ec6ae9c45d35b39b319879ed9f9ca`
  - Public Key Hash: `07d6fed49881218506064dba779b903405d56cc7826a24b15c763cc64ab98356`
- **Secure HTTP Requests**: WinHTTP ile güvenli API iletişimi
- **Man-in-the-Middle Koruması**: SSL stripping saldırılarına karşı koruma

### 🎯 Control Flow Obfuscation
- **Control Flow Flattening**: Cloakwork benzeri akış düzleştirme
- **Opaque Predicates**: Compiler optimizasyonlarını atlatan koşullar
- **Dead Code Insertion**: Analizi zorlaştıran ölü kod blokları

## 📦 Kurulum

### Gereksinimler
- Windows 10/11
- Visual Studio 2019 veya üzeri (MSVC)
- CMake 3.15+
- KeyAuth hesabı ve uygulama anahtarları

### Manuel Derleme

```bash
# Repoyu klonla
git clone https://github.com/yourusername/keyauth-protected-loader.git
cd keyauth-protected-loader

# CMake ile build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

### GitHub Actions ile Otomatik Build

Proje, GitHub Actions kullanarak otomatik olarak derlenir:
- Her push işlemi için Windows-latest üzerinde build
- Release artifact olarak EXE çıktısı
- Tag oluşturulduğunda otomatik release oluşturma

Build dosyaları **Actions** sekmesinden veya **Releases** sayfasından indirilebilir.

## 🔧 Yapılandırma

### KeyAuth Ayarları

`main.cpp` dosyasında kendi KeyAuth bilgilerinizi girin:

```cpp
// main.cpp içinde
keyauth_data.name = SECURE_STR("YOUR_APP_NAME");
keyauth_data.ownerid = SECURE_STR("YOUR_OWNER_ID");
keyauth_data.secret = SECURE_STR("YOUR_APP_SECRET");
keyauth_data.version = SECURE_STR("1.0");
keyauth_data.url = SECURE_STR("https://keyauth.win/api/1.2/");
```

### Güvenlik Seviyesi Ayarlama

```cpp
// Güvenlik kontrollerini özelleştir
#define ENABLE_DEBUG_CHECK      true
#define ENABLE_VM_CHECK         true
#define ENABLE_HOSTS_CHECK      true
#define ENABLE_PROXY_CHECK      true
#define ENABLE_PROCESS_SCAN     true
```

## 📖 Kullanım

### Temel Kullanım

```cpp
#include "SecureCore.h"
#include "KeyAuthManager.h"

int main() {
    // 1. Güvenlik motorunu başlat
    SECURE_INIT("YourMasterSecretKey123!");
    
    // 2. Güvenlik kontrollerini çalıştır
    CHECK_SECURITY();
    
    // 3. KeyAuth yöneticisini başlat
    KeyAuthManager auth;
    
    if (!auth.Initialize()) {
        MessageBoxA(NULL, "Başlatma başarısız!", "Hata", MB_ICONERROR);
        return 1;
    }
    
    // 4. Korunan alanda çalıştır
    RUN_PROTECTED({
        // Login işlemleri
        if (auth.Login(username, password)) {
            // Başarılı login sonrası işlemler
            RunApplication();
        }
    });
    
    return 0;
}
```

### Güvenli String Kullanımı

```cpp
// String'ler otomatik olarak obfuscate edilir
std::string apiUrl = SECURE_STR("https://api.example.com/endpoint");
std::string secretKey = SECURE_STR("super-secret-key-123");

// Runtime'da çözülür, kullanıldıktan sonra bellekten silinir
```

### Özel Güvenlik Kontrolleri

```cpp
// Debugger kontrolü
if (SecurityChecker::IsDebuggerPresent_Advanced()) {
    // Logger'a kaydet veya sessizce çık
    ExitProcess(0);
}

// VM kontrolü
if (SecurityChecker::IsVirtualMachine()) {
    // Farklı davranış sergile
    ShowFakeError();
    ExitProcess(0);
}

// Hosts dosyası kontrolü
if (SecurityChecker::IsHostsModified()) {
    // DNS hijacking denemesi
    ExitProcess(0);
}
```

## 🔬 Teknik Detaylar

### Şifreleme Katmanları

1. **Layer 1**: XOR with Cryptographically Secure Key Stream
2. **Layer 2**: S-Box Substitution (AES-inspired)
3. **Layer 3**: Bit Rotation Left (3 bits)
4. **Layer 4**: XOR with Inverted Key
5. **Layer 5**: Data Permutation
6. **Layer 6**: Second S-Box Substitution
7. **Layer 7**: Conditional Bit Flipping
8. **Layer 8**: Final Bit Rotation Right (2 bits)
9. **Layer 9**: HMAC-SHA256 benzeri MAC Tag Ekleme

### Derlenen String Obfuscation

```cpp
// Derleme zamanında __TIME__ seed'i ile şifreleme
#define OBFUSCATE(str) []() { \
    constexpr auto key = []() { /* compile-time hash */ }(); \
    /* XOR encryption with key */ \
}()
```

### Anti-Debug Teknikleri

- **Timing-Based Detection**: RDTSC/RDTSCP ile instruction timing
- **PEB Analysis**: Process Environment Block debugging flags
- **Hardware Breakpoints**: DR0-DR7 register kontrolü
- **INT3 Detection**: Memory'de 0xCC byte'ları taraması
- **Parent Process Verification**: Explorer.exe dışındaki ebeveynler
- **Window Title Scanning**: Debug tool pencere başlıkları

## 🛡️ Güvenlik En İyi Uygulamaları

1. **Anahtar Yönetimi**: Master key'leri asla kaynak kodda plaintext olarak saklamayın
2. **Katmanlı Savunma**: Tek bir korumaya güvenmeyin, çoklu katman kullanın
3. **Güncellemeler**: Düzenli olarak güvenlik kontrollerini güncelleyin
4. **Monitoring**: Şüpheli aktiviteleri loglayın ve raporlayın
5. **Obfuscation**: Tüm hassas string'leri obfuscate edin

## ⚠️ Yasal Uyarı

Bu yazılım yalnızca **eğitim ve yasal amaçlar** içindir. Geliştiriciler, bu kodu yalnızca kendi uygulamalarını korumak için kullanmalıdır. İzinsiz reverse engineering, crack oluşturma veya kötü amaçlı kullanım yasaktır.

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

## 🤝 Katkıda Bulunma

Katkılarınızı bekliyoruz! Lütfen şu adımları izleyin:

1. Projeyi fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add amazing feature'`)
4. Branch'inizi push edin (`git push origin feature/amazing-feature`)
5. Pull Request açın

## 🐛 Sorun Bildirimi

Bir hata bulursanız veya güvenlik açığı tespit ederseniz, lütfen [Issues](https://github.com/yourusername/keyauth-protected-loader/issues) bölümünden bildirin. Güvenlik açıklarını halka açık şekilde paylaşmadan önce özel olarak bildirmenizi rica ederiz.

## 📚 Kaynaklar

Bu proje aşağıdaki açık kaynak projelerden ilham almıştır:

- [obfusheader.h](https://github.com/ac3ss0r/obfusheader.h) - Compile-time obfuscation
- [oxorany](https://github.com/llxiaoyuan/oxorany) - String encryption
- [Cloakwork](https://github.com/ck0i/Cloakwork) - Control flow flattening
- [XAntiDebug](https://github.com/strivexjun/XAntiDebug) - Anti-debug techniques
- [KeyAuth CPP Example](https://github.com/KeyAuth/KeyAuth-CPP-Example) - Official KeyAuth integration
- [Checkpoint Anti-Debug](https://anti-debug.checkpoint.com/) - Advanced anti-debug research

## 📬 İletişim

- **GitHub**: [@yourusername](https://github.com/yourusername)
- **Discord**: [Community Server](https://discord.gg/yourserver)
- **Email**: your.email@example.com

---

**⚠️ Unutmayın**: Hiçbir güvenlik sistemi %100 kırılmaz değildir. Bu loader, reverse engineering'i zorlaştırmak ve saldırganların işini güçleştirmek için tasarlanmıştır. Derinlemesine savunma stratejisi uygulayın.
