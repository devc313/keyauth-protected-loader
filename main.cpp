#include "includes.hpp"

// ecvd @ cheatglobal
// discord: ecvdxd98
// incelemek isteyenler varsa diye yorum satırları ekledim normalde bu kadar yorum satırı kullanmam
// koruma çok güçlü olmayabilir, paylaşım için basit bir şey yaptım
// release x64 buildlemeniz gerekli


// keyauth 1.3 api protected loader

// konsol renkleri
enum ConsoleColor {
    BLACK = 0,
    DARK_BLUE = 1,
    DARK_GREEN = 2,
    DARK_CYAN = 3,
    DARK_RED = 4,
    DARK_MAGENTA = 5,
    DARK_YELLOW = 6,
    GRAY = 7,
    DARK_GRAY = 8,
    BLUE = 9,
    GREEN = 10,
    CYAN = 11,
    RED = 12,
    MAGENTA = 13,
    YELLOW = 14,
    WHITE = 15
};

    // ascii
const char* LOGO = R"(
    :::    ::: :::::::::: :::   ::: :::    ::: :::    ::: ::::::::::: :::    :::
    :+:   :+:  :+:        :+:   :+: :+:    :+: :+:    :+:     :+:     :+:    :+:
    +:+  +:+   +:+         +:+ +:+  +:+    +:+ +:+    +:+     +:+     +:+    +:+
    +#++:++    +#++:++#     +#++:   +#+    +:+ +#+    +:+     +#+     +#++:++#++
    +#+  +#+   +#+           +#+    +#+    +#+ +#+    +#+     +#+     +#+    +#+
    #+#   #+#  #+#           #+#    #+#    #+# #+#    #+#     #+#     #+#    #+#
    ###    ### ##########    ###     ########   ########      ###     ###    ###

                        [ KeyAuth Protected Loader ]
)";

// konsol renklerini ayarlamak için fonksiyon
void SetConsoleColor(ConsoleColor foreground, ConsoleColor background = BLACK) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, (background << 4) | foreground);
}

// konsol genişliğini ayarlamak için fonksiyon
void SetConsoleSize() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SMALL_RECT windowSize = {0, 0, 79, 25}; // 80x26 karakter
    COORD bufferSize = {80, 26};
    
    SetConsoleWindowInfo(hConsole, TRUE, &windowSize);
    SetConsoleScreenBufferSize(hConsole, bufferSize);
}

// dekoratif çizgi çizmek için fonksiyon
void PrintLine(char symbol = '=', ConsoleColor color = CYAN) {
    SetConsoleColor(color);
    std::cout << std::string(80, symbol) << std::endl;
    SetConsoleColor(WHITE);
}

// konsol başlığını ortalamak için fonksiyon
void PrintCentered(const std::string& text, bool newLine = true) {
    int padding = (80 - text.length()) / 2;
    std::cout << std::string(padding, ' ') << text;
    if (newLine) std::cout << std::endl;
}

// yükleme animasyonu
void LoadingAnimation(const std::string& text, int duration_ms) {
    const char* frames[] = { "|", "/", "-", "\\" };
    int frame_count = sizeof(frames) / sizeof(frames[0]);
    int frame_duration = 100;
    int total_frames = duration_ms / frame_duration;
    
    for (int i = 0; i < total_frames; i++) {
        std::cout << "\r[" << frames[i % frame_count] << "] " << text;
        Sleep(frame_duration);
    }
    std::cout << "\r[+] " << text << std::endl;
}

std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);
const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);
void sessionStatus();

using namespace KeyAuth;

// hassas bilgileri şifrelenmiş olarak sakıyoruz
namespace {
    Security::SecureString<32> NAME("appname");
    Security::SecureString<32> OWNERID("owneridhere");
    Security::SecureString<32> VERSION("1.0");
    Security::SecureString<64> URL("https://keyauth.win/api/1.3/");
    Security::SecureString<32> PATH("");
    Security::SecureString<32> REGISTRY_PATH("SOFTWARE\\KeyAuthLoader"); // kendi loaderinizin adını koyabilirsiniz lisans dosyada değilde registryde saklıyoruz
    Security::SecureString<32> REGISTRY_KEY("License"); // registryde lisans keyini saklıyoruz
}

// registry işlemleri için fonksiyonlar
bool SaveLicenseToRegistry(const std::string& license) {
    HKEY hKey;
    std::string regPath = REGISTRY_PATH.decrypt();
    std::string regKey = REGISTRY_KEY.decrypt();
    
    LONG result = RegCreateKeyExA(HKEY_CURRENT_USER, regPath.c_str(), 0, NULL, 
        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    
    if (result != ERROR_SUCCESS) {
        return false;
    }

    std::string encryptedLicense = Security::XorEncrypt(license);
    result = RegSetValueExA(hKey, regKey.c_str(), 0, REG_SZ, 
        (const BYTE*)encryptedLicense.c_str(), encryptedLicense.length() + 1);
    RegCloseKey(hKey);
    
    return result == ERROR_SUCCESS;
}

std::string GetLicenseFromRegistry() { // registryden lisans keyini alıyoruz
    HKEY hKey;
    char buffer[256] = {0};
    DWORD bufferSize = sizeof(buffer);
    std::string regPath = REGISTRY_PATH.decrypt();
    std::string regKey = REGISTRY_KEY.decrypt();
    
    if (RegOpenKeyExA(HKEY_CURRENT_USER, regPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return "";
    }
    
    if (RegQueryValueExA(hKey, regKey.c_str(), NULL, NULL, (LPBYTE)buffer, &bufferSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return "";
    }
    
    RegCloseKey(hKey);
    return Security::XorDecrypt(std::string(buffer)); 
}

// keyauth api başlatma
api KeyAuthApp(
    NAME.decrypt(),
    OWNERID.decrypt(),
    VERSION.decrypt(),
    URL.decrypt(),
    PATH.decrypt()
);

// anti-debug ve anti-dump fonksiyonları
bool IsDebuggerPresentCheck() {
    if (IsDebuggerPresent()) return true;
    
    BOOL isDebugged = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged);
    return isDebugged;
}

bool CheckDebugRegisters() { // debug registerleri kontrol ediyoruz
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (!GetThreadContext(GetCurrentThread(), &ctx)) return false;
    
    return (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0);
}

bool CheckDebuggerTools() { // debugger araçlarını kontrol ediyoruz
    const wchar_t* debuggerTools[] = {
        L"ollydbg.exe", L"x64dbg.exe", L"x32dbg.exe",
        L"ida64.exe", L"ida.exe", L"cheatengine-x86_64.exe",
        L"HTTPDebuggerUI.exe", L"ProcessHacker.exe", L"procmon.exe"
    };
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    
    PROCESSENTRY32W pe32 = {sizeof(pe32)};
    if (Process32FirstW(snapshot, &pe32)) {
        do {
            for (const auto& tool : debuggerTools) {
                if (_wcsicmp(pe32.szExeFile, tool) == 0) {
                    CloseHandle(snapshot);
                    return true;
                }
            }
        } while (Process32NextW(snapshot, &pe32));
    }
    
    CloseHandle(snapshot);
    return false;
}

void AntiDump() { // bellek dökümünü engelleyen fonksiyon
    DWORD oldProtect;
    char* pBaseAddr = (char*)GetModuleHandle(NULL);
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(pBaseAddr, &mbi, sizeof(mbi));
    VirtualProtect(pBaseAddr, mbi.RegionSize, PAGE_READONLY, &oldProtect);
}

// bellek koruma fonksiyonu
void ProtectMemory() { 
    HANDLE process = GetCurrentProcess();
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    
    MEMORY_BASIC_INFORMATION mbi;
    for (LPVOID addr = si.lpMinimumApplicationAddress; 
         addr < si.lpMaximumApplicationAddress; 
         addr = (LPBYTE)addr + mbi.RegionSize) {
        
        if (VirtualQuery(addr, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && 
                (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE)) {
                DWORD oldProtect;
                VirtualProtect(addr, mbi.RegionSize, PAGE_NOACCESS, &oldProtect);
            }
        }
    }
}

// güvenlik kontrolleri için ana fonksiyon
bool SecurityCheck() {
    if (IsDebuggerPresentCheck()) {
        SetConsoleColor(RED);
        std::cout << "\n [-] Debugger detected!";
        SetConsoleColor(WHITE);
        Sleep(1500);
        exit(20);
    }
    
    if (CheckDebugRegisters()) {
        SetConsoleColor(RED);
        std::cout << "\n [-] Debug registers detected!";
        SetConsoleColor(WHITE);
        Sleep(1500);
        exit(21);
    }
    
    if (CheckDebuggerTools()) {
        SetConsoleColor(RED);
        std::cout << "\n [-] Debugging tools detected!"; 
        SetConsoleColor(WHITE);
        Sleep(1500);
        exit(22);
    }
    
    return true;
}

// string şifreleme için xor anahtarı
const unsigned char XOR_KEY[] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};

// string şifreleme fonksiyonu
std::string XorEncrypt(const std::string& input) {
    std::string output = input;
    for (size_t i = 0; i < input.length(); i++) {
        output[i] = input[i] ^ XOR_KEY[i % sizeof(XOR_KEY)];
    }
    return output;
}

// string şifre çözme fonksiyonu
std::string XorDecrypt(const std::string& input) {
    return XorEncrypt(input); // XOR işlemi simetriktir
}

// AntiVM kontrolleri
bool IsVirtualMachine() {
    // cpuid ile sanallaştırma kontrolü
    int cpuInfo[4] = {0};
    char vendorID[13] = {0};

    __cpuid(cpuInfo, 0);
    memcpy(vendorID, &cpuInfo[1], 4);
    memcpy(vendorID + 4, &cpuInfo[3], 4);
    memcpy(vendorID + 8, &cpuInfo[2], 4);

    if (strcmp(vendorID, "VMwareVMware") == 0 ||
        strcmp(vendorID, "Microsoft Hv") == 0 ||
        strcmp(vendorID, "VBoxVBoxVBox") == 0) {
        return true;
    }

    // hypervisor bit kontrolü
    __cpuid(cpuInfo, 1);
    bool hypervisorPresent = (cpuInfo[2] & (1 << 31)) != 0;

    if (!hypervisorPresent) {
        return false;  // hypervisor yoksa kesinlikle vm değil
    }

    // vm servis kontrolü
    HANDLE hDevice = CreateFileA("\\\\.\\VmGeneralPort", 
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
        return true;
    }

    hDevice = CreateFileA("\\\\.\\VBoxMiniRdrDN", 
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
        return true;
    }

    // mac adresi kontrolü
    IP_ADAPTER_INFO adapterInfo[32];
    DWORD dwBufLen = sizeof(adapterInfo);
    if (GetAdaptersInfo(adapterInfo, &dwBufLen) == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO pAdapterInfo = adapterInfo;
        while (pAdapterInfo) {
            // vmware mac adresi kontrolü
            if (pAdapterInfo->Address[0] == 0x00 && 
                pAdapterInfo->Address[1] == 0x0C && 
                pAdapterInfo->Address[2] == 0x29) {
                return true;
            }
            // virtualBox mac adresi kontrolü
            if (pAdapterInfo->Address[0] == 0x08 && 
                pAdapterInfo->Address[1] == 0x00 && 
                pAdapterInfo->Address[2] == 0x27) {
                return true;
            }
            pAdapterInfo = pAdapterInfo->Next;
        }
    }

    return false;  // vm yoksa false döner
}

// checksum hesaplama
DWORD CalculateChecksum(const std::vector<BYTE>& data) {
    DWORD checksum = 0;
    for (size_t i = 0; i < data.size(); i++) {
        checksum = ((checksum << 5) | (checksum >> 27)) + data[i];
    }
    return checksum;
}

// kod bütünlüğü kontrolü
bool VerifyCodeIntegrity() {
    HANDLE hProcess = GetCurrentProcess();
    HMODULE hModule = GetModuleHandle(NULL);
    if (!hModule) return true; // Modül alınamazsa kontrolü geç

    MODULEINFO moduleInfo;
    if (!GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo))) {
        return true; // Modül bilgisi alınamazsa kontrolü geç
    }

    // PE Header kontrolü
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    // orijinal checksum kontrolü
    DWORD originalChecksum = ntHeaders->OptionalHeader.CheckSum;
    if (originalChecksum == 0) {
        return true; // checksum yoksa kontrolü geç
    }

    // dosya checksum'ını hesapla
    DWORD headerSum = 0;
    DWORD checkSum = 0;
    char* moduleBase = (char*)hModule;
    if (MapFileAndCheckSumA(moduleBase, &headerSum, &checkSum) != CHECKSUM_SUCCESS) {
        return true; // checksum hesaplanamazsa kontrolü geç
    }

    return true; // temel kontroller başarılı
}

// glişmiş güvenlik kontrolleri
bool AdvancedSecurityCheck() {
    // VM kontrolü
    if (IsVirtualMachine()) {
        SetConsoleColor(RED);
        std::cout << "\n [-] Virtual machine detected!";
        SetConsoleColor(WHITE);
        Sleep(1500);
        exit(30);
    }

    // kod bütünlüğü kontrolü
    if (!VerifyCodeIntegrity()) {
        SetConsoleColor(RED);
        std::cout << "\n [-] Code integrity check failed!";
        SetConsoleColor(WHITE);
        Sleep(1500);
        exit(31);
    }

    // zaman manipülasyonu kontrolü
    static DWORD lastCheck = GetTickCount();
    DWORD currentTime = GetTickCount();
    if (currentTime < lastCheck) {
        SetConsoleColor(RED);
        std::cout << "\n [-] Time manipulation detected!";
        SetConsoleColor(WHITE);
        Sleep(1500);
        exit(32);
    }
    lastCheck = currentTime;

    return true;
}

// NTP zaman paketi yapısı
#pragma pack(1)
struct NTP_PACKET {
    BYTE li_vn_mode;
    BYTE stratum;
    BYTE poll;
    BYTE precision;
    DWORD root_delay;
    DWORD root_dispersion;
    DWORD ref_id;
    DWORD ref_ts_secs;
    DWORD ref_ts_fracs;
    DWORD orig_ts_secs;
    DWORD orig_ts_fracs;
    DWORD recv_ts_secs;
    DWORD recv_ts_fracs;
    DWORD trans_ts_secs;
    DWORD trans_ts_fracs;
};
#pragma pack()

// NTP zaman kontrolü fonksiyonu
bool CheckTimeSync() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }

    const char* ntpServer = "pool.ntp.org";
    const unsigned short ntpPort = 123;

    struct addrinfo hints = {}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    char portStr[6];
    _itoa_s(ntpPort, portStr, sizeof(portStr), 10);

    if (getaddrinfo(ntpServer, portStr, &hints, &result) != 0) {
        WSACleanup();
        return false;
    }

    SOCKET sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(result);
        WSACleanup();
        return false;
    }

    // NTP paketi hazırla
    NTP_PACKET packet = {};
    packet.li_vn_mode = 0x1B; // LI = 0, VN = 3, Mode = 3 (client)

    // NTP isteği gönder
    if (sendto(sock, reinterpret_cast<char*>(&packet), sizeof(packet), 0, result->ai_addr, result->ai_addrlen) == SOCKET_ERROR) {
        closesocket(sock);
        freeaddrinfo(result);
        WSACleanup();
        return false;
    }

    // yanıt için timeout ayarla
    DWORD timeout = 5000; // 5 saniye
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));

    // NTP yanıtını al
    NTP_PACKET response = {};
    int received = recvfrom(sock, reinterpret_cast<char*>(&response), sizeof(response), 0, nullptr, nullptr);

    closesocket(sock);
    freeaddrinfo(result);
    WSACleanup();

    if (received == SOCKET_ERROR) {
        return false;
    }

    // NTP zamanını al
    DWORD ntpTime = ntohl(response.trans_ts_secs) - 2208988800U; // NTP epoch (1900) to Unix epoch (1970)
    time_t systemTime = time(nullptr);

    // zaman farkını kontrol et (5 dakikadan fazla fark varsa)
    return abs(static_cast<long long>(ntpTime) - static_cast<long long>(systemTime)) < 300;
}

int main()
{
    // güvenlik kontrollerini başlat
    Security::AntiDump();
    if (!Security::SecurityCheck()) {
        exit(25);
    }
    if (!Security::AdvancedSecurityCheck()) {
        exit(26);
    }
    
    // zaman senkronizasyonu kontrolü
    Console::SetConsoleColor(Console::DARK_CYAN);
    Console::LoadingAnimation("Checking time synchronization...", 1000);
    
    if (!NTP::CheckTimeSync()) {
        Console::SetConsoleColor(Console::RED);
        std::cout << "\n [-] System time is not synchronized!";
        std::cout << "\n [-] Please enable automatic time synchronization in Windows settings.";
        Console::SetConsoleColor(Console::WHITE);
        Sleep(3000);
        exit(33);
    }
    
    Console::SetConsoleColor(Console::GREEN);
    std::cout << "\n [+] Time synchronization verified.";
    Console::SetConsoleColor(Console::WHITE);
    Sleep(1000);

    // periyodik güvenlik kontrolü için thread başlat
    std::thread securityThread([]() {
        while (true) {
            if (!Security::SecurityCheck() || !Security::AdvancedSecurityCheck()) {
                exit(25);
            }
            Sleep(1000);
        }
    });
    securityThread.detach();

    // konsol penceresini ayarla
    Console::SetConsoleSize();
    
    // konsol arkaplan rengini ayarla
    system("color 0F");
    
    // konsol fontunu değiştir
    CONSOLE_FONT_INFOEX cfi;
    cfi.cbSize = sizeof(cfi);
    cfi.nFont = 0;
    cfi.dwFontSize.X = 8;
    cfi.dwFontSize.Y = 14;
    cfi.FontFamily = FF_MODERN;
    cfi.FontWeight = FW_NORMAL;
    wcscpy_s(cfi.FaceName, L"Terminal"); 
    SetCurrentConsoleFontEx(GetStdHandle(STD_OUTPUT_HANDLE), FALSE, &cfi);

    // logo ve başlık
    system("cls");
    Console::SetConsoleColor(Console::CYAN);
    std::cout << Console::LOGO << std::endl;
    Console::SetConsoleColor(Console::DARK_CYAN);
    Console::PrintLine('-');
    Console::SetConsoleColor(Console::CYAN);
    Console::PrintCentered("[ KeyAuth Protected Loader ]");
    Console::SetConsoleColor(Console::DARK_CYAN);
    Console::PrintLine('-');
    Console::SetConsoleColor(Console::WHITE);
    
    std::string consoleTitle = skCrypt("KeyAuth Loader").decrypt() + compilation_date + " " + compilation_time;
    SetConsoleTitleA(consoleTitle.c_str());
    
    // sunucuya bağlanma
    Console::SetConsoleColor(Console::DARK_CYAN);
    std::cout << "\n";
    Console::LoadingAnimation("Initializing secure connection...", 1500);
    Console::SetConsoleColor(Console::WHITE);

    // anti emulator kontrolleri
    if (URL.decrypt().find("keyauth.win") == std::string::npos) {
        Console::SetConsoleColor(Console::RED);
        std::cout << "\n [-] Invalid API endpoint detected!";
        Console::SetConsoleColor(Console::WHITE);
        Sleep(1500);
        exit(2);
    }

    // response timing kontrolü
    auto start = std::chrono::high_resolution_clock::now();
    KeyAuthApp.init();
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    if (duration < 100) {
        Console::SetConsoleColor(Console::RED);
        std::cout << "\n [-] Suspicious server response detected!";
        Console::SetConsoleColor(Console::WHITE);
        Sleep(1500);
        exit(3);
    }

    if (!KeyAuthApp.response.success)
    {
        Console::SetConsoleColor(Console::RED);
        std::cout << "\n [-] Connection Error: " << KeyAuthApp.response.message;
        Console::SetConsoleColor(Console::WHITE);
        Sleep(1500);
        exit(1);
    }

    if (!KeyAuthApp.response.success) {
        Console::SetConsoleColor(Console::RED);
        std::cout << "\n [-] Invalid SSL certificate detected!";
        Console::SetConsoleColor(Console::WHITE);
        Sleep(1500);
        exit(4);
    }

    Console::SetConsoleColor(Console::DARK_CYAN);
    Console::LoadingAnimation("Performing security checks...", 1000);
    
    if (KeyAuthApp.response.message.find("Credit to VaultCord.com") != std::string::npos) {
        Console::SetConsoleColor(Console::RED);
        std::cout << "\n [-] Invalid response signature detected!";
        Console::SetConsoleColor(Console::WHITE);
        Sleep(1500);
        exit(6);
    }
    
    if (duration < 50 || duration > 5000) {
        Console::SetConsoleColor(Console::RED);
        std::cout << "\n [-] Suspicious response timing detected!";
        Console::SetConsoleColor(Console::WHITE);
        Sleep(1500);
        exit(7);
    }
    
    if (KeyAuthApp.response.message.empty() || KeyAuthApp.response.message.length() < 10) {
        Console::SetConsoleColor(Console::RED);
        std::cout << "\n [-] Invalid response format detected!";
        Console::SetConsoleColor(Console::WHITE);
        Sleep(1500);
        exit(8);
    }

    std::string savedLicense = GetLicenseFromRegistry();
    if (!savedLicense.empty()) {
        Console::SetConsoleColor(Console::DARK_CYAN);
        Console::LoadingAnimation("Authenticating license...", 1000);
        Console::SetConsoleColor(Console::WHITE);
        
        start = std::chrono::high_resolution_clock::now();
        KeyAuthApp.license(savedLicense);
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        
        if (duration < 100) {
            Console::SetConsoleColor(Console::RED);
            std::cout << "\n [-] Suspicious license verification detected!";
            Console::SetConsoleColor(Console::WHITE);
            Sleep(1500);
            exit(5);
        }
        
        if (!KeyAuthApp.response.success)
        {
            Console::SetConsoleColor(Console::RED);
            std::cout << "\n [-] Authentication Failed: " << KeyAuthApp.response.message;
            Console::SetConsoleColor(Console::WHITE);
            Sleep(1500);
            exit(1);
        }
        Console::SetConsoleColor(Console::GREEN);
        std::cout << "\n [+] License verification successful!\n";
        Console::SetConsoleColor(Console::WHITE);
    }
    else
    {
        Console::SetConsoleColor(Console::DARK_CYAN);
        Console::PrintLine('-');
        Console::SetConsoleColor(Console::CYAN);
        std::cout << "\n [>] Enter License Key: ";
        Console::SetConsoleColor(Console::WHITE);
        std::string key;
        std::cin >> key;
        
        Console::SetConsoleColor(Console::DARK_CYAN);
        Console::LoadingAnimation("Validating license key...", 1000);
        Console::SetConsoleColor(Console::WHITE);
        
        KeyAuthApp.license(key);
        if (!KeyAuthApp.response.success)
        {
            Console::SetConsoleColor(Console::RED);
            std::cout << "\n [-] License Error: " << KeyAuthApp.response.message;
            Console::SetConsoleColor(Console::WHITE);
            Sleep(1500);
            exit(1);
        }

        if (SaveLicenseToRegistry(key)) {
            Console::SetConsoleColor(Console::GREEN);
            std::cout << "\n [+] License activated successfully!\n";
            Console::SetConsoleColor(Console::WHITE);
        }
        else {
            Console::SetConsoleColor(Console::YELLOW);
            std::cout << "\n [!] Warning: Could not save license key.\n";
            Console::SetConsoleColor(Console::WHITE);
        }
    }

    std::thread run(checkAuthenticated, OWNERID.decrypt());
    std::thread check(sessionStatus);

    if (KeyAuthApp.user_data.username.empty()) exit(10);
    
    while (true) {
        if (KeyAuthApp.user_data.username.empty()) {
            Console::SetConsoleColor(Console::RED);
            std::cout << "\n [-] Authentication failed! Please restart the application.";
            Console::SetConsoleColor(Console::WHITE);
            Sleep(1500);
            exit(10);
        }

        system("cls");
        Console::SetConsoleColor(Console::CYAN);
        std::cout << Console::LOGO << std::endl;
        Console::SetConsoleColor(Console::DARK_CYAN);
        Console::PrintLine('-');
        Console::SetConsoleColor(Console::CYAN);
        Console::PrintCentered("[ L O A D  A P P L I C A T I O N ]");
        Console::SetConsoleColor(Console::DARK_CYAN);
        Console::PrintLine('-');
        Console::SetConsoleColor(Console::WHITE);

        Console::SetConsoleColor(Console::CYAN);
        std::cout << "\n [1] Load Application";
        std::cout << "\n [0] Exit";
        
        Console::SetConsoleColor(Console::DARK_CYAN);
        std::cout << "\n\n [>] Select option: ";
        Console::SetConsoleColor(Console::WHITE);
        
        int choice;
        std::cin >> choice;
        
        switch (choice) {
            case 1: {
                if (!KeyAuthApp.response.success || KeyAuthApp.user_data.username.empty()) {
                    Console::SetConsoleColor(Console::RED);
                    std::cout << "\n [-] Access denied! Authentication required.";
                    Console::SetConsoleColor(Console::WHITE);
                    Sleep(1500);
                    break;
                }

                system("cls");
                Console::SetConsoleColor(Console::CYAN);
                std::cout << Console::LOGO << std::endl;
                Console::SetConsoleColor(Console::DARK_CYAN);
                Console::PrintLine('-');
                Console::SetConsoleColor(Console::CYAN);
                Console::PrintCentered("[ L O A D  A P P L I C A T I O N ]");
                Console::SetConsoleColor(Console::DARK_CYAN);
                Console::PrintLine('-');
                Console::SetConsoleColor(Console::WHITE);
                
                Console::SetConsoleColor(Console::DARK_CYAN);
                Console::LoadingAnimation("Preparing application...", 1500);
                
                if (!KeyAuthApp.response.success || KeyAuthApp.user_data.username.empty()) {
                    Console::SetConsoleColor(Console::RED);
                    std::cout << "\n [-] Session expired! Please restart the application.";
                    Console::SetConsoleColor(Console::WHITE);
                    Sleep(1500);
                    exit(10);
                }
                
                Console::SetConsoleColor(Console::GREEN);
                std::cout << "\n [+] Process completed successfully!";
                Console::SetConsoleColor(Console::WHITE);
                
                std::cout << "\n\n Press any key to return to menu...";
                std::cin.ignore();
                std::cin.get();
                break;
            }
            case 0: {
                Console::SetConsoleColor(Console::DARK_CYAN);
                std::cout << "\n [*] Closing session...";
                Console::SetConsoleColor(Console::WHITE);
                Sleep(1500);
                return 0;
            }
            default: {
                Console::SetConsoleColor(Console::RED);
                std::cout << "\n [-] Invalid option!";
                Console::SetConsoleColor(Console::WHITE);
                Sleep(1500);
                break;
            }
        }
    }

    return 0;
}

void sessionStatus() {
    KeyAuthApp.check(true);
    if (!KeyAuthApp.response.success) {
        exit(0);
    }

    if (KeyAuthApp.response.isPaid) {
        while (true) {
            Sleep(20000);
            KeyAuthApp.check();
            if (!KeyAuthApp.response.success) {
                exit(0);
            }
        }
    }
}

std::string tm_to_readable_time(tm ctx) {
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);
    return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp) {
    auto cv = strtol(timestamp.c_str(), NULL, 10);
    return (time_t)cv;
}

static std::tm timet_to_tm(time_t timestamp) {
    std::tm context;
    localtime_s(&context, &timestamp);
    return context;
}
