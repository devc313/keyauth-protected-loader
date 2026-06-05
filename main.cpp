// ecvd @ cheatglobal
// discord: ecvdxd98
// incelemek isteyenler varsa diye yorum satırları ekledim normalde bu kadar yorum satırı kullanmam
// koruma çok güçlü olmayabilir, paylaşım için basit bir şey yaptım
// release x64 buildlemeniz gerekli

// keyauth 1.3 api protected loader with advanced Fatality-inspired protections

#include "includes.hpp"
#include "Project/Protection/AdvancedProtection.h"
#include "LicenseStorage.hpp"

std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);
const std::string compilation_date = CW_STR(__DATE__).decrypt();
const std::string compilation_time = CW_STR(__TIME__).decrypt();
void sessionStatus();

using namespace KeyAuth;

// hassas bilgileri şifrelenmiş olarak saklıyoruz
// global namespace - LicenseStorage.hpp tarafından extern olarak kullanılıyor
Security::SecureString<32> NAME("app name");
Security::SecureString<32> OWNERID("ownerid");
Security::SecureString<32> VERSION("1.0");
Security::SecureString<64> URL("https://keyauth.win/api/1.3/");
Security::SecureString<32> PATH("");
Security::SecureString<32> REGISTRY_PATH("SOFTWARE\\KeyAuthLoader"); // kendi loaderinizin adını koyabilirsiniz
Security::SecureString<32> REGISTRY_KEY("License"); // registryde lisans keyini saklıyoruz

// keyauth api başlatma
api KeyAuthApp(
    NAME.decrypt(),
    OWNERID.decrypt(),
    VERSION.decrypt(),
    URL.decrypt(),
    PATH.decrypt()
);

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
    // Initialize advanced protection system (Fatality-inspired)
    INIT_ADVANCED_PROTECTION();

    // Enable critical process mode during initialization
    BEGIN_CRITICAL_SECTION();

    // Capture environment fingerprint for server binding
    std::string sessionFingerprint = g_AdvancedProtection.GetSessionFingerprint();

    // Security checks
    Security::AntiDump();
    if (!Security::SecurityCheck()) {
        END_CRITICAL_SECTION();
        exit(25);
    }
    if (!Security::AdvancedSecurityCheck()) {
        END_CRITICAL_SECTION();
        exit(26);
    }

    // Disable critical mode after sensitive init
    END_CRITICAL_SECTION();

    // zaman senkronizasyonu kontrolü
    Console::SetConsoleColor(Console::DARK_CYAN);
    Console::LoadingAnimation("Checking time synchronization...", 1000);

    if (!NTP::CheckTimeSync()) {
        Console::SetConsoleColor(Console::YELLOW);
        std::cout << "\n [!] System time sync check failed - continuing anyway.";
        std::cout << "\n [!] Some features may not work correctly.";
        Console::SetConsoleColor(Console::WHITE);
        Sleep(2000);
    }
    else
    {
        Console::SetConsoleColor(Console::GREEN);
        std::cout << "\n [+] Time synchronization verified.";
        Console::SetConsoleColor(Console::WHITE);
        Sleep(1000);
    }

    // Periodic security and protection update thread
    std::thread securityThread([]() {
        while (true) {
            UPDATE_PROTECTION();

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
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, 0x0F);

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

    CW_STACK_STR(loaderPrefix, 'K', 'e', 'y', 'A', 'u', 't', 'h', ' ' , 'L', 'o', 'a', 'd', 'e', 'r');
    std::string consoleTitle = std::string(loaderPrefix) + " " + compilation_date + " " + compilation_time;
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

    Console::SetConsoleColor(Console::DARK_CYAN);
    Console::LoadingAnimation("Performing security checks...", 1000);

    if (KeyAuthApp.response.message.find("Credit to VaultCord.com") != std::string::npos) {
        Console::SetConsoleColor(Console::RED);
        std::cout << "\n [-] Invalid response signature detected!";
        Console::SetConsoleColor(Console::WHITE);
        Sleep(1500);
        exit(6);
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
