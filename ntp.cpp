#include "ntp.hpp"
#include <iostream>

namespace NTP {
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
        Packet packet = {};
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
        Packet response = {};
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
} 