#pragma once
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

namespace NTP {
    // NTP paket yapısı
    #pragma pack(1)
    struct Packet {
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

    // NTP zaman kontrolü
    bool CheckTimeSync();
} 