#pragma once

#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <iphlpapi.h>
#include <imagehlp.h>
#include "auth.hpp"
#include <string>
#include <thread>
#include "utils.hpp"
#include "skStr.h"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <TlHelp32.h>
#include <Psapi.h>
#include <intrin.h>
#include <vector>
#include <random>
#include "security.hpp"
#include "console.hpp"
#include "ntp.hpp"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "imagehlp.lib") 