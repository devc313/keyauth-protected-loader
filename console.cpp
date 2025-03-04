#include "console.hpp"
#include <iostream>
#include <iomanip>

namespace Console {
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

    // konsol boyutunu 80x26 karaktere ayarla
    void SetConsoleSize() {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SMALL_RECT windowSize = {0, 0, 79, 25};
        COORD bufferSize = {80, 26};
        
        SetConsoleWindowInfo(hConsole, TRUE, &windowSize);
        SetConsoleScreenBufferSize(hConsole, bufferSize);
    }

    // konsol yazı ve arkaplan rengini ayarla
    void SetConsoleColor(Color foreground, Color background) {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole, (background << 4) | foreground);
    }

    // dekoratif çizgi çiz
    void PrintLine(char symbol, Color color) {
        SetConsoleColor(color);
        std::cout << std::string(80, symbol) << std::endl;
        SetConsoleColor(WHITE);
    }

    // metni konsolun ortasına yazdır
    void PrintCentered(const std::string& text, bool newLine) {
        int padding = (80 - text.length()) / 2;
        std::cout << std::string(padding, ' ') << text;
        if (newLine) std::cout << std::endl;
    }

    // yükleme animasyonu göster
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
} 