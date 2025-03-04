#pragma once
#include <Windows.h>
#include <string>

namespace Console {
    // Konsol renkleri için enum
    enum Color {
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

    // Konsol ayarları
    void SetConsoleSize();
    void SetConsoleColor(Color foreground, Color background = BLACK);
    void PrintLine(char symbol = '=', Color color = CYAN);
    void PrintCentered(const std::string& text, bool newLine = true);
    void LoadingAnimation(const std::string& text, int duration_ms);
    
    // ASCII Art logo
    extern const char* LOGO;
} 