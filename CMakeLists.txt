cmake_minimum_required(VERSION 3.15)
project(KeyAuthProtectedLoader VERSION 2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Release optimizations
if(MSVC)
    add_compile_options(/O2 /Ob2 /Oi /Ot /GL /GS- /fp:fast)
    add_link_options(/LTCG /OPT:REF /OPT:ICF)
endif()

# Add executable
add_executable(ProtectedLoader main.cpp)

# Link required libraries
target_link_libraries(ProtectedLoader PRIVATE
    bcrypt
    winhttp
    ws2_32
)

# Set subsystem to Windows (no console)
set_target_properties(ProtectedLoader PROPERTIES
    WIN32_EXECUTABLE TRUE
    VS_DPI_AWARE "PerMonitor"
)

# Post-build event to strip debug info (optional)
if(MSVC)
    add_custom_command(TARGET ProtectedLoader POST_BUILD
        COMMAND mt.exe -manifest \"${CMAKE_CURRENT_SOURCE_DIR}\\loader.manifest\" -outputresource:\"$<TARGET_FILE:ProtectedLoader>\"\;#1
        COMMENT "Embedding manifest..."
    )
endif()
