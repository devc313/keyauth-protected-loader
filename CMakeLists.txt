cmake_minimum_required(VERSION 3.15)

# Platform check - This project is Windows-only
if(NOT WIN32)
    message(FATAL_ERROR "This project is Windows-only and cannot be built on Linux/Unix systems. Please use Visual Studio on Windows.")
endif()

project(KeyAuthProtectedLoader VERSION 2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Release optimizations
if(MSVC)
    add_compile_options(/O2 /Ob2 /Oi /Ot /GL /GS- /fp:fast)
    add_link_options(/LTCG /OPT:REF /OPT:ICF)
endif()

# Add executable with all source files
add_executable(ProtectedLoader 
    main.cpp
    console.cpp
    security.cpp
    ntp.cpp
)

# Link required libraries
target_link_libraries(ProtectedLoader PRIVATE
    bcrypt
    winhttp
    ws2_32
    crypt32
    advapi32
    ntdll
    imagehlp
    iphlpapi
)

# Set subsystem to Windows (no console)
set_target_properties(ProtectedLoader PROPERTIES
    WIN32_EXECUTABLE FALSE
    VS_DPI_AWARE "PerMonitor"
)

# Include directories
target_include_directories(ProtectedLoader PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Post-build event to strip debug info (optional, comment out if manifest doesn't exist)
# if(MSVC)
#     add_custom_command(TARGET ProtectedLoader POST_BUILD
#         COMMAND mt.exe -manifest \"${CMAKE_CURRENT_SOURCE_DIR}\\loader.manifest\" -outputresource:\"$<TARGET_FILE:ProtectedLoader>\"\;#1
#         COMMENT "Embedding manifest..."
#     )
# endif()
