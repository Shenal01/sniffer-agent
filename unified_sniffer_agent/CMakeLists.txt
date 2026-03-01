cmake_minimum_required(VERSION 3.20)
project(MinimalSnifferTest VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)

# Point to your manual Npcap SDK
set(NPCAP_SDK_DIR "C:/NpcapSDK" CACHE PATH "Path to Npcap SDK")

# Point to your manual MariaDB Connector/C
set(MARIADB_DIR "C:/Program Files/MariaDB/MariaDB Connector C 64-bit" CACHE PATH "Path to MariaDB Connector/C")

# Include directories
include_directories(
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/deps"
    "${CMAKE_CURRENT_SOURCE_DIR}/deps/fmt"
    "${CMAKE_CURRENT_SOURCE_DIR}/deps/nlohmann"
    "${NPCAP_SDK_DIR}/Include"
    "${MARIADB_DIR}/include"
)

if (WIN32)
    # Target dependencies
    set(LIBS_TO_LINK Ws2_32.lib Iphlpapi.lib)
    
    # Npcap libs
    link_directories("${NPCAP_SDK_DIR}/Lib/x64")
    list(APPEND LIBS_TO_LINK wpcap.lib Packet.lib)

    # MariaDB libs
    link_directories("${MARIADB_DIR}/lib")
    list(APPEND LIBS_TO_LINK libmariadb.lib)
endif()

# Source files
file(GLOB_RECURSE SOURCES "src/*.cpp" "src/*.c")
# Exclude the minimal test from the full build
list(FILTER SOURCES EXCLUDE REGEX "minimal_test\\.cpp$")

# Add the executable
add_executable(UnifiedSnifferAgent ${SOURCES})

# Hide the console window on Windows while keeping standard 'main'
if (MSVC)
    set_target_properties(UnifiedSnifferAgent PROPERTIES LINK_FLAGS "/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup")
endif()

# Link the libraries
target_link_libraries(UnifiedSnifferAgent PRIVATE 
    ${LIBS_TO_LINK}
)

if (MSVC)
    target_compile_definitions(UnifiedSnifferAgent PRIVATE _WIN32_WINNT=0x0601)
    target_compile_definitions(UnifiedSnifferAgent PRIVATE FMT_HEADER_ONLY)
    target_compile_options(UnifiedSnifferAgent PRIVATE /utf-8)
endif()


