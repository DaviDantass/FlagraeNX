cmake_minimum_required(VERSION 3.20)
project(FlagraeNX LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(NPCAP_SDK_DIR "D:\\Dev\\npcap-sdk-1.16")
include_directories("${NPCAP_SDK_DIR}/Include")

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    # compilador for de 64-bits
    link_directories("${NPCAP_SDK_DIR}/Lib/x64")
else()
    # compilador for de 32-bits
    link_directories("${NPCAP_SDK_DIR}/Lib")
endif()

add_executable(FlagraeNX
    src/main.c
)

target_link_libraries(FlagraeNX wpcap ws2_32)