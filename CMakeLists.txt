cmake_minimum_required(VERSION 3.20)

project(FlagraeNX LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(FlagraeNX
    src/main.c
)