cmake_minimum_required(VERSION 3.28)

project(Cryptography LANGUAGES CXX)

set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)

add_subdirectory(src)
add_subdirectory(apps)
