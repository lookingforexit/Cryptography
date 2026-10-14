cmake_minimum_required(VERSION 3.30)

# CMake's import-std support is experimental in these releases and uses a
# version-specific opt-in token. Set it before project() enables CXX.
if(CMAKE_VERSION VERSION_GREATER_EQUAL 4.4.0)
    set(CMAKE_EXPERIMENTAL_CXX_IMPORT_STD "f35a9ac6-8463-4d38-8eec-5d6008153e7d")
elseif(CMAKE_VERSION VERSION_GREATER_EQUAL 4.3.0)
    set(CMAKE_EXPERIMENTAL_CXX_IMPORT_STD "451f2fe2-a8a2-47c3-bc32-94786d8fc91b")
elseif(CMAKE_VERSION VERSION_GREATER_EQUAL 4.0.3)
    set(CMAKE_EXPERIMENTAL_CXX_IMPORT_STD "d0edc3af-4c50-42ea-a356-e2862fe7a444")
elseif(CMAKE_VERSION VERSION_GREATER_EQUAL 4.0.0)
    set(CMAKE_EXPERIMENTAL_CXX_IMPORT_STD "a9e1cf81-9932-4810-974b-6eccaf14e457")
elseif(CMAKE_VERSION VERSION_GREATER_EQUAL 3.31.8)
    set(CMAKE_EXPERIMENTAL_CXX_IMPORT_STD "d0edc3af-4c50-42ea-a356-e2862fe7a444")
elseif(CMAKE_VERSION VERSION_GREATER_EQUAL 3.30.0)
    set(CMAKE_EXPERIMENTAL_CXX_IMPORT_STD "0e5b6991-d74f-4b3d-a41c-cf096e0b2508")
endif()

project(Cryptography LANGUAGES CXX)

include(FetchContent)

# Boost.Multiprecision is header-only. Populate the Boost source archive, but
# do not configure Boost's own build: Lab2 only needs its headers.
FetchContent_Declare(
    boost
    URL https://archives.boost.io/release/1.92.0/source/boost_1_92_0.tar.bz2
    URL_HASH SHA256=5c1d40cb8e19adbf740a4ec2da35b3e58f3f5804b1dce44deb53df72193cbc6c
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    SOURCE_SUBDIR _boost_headers_only
)
FetchContent_MakeAvailable(boost)

add_library(boost_headers INTERFACE)
target_include_directories(boost_headers SYSTEM INTERFACE "${boost_SOURCE_DIR}")

add_subdirectory(src)
add_subdirectory(apps)

if(BUILD_TESTING)
    file(GLOB LAB2_TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp")
    if(LAB2_TEST_SOURCES)
        add_subdirectory(tests)
    endif()
endif()
