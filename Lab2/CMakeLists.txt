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
