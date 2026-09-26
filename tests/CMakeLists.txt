if(EXISTS /usr/src/googletest/CMakeLists.txt)
        add_subdirectory(/usr/src/googletest googletest-build)
else()
        message(FATAL_ERROR "GoogleTest sources were not found. Install the googletest package or provide a project-local GoogleTest source.")
endif()

add_executable(cryptography_tests
        bits_tests.cpp
        context_tests.cpp
        feistel_tests.cpp
        modes_tests.cpp
        padding_tests.cpp
)

target_compile_features(cryptography_tests
        PRIVATE
            cxx_std_23
)

set_target_properties(cryptography_tests
        PROPERTIES
            CXX_MODULE_STD ON
)

target_link_libraries(cryptography_tests
        PRIVATE
            cryptography_lib
            GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(cryptography_tests)
