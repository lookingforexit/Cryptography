find_package(GTest CONFIG REQUIRED)

add_executable(cryptography_tests
        bits_tests.cpp
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
