if(NOT TARGET gtest)
    if(EXISTS /usr/src/googletest/CMakeLists.txt)
        add_subdirectory(/usr/src/googletest googletest-build)
    else()
        message(FATAL_ERROR "GoogleTest sources were not found. Install the googletest package or provide a project-local GoogleTest source.")
    endif()
endif()

add_executable(tests2
        number_theory_tests.cpp
)

target_compile_features(tests2
        PRIVATE
            cxx_std_23
)

set_target_properties(tests2
        PROPERTIES
            CXX_MODULE_STD ON
)

target_link_libraries(tests2
        PRIVATE
        lib2
            GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(tests2)
