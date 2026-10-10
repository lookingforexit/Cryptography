add_library(lib2)

target_compile_features(lib2
        PUBLIC
            cxx_std_23
)

set_target_properties(lib2
        PROPERTIES
            CXX_MODULE_STD ON
)

target_sources(lib2
        PUBLIC
            FILE_SET CXX_MODULES FILES
                crypto.number_theory.cppm
        PRIVATE
            crypto.number_theory.cpp
)

target_link_libraries(lib2
        PUBLIC
            boost_headers
)
