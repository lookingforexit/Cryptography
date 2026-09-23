add_library(cryptography_lib)

target_compile_features(cryptography_lib
        PUBLIC
            cxx_std_23
)

set_target_properties(cryptography_lib
        PROPERTIES
            CXX_MODULE_STD ON
)

target_sources(cryptography_lib
        PUBLIC
            FILE_SET CXX_MODULES FILES
                crypto.bits.cppm
        PRIVATE
            crypto.bits.cpp
)
