add_library(cryptography_lib)

target_compile_features(cryptography_lib
        PUBLIC
            cxx_std_23
)

target_sources(cryptography_lib
        PUBLIC
            FILE_SET CXX_MODULES FILES
                crypto.bits.cppm
        PRIVATE
            crypto.bits.cpp
)
