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
                crypto.cipher.cppm
                crypto.modes.cppm
                crypto.padding.cppm
                crypto.context.cppm
                crypto.feistel.cppm
        PRIVATE
            crypto.bits.cpp
            crypto.cipher.cpp
            crypto.modes.cpp
            crypto.padding.cpp
            crypto.context.cpp
            crypto.feistel.cpp
)
