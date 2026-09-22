add_executable(cryptography_app
        main.cpp
)

target_compile_features(cryptography_app
        PRIVATE
            cxx_std_23
)

target_link_libraries(cryptography_app
        PRIVATE
            cryptography_lib
)

set_target_properties(cryptography_app
        PROPERTIES
            OUTPUT_NAME crypto
)
