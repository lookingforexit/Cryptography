add_executable(app2
        main.cpp
)

target_compile_features(app2
        PRIVATE
            cxx_std_23
)

set_target_properties(app2
        PROPERTIES
            CXX_MODULE_STD ON
)

target_link_libraries(app2
        PRIVATE
        lib2
)

set_target_properties(app2
        PROPERTIES
            OUTPUT_NAME crypto
)
