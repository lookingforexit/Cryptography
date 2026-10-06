add_executable(app1
        main.cpp
)

target_compile_features(app1
        PRIVATE
            cxx_std_23
)

set_target_properties(app1
        PROPERTIES
            CXX_MODULE_STD ON
)

target_link_libraries(app1
        PRIVATE
        lib1
)

set_target_properties(app1
        PROPERTIES
            OUTPUT_NAME crypto
)
