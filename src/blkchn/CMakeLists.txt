set(target_name blkchn)

add_executable(${target_name})
set_compile_options(${target_name})

target_sources(
    ${target_name}
    PRIVATE
    main.cpp
)

target_include_directories(
    ${target_name}
    PUBLIC
    ${PROJECT_SOURCE_DIR/blkchn}
)

target_link_libraries(
    ${target_name}
    OpenSSL::SSL
    OpenSSL::Crypto
)
