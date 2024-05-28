find_package(OpenSSL REQUIRED)

add_executable(main main.cpp)
target_sources(main PRIVATE ssl_messenger.cpp)
target_link_libraries(main proto_objects OpenSSL::SSL)

