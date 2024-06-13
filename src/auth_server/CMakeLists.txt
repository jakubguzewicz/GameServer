find_package(OpenSSL REQUIRED)

add_executable(auth_server main.cpp)
target_link_libraries(auth_server proto_objects OpenSSL::SSL)

