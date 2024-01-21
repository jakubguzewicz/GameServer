find_package(OpenSSL REQUIRED)

add_executable(main main.cpp)
add_executable(mock mock_dtls_client.cpp)
target_link_libraries(main proto_objects OpenSSL::SSL)
target_link_libraries(mock proto_objects OpenSSL::SSL)


