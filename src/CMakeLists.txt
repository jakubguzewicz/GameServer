find_package(OpenSSL REQUIRED)

add_executable(main main.cpp)
add_executable(mock_client mock_dtls_client.cpp)
add_executable(mock_server mock_dtls_server.cpp)
target_link_libraries(main proto_objects OpenSSL::SSL)
target_link_libraries(mock_client proto_objects OpenSSL::SSL)
target_link_libraries(mock_server proto_objects OpenSSL::SSL)


