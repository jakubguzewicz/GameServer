find_package(OpenSSL REQUIRED)

add_executable(broker main.cpp)
target_sources(broker PRIVATE ssl_messenger.cpp)
target_link_libraries(broker proto_objects OpenSSL::SSL)

