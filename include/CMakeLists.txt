find_package(Protobuf REQUIRED)

target_include_directories(broker PRIVATE broker)
target_include_directories(auth_server PRIVATE auth_server)
add_subdirectory(proto)