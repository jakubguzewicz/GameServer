find_package(Protobuf REQUIRED)

target_include_directories(broker PRIVATE broker)
add_subdirectory(proto)