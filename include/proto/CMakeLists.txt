include_directories(${Protobuf_INCLUDE_DIR})
add_library(proto_objects game_messages.proto)
target_link_libraries(proto_objects INTERFACE protobuf::libprotobuf)
protobuf_generate(
    TARGET proto_objects
    PROTOC_OPTIONS --experimental_allow_proto3_optional
)
message("hello there")
message(${CMAKE_CURRENT_BINARY_DIR})
