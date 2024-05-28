#include "ssl_messenger.hpp"
#include "proto/game_messages.pb.h"
#include "servers.hpp"

game_messages::GameMessage
SslMessenger::send_message(game_messages::LogInRequest message,
                           const SSL *ssl_to_be_added) const {
    (void)ssl_to_be_added;
    (void)message;
    return {};
}
game_messages::GameMessage
SslMessenger::send_message(game_messages::LogInResponse message) const {
    (void)message;
    return {};
}
game_messages::GameMessage
SslMessenger::send_message(game_messages::JoinWorldRequest message) const {
    (void)message;
    return {};
}
game_messages::GameMessage
SslMessenger::send_message(game_messages::JoinWorldResponse message) const {
    (void)message;
    return {};
}
game_messages::GameMessage
SslMessenger::send_message(game_messages::ClientUpdateState message,
                           uint32_t game_server_id) const {
    (void)message;
    (void)game_server_id;
    return {};
}
game_messages::GameMessage
SslMessenger::send_message(game_messages::ServerUpdateState message,
                           std::vector<uint32_t> user_ids) const {
    (void)message;
    (void)user_ids;
    return {};
}
game_messages::GameMessage
SslMessenger::send_message(game_messages::ChatMessageRequest message,
                           uint32_t game_server_id) const {
    (void)message;
    (void)game_server_id;
    return {};
}
game_messages::GameMessage
SslMessenger::send_message(game_messages::ChatMessageResponse message) const {
    (void)message;
    return {};
}
