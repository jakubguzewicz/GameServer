#include "ssl_messenger.hpp"
#include "proto/game_messages.pb.h"
#include "servers.hpp"
#include "user_session.hpp"
#include <cstdint>
#include <memory>
#include <utility>

void SslMessenger::add_to_login_queue_map(uint32_t session_id,
                                          const std::string &username,
                                          UserSession &user_session) {
    login_queue_map.insert({{username, session_id}, user_session});
}

game_messages::GameMessage
SslMessenger::send_message(game_messages::LogInRequest message,
                           UserSession &user_session_to_be_added) {
    (void)user_session_to_be_added;
    (void)message;

    this->add_to_login_queue_map(this->_session_id_counter++,
                                 message.username(), user_session_to_be_added);

    // Add sending message
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
