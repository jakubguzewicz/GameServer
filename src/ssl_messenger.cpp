#include "ssl_messenger.hpp"
#include "proto/game_messages.pb.h"
#include "servers.hpp"
#include "user_session.hpp"
#include <cstdint>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <utility>

using mutex_type = std::shared_timed_mutex;
using read_lock = std::shared_lock<mutex_type>;
using write_lock = std::unique_lock<mutex_type>;

void SslMessenger::add_to_login_queue_map(uint32_t session_id,
                                          const std::string &username,
                                          UserSession &user_session) {
    write_lock lock(_login_mutex);
    login_queue_map.insert({{username, session_id}, user_session});
}

game_messages::GameMessage
SslMessenger::send_message(game_messages::LogInRequest *message,
                           UserSession &user_session_to_be_added) {
    (void)user_session_to_be_added;
    (void)message;

    std::shared_ptr<SSL> ssl;
    // First we need to check if we can send it anywhere
    {
        read_lock lock(_auth_mutex);
        auto iterator = this->auth_servers.begin();

        // If we cannot send it, return early
        if (iterator == this->auth_servers.end()) {
            return {};
        } else {
            // Right now we just get the first server (as we expect only one
            // atm), later we can change iterator->second.ssl to member function
            // get_auth_server()
            ssl = iterator->second.ssl;
        }
    }

    this->add_to_login_queue_map(this->_session_id_counter++,
                                 message->username(), user_session_to_be_added);

    auto to_send = game_messages::GameMessage();
    to_send.set_allocated_log_in_request(message);

    send_message(to_send, *ssl);
    return {};
}
game_messages::GameMessage
SslMessenger::send_message(game_messages::LogInResponse &message) {
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
