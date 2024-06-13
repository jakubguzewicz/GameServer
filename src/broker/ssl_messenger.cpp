#include "ssl_messenger.hpp"
#include "game_messages.pb.h"
#include "servers.hpp"
#include "user_session.hpp"
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <utility>
#include <vector>

using mutex_type = std::shared_timed_mutex;
using read_lock = std::shared_lock<mutex_type>;
using write_lock = std::unique_lock<mutex_type>;

void SslMessenger::add_to_login_queue_map(uint32_t session_id,
                                          const std::string &username,
                                          UserSession &user_session) {
    write_lock lock(_login_mutex);
    login_queue_map.insert({{username, session_id}, user_session});
}

void SslMessenger::send_message(const game_messages::GameMessage &message,
                                SSL &ssl) {
    auto message_string = message.SerializeAsString();
    SSL_write(&ssl, message_string.data(),
              message_string.size()); // NOLINT(*-narrowing-conversions)
}

void SslMessenger::send_message(const std::string &message, SSL &ssl) {
    SSL_write(&ssl, message.data(),
              message.size()); // NOLINT(*-narrowing-conversions)
}

game_messages::GameMessage
SslMessenger::send_message(game_messages::LogInRequest *message,
                           UserSession &user_session_to_be_added) {
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
SslMessenger::send_message(game_messages::LogInResponse *message) {

    // Change state of login queue / user sessions map
    auto user_session_to_be_added =
        login_queue_map.extract({message->username(), message->session_id()});

    // If login was correct, then add to user sessions
    if (message->has_user_id()) {
        write_lock lock(_user_mutex);
        user_sessions.insert_or_assign(
            user_session_to_be_added.mapped().user_ID,
            user_session_to_be_added.mapped());
    }

    // Then send a message
    auto out_message = game_messages::GameMessage();
    out_message.set_allocated_log_in_response(message);
    auto out_message_string = out_message.SerializeAsString();

    this->send_message(out_message_string,
                       *user_session_to_be_added.mapped().ssl);
    return {};
}
game_messages::GameMessage
SslMessenger::send_message(game_messages::JoinWorldRequest *message) const {

    auto out_message = game_messages::GameMessage();
    out_message.set_allocated_join_world_request(message);
    auto out_message_string = out_message.SerializeAsString();

    // For now we send to the first game server
    std::shared_ptr<SSL> ssl;
    // First we need to check if we can send it anywhere
    {
        read_lock lock(_auth_mutex);
        auto iterator = this->game_servers.begin();

        // If we cannot send it, return early
        if (iterator == this->game_servers.end()) {
            return {};
        } else {
            // Right now we just get the first server (as we expect only one
            // atm), later we can change iterator->second.ssl to member function
            // get_auth_server()
            ssl = iterator->second.ssl;
        }
    }

    this->send_message(out_message_string, *ssl);
    return {};
}
game_messages::GameMessage SslMessenger::send_message(
    game_messages::JoinWorldResponse *message,
    GameServer &game_server_to_add_user_session_to) const {

    // Can't user RAII, because of scope issues with reference wrapper
    // constructor. But this case is easy and straightforward
    _user_mutex.lock_shared();
    auto user_session = std::ref(user_sessions.at(message->user_id()));
    _user_mutex.unlock_shared();

    if (message->has_character_data()) {
        // User successfully joined the world, because character data is set
        write_lock lock(_game_mutex);
        game_server_to_add_user_session_to.connectedUsers.insert_or_assign(
            user_session.get().user_ID, user_session.get());
    }

    auto out_message = game_messages::GameMessage();
    out_message.set_allocated_join_world_response(message);
    auto out_message_string = out_message.SerializeAsString();
    this->send_message(out_message_string, *user_session.get().ssl);
    return {};
}
game_messages::GameMessage
SslMessenger::send_message(game_messages::ClientUpdateState *message,
                           uint32_t game_server_id) const {
    auto out_message = game_messages::GameMessage();
    out_message.set_allocated_client_update_state(message);
    auto out_message_string = out_message.SerializeAsString();

    {
        read_lock lock(_game_mutex);
        this->send_message(out_message_string,
                           *this->game_servers.at(game_server_id).ssl);
    }
    return {};
}
game_messages::GameMessage
SslMessenger::send_message(game_messages::ServerUpdateState *message,
                           const GameServer &game_server_session) const {
    auto out_message = game_messages::GameMessage();
    out_message.set_allocated_server_update_state(message);
    auto out_message_string = out_message.SerializeAsString();
    for (const auto &user_session : game_server_session.connectedUsers) {
        this->send_message(out_message_string, *user_session.second.ssl);
    }
    return {};
}
game_messages::GameMessage
SslMessenger::send_message(game_messages::ChatMessageRequest *message,
                           uint32_t game_server_id) const {

    switch (message->chat_group()) {

    case game_messages::CHAT_GROUP_ALL: {
        auto out_message = game_messages::ChatMessageResponse();
        out_message.set_source_user_id(message->user_id());
        out_message.set_chat_group(message->chat_group());
        out_message.set_message(message->message());

        {
            read_lock lock(_game_mutex);
            this->send_message(&out_message,
                               this->game_servers.at(game_server_id));
        }
        break;
    }
    case game_messages::CHAT_GROUP_WHISPER:
    case game_messages::CHAT_GROUP_PARTY: {
        auto out_message = game_messages::GameMessage();
        out_message.set_allocated_chat_message_request(message);
        auto out_message_string = out_message.SerializeAsString();
        {
            read_lock lock(_game_mutex);
            this->send_message(out_message_string,
                               *this->game_servers.at(game_server_id).ssl);
        }
    }
    default: {
        // TODO: Wrong message format
        break;
    }
    }

    (void)message;
    (void)game_server_id;
    return {};
}
game_messages::GameMessage
SslMessenger::send_message(game_messages::ChatMessageResponse *message,
                           const GameServer &game_server_session) const {
    auto out_message = game_messages::GameMessage();
    if (out_message.chat_message_response().chat_group() ==
        game_messages::ChatGroup::CHAT_GROUP_ALL) {
        // As we send messages to everyone on the server, we don't need to look
        // at dest_users_id and we should not send it to everyone => unneeded
        // data to send
        message->clear_dest_users_id();
        out_message.set_allocated_chat_message_response(message);
        auto out_message_string = out_message.SerializeAsString();

        for (auto user_session : game_server_session.connectedUsers) {
            this->send_message(out_message_string, *user_session.second.ssl);
        }
    } else {
        out_message.set_allocated_chat_message_response(message);
        auto out_message_string = out_message.SerializeAsString();
        // We send dest users to party/whisper so it works correctly in case of
        // group whisper messages
        for (auto user_id :
             out_message.chat_message_response().dest_users_id()) {
            read_lock lock(_user_mutex);
            this->send_message(out_message_string,
                               *user_sessions.find(user_id)->second.ssl);
        }
    }

    return {};
}

void SslMessenger::remove_from_game_servers(uint32_t server_id) {
    if (server_id != 0) {
        write_lock lock(_game_mutex);
        this->game_servers.erase(server_id);
    }
}
void SslMessenger::remove_from_user_sessions(uint32_t user_id) {
    if (user_id != 0) {
        write_lock lock(_user_mutex);
        user_sessions.erase(user_id);
    }
}
void SslMessenger::remove_from_auth_servers(uint32_t server_id) {
    if (server_id != 0) {
        write_lock lock(_auth_mutex);
        user_sessions.erase(server_id);
    }
}

void SslMessenger::add_to_game_servers(uint32_t server_id,
                                       GameServer &game_server) {
    if (server_id != 0) {
        write_lock lock(_game_mutex);
        this->game_servers.insert_or_assign(server_id, game_server);
    }
}
void SslMessenger::add_to_auth_servers(uint32_t server_id,
                                       AuthServer &auth_server) {
    if (server_id != 0) {
        write_lock lock(_auth_mutex);
        this->auth_servers.insert_or_assign(server_id, auth_server);
    }
}