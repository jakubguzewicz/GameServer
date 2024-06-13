#include "game_messages.pb.h"
#include "servers.hpp"
#include "user_session.hpp"
#include <boost/functional/hash.hpp>
#include <cstdint>
#include <memory>
#include <shared_mutex>
#include <unordered_map>
#include <utility>
#include <vector>

#pragma once

class SslMessenger {

    using mutex_type = std::shared_timed_mutex;

  private:
    mutable mutex_type _auth_mutex;
    mutable mutex_type _game_mutex;
    mutable mutex_type _user_mutex;
    mutable mutex_type _login_mutex;
    uint32_t _session_id_counter = 0;
    std::unordered_map<uint32_t, GameServer &> game_servers{};
    std::unordered_map<uint32_t, AuthServer &> auth_servers{};
    std::unordered_map<uint32_t, UserSession &> user_sessions{};

    std::unordered_map<std::pair<std::string, uint32_t>, UserSession &,
                       boost::hash<std::pair<std::string, uint32_t>>>
        login_queue_map{};

    static void send_message(const game_messages::GameMessage &message,
                             SSL &ssl);
    static void send_message(const std::string &message, SSL &ssl);

  public:
    SslMessenger(
        std::unordered_map<uint32_t, GameServer &> game_servers,
        std::unordered_map<uint32_t, AuthServer &> auth_servers,
        std::unordered_map<uint32_t, UserSession &> user_sessions,
        std::unordered_map<std::pair<std::string, uint32_t>, UserSession &,
                           boost::hash<std::pair<std::string, uint32_t>>>
            login_queue_map)
        : game_servers(std::move(game_servers)),
          auth_servers(std::move(auth_servers)),
          user_sessions(std::move(user_sessions)),
          login_queue_map(std::move(login_queue_map)) {}

    SslMessenger() = default;

    void add_to_login_queue_map(uint32_t session_id,
                                const std::string &username,
                                UserSession &user_session);

    void remove_from_game_servers(uint32_t server_id);
    void remove_from_user_sessions(uint32_t user_id);
    void remove_from_auth_servers(uint32_t server_id);

    void add_to_game_servers(uint32_t server_id, GameServer &game_server);
    void add_to_auth_servers(uint32_t server_id, AuthServer &auth_server);
    // You should not publicly add users to game session, add them by processing
    // login messages logic
    void add_to_users() = delete;

    game_messages::GameMessage
    send_message(game_messages::LogInRequest *message,
                 UserSession &user_session_to_be_added);
    game_messages::GameMessage
    send_message(game_messages::LogInResponse *message);
    game_messages::GameMessage
    send_message(game_messages::JoinWorldRequest *message) const;
    game_messages::GameMessage
    send_message(game_messages::JoinWorldResponse *message,
                 GameServer &game_server_to_add_user_session_to) const;
    game_messages::GameMessage
    send_message(game_messages::ClientUpdateState *message,
                 uint32_t game_server_id) const;
    game_messages::GameMessage
    send_message(game_messages::ServerUpdateState *message,
                 const GameServer &game_server_session) const;
    game_messages::GameMessage
    send_message(game_messages::ChatMessageRequest *message,
                 uint32_t game_server_id) const;
    game_messages::GameMessage
    send_message(game_messages::ChatMessageResponse *message,
                 const GameServer &game_server_session) const;
};