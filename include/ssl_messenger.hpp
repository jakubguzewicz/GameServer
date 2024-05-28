#include "proto/game_messages.pb.h"
#include "servers.hpp"
#include "user_session.hpp"
#include <cstdint>
#include <unordered_map>
#include <utility>
#include <vector>

#pragma once

namespace std {
template <> class hash<pair<uint32_t, uint32_t>> {
  public:
    uint64_t operator()(const pair<uint32_t, uint32_t> pair) const {
        // std::hash<int> is already int's value, so no reason to make it more
        // difficult as we can hold whole information in 64 bits.
        return (uint64_t)pair.first +
               ((uint64_t)pair.second << 32); // NOLINT(*magic-numbers);
    }
};
} // namespace std

class SslMessenger {

  private:
    std::unordered_map<uint32_t, GameServer> game_servers{};
    std::unordered_map<uint32_t, AuthServer> auth_servers{};
    std::unordered_map<uint32_t, UserSession> user_sessions{};

    std::unordered_map<std::pair<uint32_t, uint32_t>, UserSession>
        login_queue_map{};

  public:
    SslMessenger(std::unordered_map<uint32_t, GameServer> game_servers,
                 std::unordered_map<uint32_t, AuthServer> auth_servers,
                 std::unordered_map<uint32_t, UserSession> user_sessions,
                 std::unordered_map<std::pair<uint32_t, uint32_t>, UserSession>
                     login_queue_map)
        : game_servers(std::move(game_servers)),
          auth_servers(std::move(auth_servers)),
          user_sessions(std::move(user_sessions)),
          login_queue_map(std::move(login_queue_map)) {}

    SslMessenger() = default;

    game_messages::GameMessage send_message(game_messages::LogInRequest message,
                                            const SSL *ssl_to_be_added) const;
    game_messages::GameMessage
    send_message(game_messages::LogInResponse message) const;
    game_messages::GameMessage
    send_message(game_messages::JoinWorldRequest message) const;
    game_messages::GameMessage
    send_message(game_messages::JoinWorldResponse message) const;
    game_messages::GameMessage
    send_message(game_messages::ClientUpdateState message,
                 uint32_t game_server_id) const;
    game_messages::GameMessage
    send_message(game_messages::ServerUpdateState message,
                 std::vector<uint32_t> user_ids) const;
    game_messages::GameMessage
    send_message(game_messages::ChatMessageRequest message,
                 uint32_t game_server_id) const;
    game_messages::GameMessage
    send_message(game_messages::ChatMessageResponse message) const;
};