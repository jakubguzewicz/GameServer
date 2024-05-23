#include "proto/game_messages.pb.h"
#include "servers.hpp"
#include "user_session.hpp"
#include <cstdint>
#include <unordered_map>
#include <vector>

#pragma once

class SslMessenger {

  private:
    std::unordered_map<uint32_t, GameServer> game_servers{};
    std::unordered_map<uint32_t, AuthServer> auth_servers{};
    std::unordered_map<uint32_t, UserSession> user_sessions{};

  public:
    SslMessenger(const std::unordered_map<uint32_t, GameServer> &game_servers,
                 const std::unordered_map<uint32_t, AuthServer> &auth_servers,
                 const std::unordered_map<uint32_t, UserSession> &user_sessions)
        : game_servers(game_servers), auth_servers(auth_servers),
          user_sessions(user_sessions) {}

    game_messages::GameMessage send_message(game_messages::LogInRequest) const;
    game_messages::GameMessage send_message(game_messages::LogInResponse) const;
    game_messages::GameMessage
        send_message(game_messages::JoinWorldRequest) const;
    game_messages::GameMessage
        send_message(game_messages::JoinWorldResponse) const;
    game_messages::GameMessage send_message(game_messages::ClientUpdateState,
                                            uint32_t game_server_id) const;
    game_messages::GameMessage
    send_message(game_messages::ServerUpdateState,
                 std::vector<uint32_t> user_ids) const;
    game_messages::GameMessage
        send_message(game_messages::ChatMessageRequest) const;
    game_messages::GameMessage
        send_message(game_messages::ChatMessageResponse) const;
};