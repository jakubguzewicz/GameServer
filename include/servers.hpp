#include <functional>
#include <memory>
#include <openssl/ssl.h>
#include <ssl_deleter.h>
#include <user_session.hpp>
#include <vector>

#pragma once

class AuthServer {

  public:
    std::shared_ptr<SSL> ssl;
};

class GameServer {
  public:
    std::shared_ptr<SSL> ssl;
    std::vector<std::reference_wrapper<UserSession>> connectedUsers;

    // GameServer(const GameServer &) = delete;
    // GameServer(GameServer &&) = delete;
    // GameServer &operator=(const GameServer &) = delete;
    // GameServer &operator=(GameServer &&) = delete;
    // ~GameServer() = default;
};