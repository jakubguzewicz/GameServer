#include <openssl/ssl.h>
#include <ssl_deleter.h>
#include <user_session.hpp>
#include <vector>

#pragma once

class AuthServer {

  public:
    std::unique_ptr<SSL, SslDeleter> ssl;
};

class GameServer {
  public:
    std::unique_ptr<SSL, SslDeleter> ssl;
    std::vector<UserSession> connectedUsers;

    // GameServer(const GameServer &) = delete;
    // GameServer(GameServer &&) = delete;
    // GameServer &operator=(const GameServer &) = delete;
    // GameServer &operator=(GameServer &&) = delete;
    // ~GameServer() = default;
};