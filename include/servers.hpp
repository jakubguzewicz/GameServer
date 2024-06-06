#include <functional>
#include <memory>
#include <openssl/ssl.h>
#include <ssl_deleter.h>
#include <unordered_map>
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
    std::unordered_map<uint32_t, UserSession &> connectedUsers;
    explicit GameServer(std::shared_ptr<SSL> ssl) {
        this->ssl = std::shared_ptr<SSL>(std::move(ssl));
    }
};