#include "ssl_deleter.h"
#include <memory>
#include <openssl/ssl.h>

#pragma once

class UserSession {
  public:
    std::unique_ptr<SSL, SslDeleter> ssl{};
    uint32_t user_ID{};
    uint32_t connected_game_server_ID{};
    explicit UserSession(std::unique_ptr<SSL, SslDeleter> ssl)
        : ssl(std::move(ssl)) {}
};