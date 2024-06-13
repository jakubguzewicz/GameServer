#include "ssl_deleter.h"
#include <memory>
#include <openssl/ssl.h>

#pragma once

class UserSession {
  public:
    std::shared_ptr<SSL> ssl{};
    uint32_t user_ID{};
    uint32_t connected_game_server_ID{};
    explicit UserSession(std::shared_ptr<SSL> ssl) {
        this->ssl = std::shared_ptr<SSL>(std::move(ssl));
    }

    // UserSession(const UserSession &) = delete;
    // UserSession(UserSession &&) = delete;
    // UserSession &operator=(const UserSession &) = delete;
    // UserSession &operator=(UserSession &&) = delete;
    // ~UserSession() = default;
};