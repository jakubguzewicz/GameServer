#include <openssl/ssl.h>

#pragma once

class UserSession {
  public:
    std::unique_ptr<SSL, SslDeleter> ssl;
    uint32_t userID;
};