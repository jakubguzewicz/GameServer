#include <openssl/ssl.h>
#include <ssl_deleter.h>
#include <user_session.hpp>

class AuthServer {

  public:
    std::unique_ptr<SSL, SslDeleter> ssl;
};

class GameServer {

  public:
    std::unique_ptr<SSL, SslDeleter> ssl;
    std::vector<UserSession> connectedUsers;
};