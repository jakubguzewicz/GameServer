#include <openssl/ssl.h>
#include <ssl_deleter.h>
#include <user_session.hpp>

class Server {

  public:
    std::unique_ptr<SSL, SslDeleter> ssl;
};

class GameServer : public Server {

  public:
    std::vector<UserSession> connectedUsers;
};