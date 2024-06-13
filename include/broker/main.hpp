#include "game_messages.pb.h"
#include "login_data.hpp"
#include "servers.hpp"
#include "ssl_messenger.hpp"
#include "user_session.hpp"
#include <openssl/ssl.h>
#include <vector>

int main(int argc, char const *argv[]);

void listen_for_new_clients_ssl(const std::string &port,
                                SslMessenger &ssl_messenger);
void listen_for_new_game_servers_ssl(const std::string &port,
                                     SslMessenger &ssl_messenger);
void listen_for_new_auth_servers_ssl(const std::string &port,
                                     SslMessenger &ssl_messenger);