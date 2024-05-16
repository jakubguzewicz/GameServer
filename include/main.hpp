#include "login_data.hpp"
#include "proto/game_messages.pb.h"
#include "servers.hpp"
#include "user_session.hpp"
#include <openssl/ssl.h>
#include <vector>

int main(int argc, char const *argv[]);

void listen_for_new_clients_ssl(const std::string &port,
                                std::vector<UserSession> &users_vector);
void listen_for_new_game_servers_ssl(
    const std::string &port, std::vector<GameServer> &game_servers_vector);
void listen_for_new_auth_servers_ssl(
    const std::string &port, std::vector<AuthServer> &auth_servers_vector);