#include "login_data.hpp"
#include "proto/game_messages.pb.h"
#include "servers.hpp"
#include "user_session.hpp"
#include <openssl/ssl.h>
#include <vector>

int main(int argc, char const *argv[]);

void listen_for_new_clients_ssl(
    const std::string &port,
    std::unordered_map<uint32_t, UserSession> &users_map);
void listen_for_new_game_servers_ssl(
    const std::string &port,
    std::unordered_map<uint32_t, GameServer> &game_servers_map);
void listen_for_new_auth_servers_ssl(
    const std::string &port,
    std::unordered_map<uint32_t, AuthServer> &auth_servers_map);