#include "main.hpp"
#include <iostream>
#include <thread>

int main(int argc, char const *argv[]) {
    (void)argv;
    (void)argc;

    // Setup empty data structures
    std::vector<GameServer> game_servers;
    std::vector<AuthServer> auth_servers;
    std::vector<UserSession> connected_users;

    // Setup listeners
    std::cout << "Hello there!" << std::endl;

    // TODO: change to read from config file
    std::string client_port = "4720";
    std::string auth_server_port = "4721";
    std::string game_server_port = "4722";

    std::thread clients_listener_thread(listen_for_new_clients_ssl, client_port,
                                        std::ref(connected_users));

    std::thread auth_servers_listener_thread(listen_for_new_auth_servers_ssl,
                                             auth_server_port,
                                             std::ref(auth_servers));

    std::thread game_servers_listener_thread(listen_for_new_game_servers_ssl,
                                             game_server_port,
                                             std::ref(game_servers));

    clients_listener_thread.join();
    auth_servers_listener_thread.join();
    std::cout << "Something went very, very, wrong if you reached here (all "
                 "listener threads ended execution)."
              << std::endl;
}

void listen_for_new_clients_ssl(std::string port,
                                std::vector<UserSession> &users_vector) {

    std::cout << "TODO: setup client listener";
    (void)port;
    (void)users_vector;
}

void listen_for_new_game_servers_ssl(
    std::string port, std::vector<GameServer> &game_servers_vector) {

    std::cout << "TODO: setup server listener" << std::endl;
    (void)port;
    (void)game_servers_vector;
}

void listen_for_new_auth_servers_ssl(
    std::string port, std::vector<AuthServer> &auth_servers_vector) {

    std::cout << "TODO: setup auth server listener" << std::endl;
    (void)port;
    (void)auth_servers_vector;
}
