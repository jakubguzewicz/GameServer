#include "main.hpp"
#include <iostream>
#include <thread>

int main(int argc, char const *argv[]) {
    (void)argv;
    (void)argc;

    // Setup empty data structures
    std::vector<GameServer> gameServers;
    std::vector<AuthServer> authServers;
    std::vector<UserSession> connectedUsers;

    // Setup listeners
    std::cout << "Hello there!" << std::endl;

    // TODO: change to read from config file
    std::string client_port = "4720";
    std::string server_port = "4721";

    std::thread clients_listener_thread(listen_for_new_clients_ssl, client_port,
                                        std::ref(connectedUsers));

    std::thread servers_listener_thread(listen_for_new_servers_ssl, server_port,
                                        std::ref(gameServers),
                                        std::ref(authServers));

    clients_listener_thread.join();
    servers_listener_thread.join();
    std::cout << "Something went very, very, wrong if you reached here (both "
                 "listener threads ended execution)."
              << std::endl;
}

void listen_for_new_clients_ssl(std::string port,
                                std::vector<UserSession> &users_vector) {

    std::cout << "TODO: setup client listener";
    (void)port;
    (void)users_vector;
}

void listen_for_new_servers_ssl(std::string port,
                                std::vector<GameServer> &game_servers_vector,
                                std::vector<AuthServer> &auth_servers_vector) {

    std::cout << "TODO: setup server listener" << std::endl;
    (void)port;
    (void)game_servers_vector;
    (void)auth_servers_vector;
}
