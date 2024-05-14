#include "main.hpp"
#include <iostream>
#include <sys/socket.h>
#include <sys/types.h>
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

    // TODO: change paths to use config file
    auto cert_path = "certs/client_cert.pem";
    auto key_path = "certs/client_key.pem";

    auto dtls_ctx = SSL_CTX_new(DTLS_server_method());
    if (dtls_ctx == NULL) {
        throw std::runtime_error("Failed to create SSL_CTX");
    }

    SSL_CTX_set_min_proto_version(dtls_ctx, DTLS1_2_VERSION);

    if (!SSL_CTX_use_certificate_file(dtls_ctx, cert_path, SSL_FILETYPE_PEM)) {
        throw std::runtime_error("Failed to load client cert with path: " +
                                 std::string(cert_path));
    }

    if (!SSL_CTX_use_PrivateKey_file(dtls_ctx, key_path, SSL_FILETYPE_PEM)) {
        throw std::runtime_error("Failed to load client key with path: " +
                                 std::string(key_path));
    }

    // It should be a loop from here

    auto dtls_ssl = SSL_new(dtls_ctx);
    if (dtls_ssl == NULL) {
        throw std::runtime_error("Failed to create client listener SSL");
    }

    // TODO: check if needed in mock

    SSL_set_options(dtls_ssl, SSL_OP_COOKIE_EXCHANGE);

    auto sock = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
    if (sock < 0) {
        throw std::runtime_error(
            "Could not create socket fd for client listener");
    }
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
