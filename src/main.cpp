#include "main.hpp"
#include "proto/game_messages.pb.h"
#include "ssl_deleter.h"
#include "ssl_messenger.hpp"
#include "user_session.hpp"
#include <array>
#include <cstdint>
#include <functional>
#include <iostream>
#include <memory>
#include <openssl/bio.h>
#include <openssl/prov_ssl.h>
#include <openssl/ssl.h>
#include <openssl/types.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {

    (void)ssl;
    (void)cookie;
    (void)cookie_len;
    // just a quick check, this cookie is not normal
    for (int i = 0; i < 20; i++) {
        cookie[i] = (char)'a' + i;
    }
    cookie_len[0] = 20u;

    return 1;
}
int verify_cookie(SSL *ssl, const unsigned char *cookie,
                  unsigned int cookie_len) {
    (void)ssl;
    (void)cookie;
    (void)cookie_len;

    return 1;
}

SSL_CTX *setup_new_dtls_ctx(const std::string &cert_path,
                            const std::string &key_path) {
    auto *dtls_ctx = SSL_CTX_new(DTLS_server_method());
    if (dtls_ctx == nullptr) {
        throw std::runtime_error("Failed to create SSL_CTX");
    }

    SSL_CTX_set_min_proto_version(dtls_ctx, DTLS1_2_VERSION);

    if (SSL_CTX_use_certificate_file(dtls_ctx, cert_path.c_str(),
                                     SSL_FILETYPE_PEM) != 1) {
        throw std::runtime_error("Failed to load client cert with path: " +
                                 std::string(cert_path));
    }

    if (SSL_CTX_use_PrivateKey_file(dtls_ctx, key_path.c_str(),
                                    SSL_FILETYPE_PEM) != 1) {
        throw std::runtime_error("Failed to load client key with path: " +
                                 std::string(key_path));
    }

    return dtls_ctx;
}

SSL_CTX *setup_new_tls_ctx(const std::string &cert_path,
                           const std::string &key_path) {
    auto *tls_ctx = SSL_CTX_new(TLS_server_method());
    if (tls_ctx == nullptr) {
        throw std::runtime_error("Failed to create SSL_CTX");
    }

    SSL_CTX_set_min_proto_version(tls_ctx, TLS1_3_VERSION);

    if (SSL_CTX_use_certificate_file(tls_ctx, cert_path.c_str(),
                                     SSL_FILETYPE_PEM) != 1) {
        throw std::runtime_error("Failed to load client cert with path: " +
                                 std::string(cert_path));
    }

    if (SSL_CTX_use_PrivateKey_file(tls_ctx, key_path.c_str(),
                                    SSL_FILETYPE_PEM) != 1) {
        throw std::runtime_error("Failed to load client key with path: " +
                                 std::string(key_path));
    }

    return tls_ctx;
}

void setup_dtls_listener_socket(int main_fd, SSL &ssl,
                                BIO_ADDRINFO *server_addrinfo) {

    // For each separate connection we need to make these steps:
    // 1. Create SSL object for new connection (passsed here as argument)
    // 2. Create BIO object for new connection and pass it to SSL
    // 3. Set fd in BIO to the fd used for new connections (the same for all new
    // connections)
    // --------------------------
    // 4. Listen for new connections, but don't process the handshake -
    // DTLSv1_listen() is responsible for that
    // --------------------------
    // 5. Create new fd and bind it to the server address and connect it to the
    // peer address given by DTLSv1_listen()
    // 6. Swap the fd in new connection BIO/SSL to the newly made fd
    // --------------------------
    // 7. Finish the handshake
    // 8. Create new thread with new SSL connection

    // Create fd used for the new connection
    auto sock = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
    if (sock < 0) {
        throw std::runtime_error(
            "Could not create socket fd for client listener");
    }

    // Set up bio with fd listening for new connections
    auto *bio = BIO_new_dgram(main_fd, BIO_NOCLOSE);
    SSL_set_bio(&ssl, bio, bio);

    // Listen for the handshake of new connection and save it's connection tuple
    // to peer pointer
    BIO_ADDR *peer = BIO_ADDR_new();
    DTLSv1_listen(&ssl, peer);

    // After we got new connection, it's time to:
    // 1. bind our new fd to listen on server socket
    // 2. connect our new fd to peer, whose address we've just got.
    BIO_bind(sock, BIO_ADDRINFO_address(server_addrinfo), BIO_SOCK_REUSEADDR);
    BIO_connect(sock, peer, 0);

    // Set the bio in ssl to newly made bio
    SSL_set_bio(&ssl, bio, bio);

    // Change fd in bio to the newly set up fd and pass it as connected
    BIO_set_fd(bio, sock, BIO_CLOSE);
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &peer);

    SSL_set_options(&ssl, SSL_OP_COOKIE_EXCHANGE);

    // We can free addr, values are stored in system kernel by now.
    BIO_ADDR_free(peer);
}

int setup_tls_listener_socket(const std::string &port) {
    auto sock = BIO_socket(AF_INET, SOCK_PACKET, 0, 0);
    if (sock < 0) {
        throw std::runtime_error(
            "Could not create socket fd for client listener");
    }

    BIO_ADDRINFO *addrinfo = nullptr;

    BIO_lookup_ex("0.0.0.0", port.c_str(), BIO_LOOKUP_SERVER, AF_INET,
                  SOCK_PACKET, 0, &addrinfo);

    if (addrinfo == nullptr) {
        throw std::runtime_error(
            "Could not lookup ADDRINFO for client listener");
    }

    if (BIO_listen(sock, BIO_ADDRINFO_address(addrinfo), BIO_SOCK_REUSEADDR) ==
        0) {
        throw std::runtime_error(
            "Could not start listening in client listener");
    }

    // There is no need to keep addrinfo anymore, needed data is already stored
    // in os kernel.

    BIO_ADDRINFO_free(addrinfo);

    return sock;
}

void handle_client_connection(std::shared_ptr<SSL> ssl,
                              SslMessenger &ssl_messenger) {

    const auto MAX_DTLS_RECORD_SIZE = 16384;

    auto user_session = UserSession(std::move(ssl));

    // Maximum DTLS record size is 16kB and single read can return only exactly
    // one record.
    auto buf = std::array<char, MAX_DTLS_RECORD_SIZE>();
    size_t readbytes = 0;

    while (SSL_get_shutdown(user_session.ssl.get()) == 0) {

        if (SSL_read_ex(user_session.ssl.get(), buf.data(), sizeof(buf),
                        &readbytes) > 0) {

            game_messages::GameMessage in_message;
            in_message.ParseFromArray(
                buf.data(),
                readbytes); // NOLINT(*-narrowing-conversions)

            // It hurts less than if/else chain, but it's still ugly.
            //
            // Also, why wasn't the case() documented in any way in oneof
            // nested messages? only in enum, while it also is implemented
            // here?
            switch (in_message.message_type_case()) {

            case game_messages::GameMessage::kClientUpdateState: {
                if (user_session.user_ID == 0) {
                    // TODO: send message about no authentication
                } else if (user_session.connected_game_server_ID != 0) {
                    // TODO: send message about no connected game server
                } else {
                    // user exists and is connected to game server => pass
                    // the update to connected game server

                    ssl_messenger.send_message(
                        in_message.release_client_update_state(),
                        user_session.connected_game_server_ID);
                }
                break;
            }

            case game_messages::GameMessage::kChatMessageRequest: {
                if (user_session.user_ID == 0) {
                    // TODO: send message about no authentication
                } else if (user_session.connected_game_server_ID != 0) {
                    // TODO: send message about no connected game server
                } else {
                    // user exists and is connected to game server => pass
                    // the update to connected game server

                    ssl_messenger.send_message(
                        in_message.release_chat_message_request(),
                        user_session.connected_game_server_ID);
                }
                break;
            }

            case game_messages::GameMessage::kLogInRequest: {

                // Need to refactor, we need secondary Map<{user_id,
                // session_id}, SSL>
                ssl_messenger.send_message(in_message.release_log_in_request(),
                                           user_session);
                break;
            }

            case game_messages::GameMessage::kJoinWorldRequest: {
                ssl_messenger.send_message(
                    in_message.release_join_world_request());
                break;
            }

            default: {
                // TODO: implement wrong message type handling
                break;
            }
            }
        }
    }
}

void handle_game_server_connection(std::unique_ptr<SSL, SslDeleter> ssl,
                                   SslMessenger &ssl_messenger) {
    (void)ssl;
    (void)ssl_messenger;
}

void handle_auth_server_connection(std::unique_ptr<SSL, SslDeleter> ssl,
                                   SslMessenger &ssl_messenger) {
    (void)ssl;
    (void)ssl_messenger;
}

int main(int argc, char const *argv[]) {
    (void)argv;
    (void)argc;

    // Unneeded for now
    // Setup empty data structures
    // std::unordered_map<uint32_t, GameServer> game_servers;
    // std::unordered_map<uint32_t, AuthServer> auth_servers;
    // std::unordered_map<uint32_t, UserSession> connected_users;

    // Setup mediator/messenger

    auto ssl_messenger = SslMessenger();

    // Setup listeners

    // TODO: change to read from config file
    std::string client_port = "4720";
    std::string auth_server_port = "4721";
    std::string game_server_port = "4722";

    std::thread clients_listener_thread(listen_for_new_clients_ssl,
                                        std::cref(client_port),
                                        std::ref(ssl_messenger));

    std::thread auth_servers_listener_thread(listen_for_new_auth_servers_ssl,
                                             std::cref(auth_server_port),
                                             std::ref(ssl_messenger));

    std::thread game_servers_listener_thread(listen_for_new_game_servers_ssl,
                                             std::cref(game_server_port),
                                             std::ref(ssl_messenger));

    clients_listener_thread.join();
    auth_servers_listener_thread.join();
    game_servers_listener_thread.join();
    std::cout << "Something went very, very, wrong if you reached here (all "
                 "listener threads ended execution)\n";
}

void listen_for_new_clients_ssl(const std::string &port,
                                SslMessenger &ssl_messenger) {

    // TODO: change paths to use config file
    auto cert_path = std::string("certs/client_cert.pem");
    auto key_path = std::string("certs/client_key.pem");

    auto dtls_ctx = std::unique_ptr<SSL_CTX, SslDeleter>(
        setup_new_dtls_ctx(cert_path, key_path));

    // Bind file descriptor on which we listen
    // We listen for new connections on one file descriptor, so it needs to be
    // outside of loop. It should not be a bottleneck unless there is multiple
    // thousands of login requests per second.

    auto new_connection_listener_fd = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);

    // Get address and port tuple for listener to bind to
    BIO_ADDRINFO *addrinfo; // NOLINT(*init-variables): variable is initialized
                            // inside BIO_lookup_ex()
    if (BIO_lookup_ex("0.0.0.0", port.c_str(), BIO_LOOKUP_SERVER, AF_INET,
                      SOCK_DGRAM, 0, &addrinfo) == 0) {
        throw std::runtime_error("Could not loookup server address");
    }

    if (BIO_bind(new_connection_listener_fd, BIO_ADDRINFO_address(addrinfo),
                 BIO_SOCK_REUSEADDR) == 0) {
        throw std::runtime_error(
            "Could not bind the main listening socket for client listener.\n");
    }

    // Main listening loop

    while (true) {

        auto dtls_ssl =
            std::unique_ptr<SSL, SslDeleter>(SSL_new(dtls_ctx.get()));
        if (dtls_ssl == nullptr) {
            throw std::runtime_error("Failed to create client listener SSL");
        }

        setup_dtls_listener_socket(new_connection_listener_fd, *dtls_ssl,
                                   addrinfo);

        SSL_set_options(dtls_ssl.get(), SSL_OP_COOKIE_EXCHANGE);

        if (SSL_accept(dtls_ssl.get()) < 1) {
            std::cout << "Failed to accept client\n";
            /*
             * If the failure is due to a verification error we can get more
             * information about it from SSL_get_verify_result().
             */
            if (SSL_get_verify_result(dtls_ssl.get()) != X509_V_OK) {
                std::cout << "Verify error:"
                          << "\n"
                          << X509_verify_cert_error_string(
                                 SSL_get_verify_result(dtls_ssl.get()))
                          << "\n";
            }
        } else {
            // Create handler thread and detach it
            std::thread client_handler_thread(handle_client_connection,
                                              std::move(dtls_ssl),
                                              std::ref(ssl_messenger));
            client_handler_thread.detach();
        }
    }
}

void listen_for_new_game_servers_ssl(const std::string &port,
                                     SslMessenger &ssl_messenger) {

    // TODO: change paths to use config file
    auto cert_path = std::string("certs/client_cert.pem");
    auto key_path = std::string("certs/client_key.pem");

    auto dtls_ctx = std::unique_ptr<SSL_CTX, SslDeleter>(
        setup_new_dtls_ctx(cert_path, key_path));

    // Bind file descriptor on which we listen
    // We listen for new connections on one file descriptor, so it needs to be
    // outside of loop. It should not be a bottleneck unless there is multiple
    // thousands of login requests per second.

    auto new_connection_listener_fd = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);

    // Get address and port tuple for listener to bind to
    BIO_ADDRINFO *addrinfo; // NOLINT(*init-variables): variable is initialized
                            // inside BIO_lookup_ex()
    if (BIO_lookup_ex("0.0.0.0", port.c_str(), BIO_LOOKUP_SERVER, AF_INET,
                      SOCK_DGRAM, 0, &addrinfo) == 0) {
        throw std::runtime_error("Could not loookup server address");
    }

    if (BIO_bind(new_connection_listener_fd, BIO_ADDRINFO_address(addrinfo),
                 BIO_SOCK_REUSEADDR) == 0) {
        throw std::runtime_error(
            "Could not bind the main listening socket for client listener.\n");
    }

    // Main listening loop

    while (true) {

        auto dtls_ssl =
            std::unique_ptr<SSL, SslDeleter>(SSL_new(dtls_ctx.get()));
        if (dtls_ssl == nullptr) {
            throw std::runtime_error("Failed to create client listener SSL");
        }

        setup_dtls_listener_socket(new_connection_listener_fd, *dtls_ssl,
                                   addrinfo);

        // TODO: check if needed in mock
        SSL_set_options(dtls_ssl.get(), SSL_OP_COOKIE_EXCHANGE);

        if (SSL_accept(dtls_ssl.get()) < 1) {
            std::cout << "Failed to accept client\n";
            /*
             * If the failure is due to a verification error we can get more
             * information about it from SSL_get_verify_result().
             */
            if (SSL_get_verify_result(dtls_ssl.get()) != X509_V_OK) {
                std::cout << "Verify error:"
                          << "\n"
                          << X509_verify_cert_error_string(
                                 SSL_get_verify_result(dtls_ssl.get()))
                          << "\n";
            }
        } else {
            // Create handler thread and detach it
            std::thread game_server_handler_thread(
                handle_game_server_connection, std::move(dtls_ssl),
                std::ref(ssl_messenger));
            game_server_handler_thread.detach();
        }
    }
}

void listen_for_new_auth_servers_ssl(const std::string &port,
                                     SslMessenger &ssl_messenger) {

    // TODO: change paths to use config file
    auto cert_path = std::string("certs/client_cert.pem");
    auto key_path = std::string("certs/client_key.pem");

    auto tls_ctx = std::unique_ptr<SSL_CTX, SslDeleter>(
        setup_new_tls_ctx(cert_path, key_path));

    auto *ssl_bio = BIO_new_ssl(tls_ctx.get(), 0);

    auto *accept_bio = BIO_new_accept(port.data());
    BIO_set_accept_bios(accept_bio, ssl_bio);

    while (true) {

        // We use raw pointer here, because we pass this BIO pointer to
        // std::unique_ptr<SSL,SslDeleter> and deleter uses OpenSSL macro
        // that correctly frees BIO passed to SSL structure.
        //
        // By using the raw pointer we don't get problems with library
        // compatibility with unique_ptr and we eliminate the problem with
        // automatic freeing of std::unique_ptr<BIO> when going out of scope
        // at the end of loop iteration.
        if (BIO_do_accept(accept_bio) <= 0) {
            std::cout << "accept bio\n";
        }

        auto tls_ssl = std::unique_ptr<SSL, SslDeleter>(SSL_new(tls_ctx.get()));
        if (tls_ssl == nullptr) {
            std::cout << "Error 18\n";
            throw std::runtime_error("Failed to create client listener SSL");
        }

        auto *conn_bio = BIO_pop(accept_bio);

        SSL_set_bio(tls_ssl.get(), conn_bio, conn_bio);

        // Create handler thread and detach it
        std::thread auth_server_handler_thread(handle_auth_server_connection,
                                               std::move(tls_ssl),
                                               std::ref(ssl_messenger));
        auth_server_handler_thread.detach();
    }
}
