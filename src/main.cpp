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

int setup_dtls_listener_socket(const std::string &port) {
    auto sock = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
    if (sock < 0) {
        throw std::runtime_error(
            "Could not create socket fd for client listener");
    }

    BIO_ADDRINFO *addrinfo = nullptr;

    BIO_lookup_ex("0.0.0.0", port.c_str(), BIO_LOOKUP_SERVER, AF_INET,
                  SOCK_DGRAM, 0, &addrinfo);

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
                        in_message.client_update_state(),
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
                        in_message.chat_message_request(),
                        user_session.connected_game_server_ID);
                }
                break;
            }

            case game_messages::GameMessage::kLogInRequest: {

                // Need to refactor, we need secondary Map<{user_id,
                // session_id}, SSL>
                ssl_messenger.send_message(in_message.mutable_log_in_request(),
                                           user_session);
                break;
            }

            case game_messages::GameMessage::kJoinWorldRequest: {
                ssl_messenger.send_message(in_message.join_world_request());
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

    // Bind socket on which we listen
    // We listen on exactly one port (like), so it needs to be outside of
    // loop

    auto sock = setup_dtls_listener_socket(port);

    // Main listening loop
    //
    // For each separate connection we need to make these steps:
    //  1. Create BIO object
    //  2. Bind BIO object to listener socket
    //  3. Create SSL object with aforementioned BIO
    //  4. Accept new connection (it is blocking operation until we get new
    //  connection)
    //  5. Create new handler thread using the SSL object with accepted
    //  connection

    while (true) {

        // We use raw pointer here, because we pass this BIO pointer to
        // std::unique_ptr<SSL,SslDeleter> and deleter uses OpenSSL macro
        // that correctly frees BIO passed to SSL structure.
        //
        // By using the raw pointer we don't get problems with library
        // compatibility with unique_ptr and we eliminate the problem with
        // automatic freeing of std::unique_ptr<BIO> when going out of scope
        // at the end of loop iteration.
        auto *bio = BIO_new_dgram(sock, BIO_NOCLOSE);

        if (bio == nullptr) {
            throw std::runtime_error(
                "Could not create BIO object in client listener");
        }

        auto dtls_ssl =
            std::unique_ptr<SSL, SslDeleter>(SSL_new(dtls_ctx.get()));
        if (dtls_ssl == nullptr) {
            throw std::runtime_error("Failed to create client listener SSL");
        }

        SSL_set_bio(dtls_ssl.get(), bio, bio);

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
        }

        // Create handler thread and detach it
        std::thread client_handler_thread(handle_client_connection,
                                          std::move(dtls_ssl),
                                          std::ref(ssl_messenger));
        client_handler_thread.detach();
    }
}

void listen_for_new_game_servers_ssl(const std::string &port,
                                     SslMessenger &ssl_messenger) {

    // TODO: change paths to use config file
    auto cert_path = std::string("certs/client_cert.pem");
    auto key_path = std::string("certs/client_key.pem");

    auto dtls_ctx = std::unique_ptr<SSL_CTX, SslDeleter>(
        setup_new_dtls_ctx(cert_path, key_path));

    // Bind socket on which we listen
    // We listen on exactly one port (like), so it needs to be outside of
    // loop

    auto sock = setup_dtls_listener_socket(port);

    // Main listening loop
    //
    // For each separate connection we need to make these steps:
    //  1. Create BIO object
    //  2. Bind BIO object to listener socket
    //  3. Create SSL object with aforementioned BIO
    //  4. Accept new connection (it is blocking operation until we get new
    //  connection)
    //  5. Create new handler thread using the SSL object with accepted
    //  connection

    while (true) {

        // We use raw pointer here, because we pass this BIO pointer to
        // std::unique_ptr<SSL,SslDeleter> and deleter uses OpenSSL macro
        // that correctly frees BIO passed to SSL structure.
        //
        // By using the raw pointer we don't get problems with library
        // compatibility with unique_ptr and we eliminate the problem with
        // automatic freeing of std::unique_ptr<BIO> when going out of scope
        // at the end of loop iteration.
        auto *bio = BIO_new_dgram(sock, BIO_NOCLOSE);

        if (bio == nullptr) {
            throw std::runtime_error(
                "Could not create BIO object in client listener");
        }

        auto dtls_ssl =
            std::unique_ptr<SSL, SslDeleter>(SSL_new(dtls_ctx.get()));
        if (dtls_ssl == nullptr) {
            throw std::runtime_error("Failed to create client listener SSL");
        }

        SSL_set_bio(dtls_ssl.get(), bio, bio);

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
        }

        // Create handler thread and detach it
        std::thread game_server_handler_thread(handle_game_server_connection,
                                               std::move(dtls_ssl),
                                               std::ref(ssl_messenger));
        game_server_handler_thread.detach();
    }
}

void listen_for_new_auth_servers_ssl(const std::string &port,
                                     SslMessenger &ssl_messenger) {

    // TODO: change paths to use config file
    auto cert_path = std::string("certs/client_cert.pem");
    auto key_path = std::string("certs/client_key.pem");

    auto tls_ctx = std::unique_ptr<SSL_CTX, SslDeleter>(
        setup_new_tls_ctx(cert_path, key_path));

    // Bind socket on which we listen
    // We listen on exactly one port (like), so it needs to be outside of
    // loop

    auto sock = setup_tls_listener_socket(port);

    // Main listening loop
    //
    // For each separate connection we need to make these steps:
    //  1. Create BIO object
    //  2. Bind BIO object to listener socket
    //  3. Create SSL object with aforementioned BIO
    //  4. Accept new connection (it is blocking operation until we get new
    //  connection)
    //  5. Create new handler thread using the SSL object with accepted
    //  connection

    while (true) {

        // We use raw pointer here, because we pass this BIO pointer to
        // std::unique_ptr<SSL,SslDeleter> and deleter uses OpenSSL macro
        // that correctly frees BIO passed to SSL structure.
        //
        // By using the raw pointer we don't get problems with library
        // compatibility with unique_ptr and we eliminate the problem with
        // automatic freeing of std::unique_ptr<BIO> when going out of scope
        // at the end of loop iteration.
        auto *bio = BIO_new_socket(sock, BIO_NOCLOSE);

        if (bio == nullptr) {
            throw std::runtime_error(
                "Could not create BIO object in client listener");
        }

        auto tls_ssl = std::unique_ptr<SSL, SslDeleter>(SSL_new(tls_ctx.get()));
        if (tls_ssl == nullptr) {
            throw std::runtime_error("Failed to create client listener SSL");
        }

        SSL_set_bio(tls_ssl.get(), bio, bio);

        if (SSL_accept(tls_ssl.get()) < 1) {
            std::cout << "Failed to accept client\n";
            /*
             * If the failure is due to a verification error we can get more
             * information about it from SSL_get_verify_result().
             */
            if (SSL_get_verify_result(tls_ssl.get()) != X509_V_OK) {
                std::cout << "Verify error:"
                          << "\n"
                          << X509_verify_cert_error_string(
                                 SSL_get_verify_result(tls_ssl.get()))
                          << "\n";
            }
        }

        // Create handler thread and detach it
        std::thread auth_server_handler_thread(handle_auth_server_connection,
                                               std::move(tls_ssl),
                                               std::ref(ssl_messenger));
        auth_server_handler_thread.detach();
    }
}
