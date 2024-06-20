#include "main.hpp"
#include "game_messages.pb.h"
#include "ssl_deleter.h"
#include <bsoncxx/builder/basic/kvp.hpp>
#include <bsoncxx/json-fwd.hpp>
#include <cstddef>
#include <iostream>
#include <memory>
#include <mongocxx/instance-fwd.hpp>
#include <mongocxx/pool.hpp>

#include <bsoncxx/builder/basic/document.hpp>
#include <bsoncxx/json.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/stdx.hpp>
#include <mongocxx/uri.hpp>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <stdexcept>
#include <sys/socket.h>

using bsoncxx::builder::basic::kvp;
using bsoncxx::builder::basic::make_array;
using bsoncxx::builder::basic::make_document;

int main(int argc, char const *argv[]) { // NOLINT(bugprone-exception-escape)
    (void)argc;
    (void)argv;

    const auto hostname = std::string("broker");
    const auto port = std::string("4721");

    // Create MongoDB client session
    auto mongo_instance = mongocxx::instance{};
    auto mongo_pool = mongocxx::pool(mongocxx::uri("mongodb://mongodb:27017"));

    auto entry = mongo_pool.acquire();
    auto &client = (*entry);
    auto auth_db = client["auth_db"];
    auto credentials_collection = auth_db["users_credentials"];

    // Establish OpenSSL TLS session with broker
    auto tls_ctx =
        std::unique_ptr<SSL_CTX, SslDeleter>(SSL_CTX_new(TLS_client_method()));

    if (tls_ctx == nullptr) {
        throw std::runtime_error("Failed to create SSL_CTX");
    }

    SSL_CTX_set_verify(tls_ctx.get(), SSL_VERIFY_PEER, nullptr);

    if (SSL_CTX_load_verify_file(tls_ctx.get(), "certs/cert.pem") == 0) {
        throw std::runtime_error("Failed to load cert.pem file");
    }

    // loop is used to reconnect with server in case of ssl disconnect
    while (true) {

        auto tls_ssl = std::unique_ptr<SSL, SslDeleter>(SSL_new(tls_ctx.get()));
        if (tls_ssl == nullptr) {
            throw std::runtime_error("Failed to create SSL");
        }

        BIO_ADDRINFO *addrinfo; // NOLINT(*init-variables): variable is
                                // initialized inside BIO_lookup_ex()
        if (BIO_lookup_ex(hostname.c_str(), port.c_str(), BIO_LOOKUP_CLIENT,
                          AF_INET, SOCK_STREAM, 0, &addrinfo) == 0) {
            throw std::runtime_error(
                "Could not lookup broker address in BIO_lookup_ex()");
        }

        auto fd = // NOLINT(*-identifier-length)
            BIO_socket(BIO_ADDRINFO_family(addrinfo), SOCK_STREAM, 0, 0);

        if (fd == -1) {
            throw std::runtime_error("Could not create fd for client");
        }

        if (BIO_connect(fd, BIO_ADDRINFO_address(addrinfo), 0) == 0) {
            BIO_closesocket(fd);
            throw std::runtime_error("Could not connect fd to socket");
        }

        BIO_ADDRINFO_free(addrinfo);

        // Using raw pointer, because we pass ownership to SSL, which handles
        // pointer's lifetime

        auto *bio = BIO_new_socket(fd, BIO_NOCLOSE);

        SSL_set_bio(tls_ssl.get(), bio, bio);

        if (SSL_connect(tls_ssl.get()) < 1) {
            throw std::runtime_error("Failed to connect to the server");
            /*
             * If the failure is due to a verification error we can get more
             * information about it from SSL_get_verify_result().
             */
            if (SSL_get_verify_result(tls_ssl.get()) != X509_V_OK)
                std::cout << "Verify error:" << std::endl
                          << X509_verify_cert_error_string(
                                 SSL_get_verify_result(tls_ssl.get()))
                          << std::endl;
            return 1;
        }

        // Main request/response loop

        const auto MAX_TLS_RECORD_SIZE = 16384;
        auto buf = std::array<char, MAX_TLS_RECORD_SIZE>();
        size_t readbytes = 0;
        while (SSL_get_shutdown(tls_ssl.get()) == 0) {
            if (SSL_read_ex(tls_ssl.get(), buf.data(), sizeof(buf),
                            &readbytes) > 0) {
                game_messages::GameMessage in_message;
                in_message.ParseFromArray(
                    buf.data(), readbytes); // NOLINT(*-narrowing-conversions)

                if (in_message.message_type_case() ==
                    game_messages::GameMessage::kLogInRequest) {
                    // correct behaviour
                    game_messages::GameMessage out_message;
                    auto username = in_message.log_in_request().username();
                    auto password = in_message.log_in_request().password();
                    auto session_id = in_message.log_in_request().session_id();

                    game_messages::LogInResponse login_response;
                    login_response.set_username(username);
                    login_response.set_session_id(session_id);

                    auto result = credentials_collection.find_one(
                        make_document(kvp("username", username)));
                    if (result) {
                        auto credentials = Credentials();
                        credentials.password =
                            result.value()["password"].get_string();
                        credentials.hash = result.value()["hash"].get_string();
                        credentials.salt = result.value()["salt"].get_string();

                        if (check_password(credentials)) {
                            login_response.set_user_id(
                                result.value()["user_id"].get_int32());
                        }
                    }

                    out_message.set_allocated_log_in_response(&login_response);
                    auto out_message_string = out_message.SerializeAsString();
                    // NOLINTBEGIN(*-narrowing-conversions)
                    SSL_write(tls_ssl.get(), out_message_string.data(),
                              out_message_string.size());
                    // NOLINTEND(*-narrowing-conversions)
                } else {
                    // Wrong message type received
                }
            }
        }
    }
    return 0;
}

bool check_password(Credentials credentials) {
    // TODO
    (void)credentials;
    return true;
}
