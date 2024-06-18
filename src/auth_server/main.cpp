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

    auto tls_ssl = std::unique_ptr<SSL, SslDeleter>(SSL_new(tls_ctx.get()));
    if (tls_ssl == nullptr) {
        throw std::runtime_error("Failed to create SSL");
    }

    BIO_ADDRINFO *addrinfo; // NOLINT(*init-variables): variable is initialized
                            // inside BIO_lookup_ex()
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
    while (true) {
    }

    auto test_db = client["test"];
    test_db["testing"].insert_one(
        make_document(kvp("item", "hi"), kvp("item2", "there")));

    auto iter = test_db["testing"].find({});
    for (auto doc : iter) {
        std::cout << bsoncxx::to_json(doc, bsoncxx::ExtendedJsonMode::k_relaxed)
                  << std::endl;
    }

    return 0;
}
