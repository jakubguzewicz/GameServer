#include "mock_dtls_client.hpp"
#include <iostream>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>

int main(int argc, char const *argv[]) {

    // if (argc != 3) {
    //     std::cout << "Bad arguments: hostname, port" << std::endl;
    //     return 1;
    // }

    // std::vector<char> hostname(argv[1], argv[1] + strlen(argv[1]) + 1);
    // std::vector<char> port(argv[2], argv[2] + strlen(argv[2]) + 1);

    (void)argc;
    (void)argv[0];

    auto dtls_ctx = SSL_CTX_new(DTLS_server_method());
    if (dtls_ctx == NULL) {
        std::cout << "Failed to create SSL_CTX" << std::endl;
    }

    SSL_CTX_set_verify(dtls_ctx, SSL_VERIFY_PEER, NULL);

    if (!SSL_CTX_use_certificate_file(dtls_ctx, "certs/cert.pem",
                                      SSL_FILETYPE_PEM)) {
        std::cout << "Failed to find cert.pem file" << std::endl;
    }

    if (!SSL_CTX_use_PrivateKey_file(dtls_ctx, "certs/key.pem",
                                     SSL_FILETYPE_PEM)) {
        std::cout << "Failed to find key.pem file" << std::endl;
    }

    auto dtls_ssl = SSL_new(dtls_ctx);
    if (dtls_ssl == NULL) {
        std::cout << "Failed to create SSL" << std::endl;
    }

    int sock = -1;
    BIO_ADDRINFO *result;
    const BIO_ADDRINFO *address_info = NULL;

    // get socket fd
    sock = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
    if (sock == -1) {
        std::cout << "Could not create socket fd" << std::endl;
    }

    // start listening on port 5720 (random number not on known list :D)
    if (BIO_lookup_ex(NULL, "5720", BIO_LOOKUP_SERVER, AF_INET, SOCK_DGRAM, 0,
                      &result) == 0) {
        std::cout << "BIO_lookup didn't find an address" << std::endl;
    }

    for (address_info = result; address_info != NULL;
         BIO_ADDRINFO_next(address_info)) {
        sock = BIO_socket(BIO_ADDRINFO_family(address_info), SOCK_DGRAM, 0, 0);
        if (sock == -1) {
            continue;
        }

        if (!BIO_listen(sock, BIO_ADDRINFO_address(address_info),
                        BIO_SOCK_KEEPALIVE | BIO_SOCK_NODELAY)) {
            BIO_closesocket(sock);
            sock = -1;
            continue;
        } else {
            // We've got a listener
            break;
        }
    }

    if (sock == -1) {
        std::cout << "Could not start listening" << std::endl;
    }
    // No need to keep it anymore
    BIO_ADDRINFO_free(result);

    // Now create BIO
    BIO *bio;

    bio = BIO_new(BIO_s_socket());
    if (bio == NULL) {
        BIO_closesocket(sock);
        return 1;
    }

    BIO_set_fd(bio, sock, BIO_CLOSE);

    SSL_set_bio(dtls_ssl, bio, bio);

    // finish handshake
    if (SSL_accept(dtls_ssl) < 1) {
        printf("Failed to accept client\n");
        /*
         * If the failure is due to a verification error we can get more
         * information about it from SSL_get_verify_result().
         */
        if (SSL_get_verify_result(dtls_ssl) != X509_V_OK)
            std::cout << "Verify error:" << std::endl
                      << X509_verify_cert_error_string(
                             SSL_get_verify_result(dtls_ssl))
                      << std::endl;
        return 1;
    }

    // Now let's receive something
    // init objects
    game_messages::SampleString out_message;
    game_messages::SampleString in_message;
    std::string out_message_string;
    std::string in_message_string;
    std::vector<char> in_message_vector;
    std::vector<char> out_message_vector;

    // added only because SSL_get_error requires this variable
    int ret = 0;

    while (!(SSL_get_shutdown(dtls_ssl) & SSL_RECEIVED_SHUTDOWN)) {
        // read message
        SSL_read(dtls_ssl, &in_message_vector[0], in_message_vector.max_size());
        std::string in_message_string(in_message_vector.begin(),
                                      in_message_vector.end());

        if (SSL_get_error(dtls_ssl, ret) != SSL_ERROR_NONE) {
            break;
        }

        in_message.ParseFromString(in_message_string);
        std::cout << "Received message: " << in_message.sample_string()
                  << std::endl;

        // reply to it
        out_message.set_sample_string("Received you message: " +
                                      in_message.sample_string());
        std::vector<char> out_message_vector(out_message_string.begin(),
                                             out_message_string.end());
        SSL_write(dtls_ssl, &out_message_vector[0], out_message_vector.size());
    }

    // cleanup
    std::cout << "Session ended, cleanup" << std::endl;
    SSL_shutdown(dtls_ssl);
}