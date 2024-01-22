#include "mock_dtls_client.hpp"
#include <iostream>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

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

int main(int argc, char const *argv[]) {

    if (argc != 2) {
        std::cout << "Bad arguments: port" << std::endl;
        return 1;
    }

    std::vector<char> port(argv[1], argv[1] + strlen(argv[1]) + 1);

    (void)argc;
    (void)argv[0];

    auto dtls_ctx = SSL_CTX_new(DTLS_server_method());
    if (dtls_ctx == NULL) {
        std::cout << "Failed to create SSL_CTX" << std::endl;
    }

    SSL_CTX_set_min_proto_version(dtls_ctx, DTLS1_2_VERSION);

    SSL_CTX_set_cookie_generate_cb(dtls_ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(dtls_ctx, verify_cookie);

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

    SSL_set_options(dtls_ssl, SSL_OP_COOKIE_EXCHANGE);

    int sock = -1;
    BIO_ADDRINFO *result;
    const BIO_ADDRINFO *address_info = NULL;

    // get socket fd
    sock = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
    if (sock == -1) {
        std::cout << "Could not create socket fd" << std::endl;
    }

    const int on = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void *)&on,
               (socklen_t)sizeof(on));

    // start listening on port given in args
    BIO_lookup_ex("127.0.0.1", &port[0], BIO_LOOKUP_SERVER, AF_INET, SOCK_DGRAM,
                  0, &result);

    for (address_info = result; address_info != NULL;
         BIO_ADDRINFO_next(address_info)) {
        sock = BIO_socket(BIO_ADDRINFO_family(address_info), SOCK_DGRAM, 0, 0);
        if (sock == -1) {
            std::cout << "fail on BIO_socket" << std::endl;
            continue;
        }

        if (!BIO_listen(sock, BIO_ADDRINFO_address(address_info), 0)) {
            std::cout << "fail on BIO_listen" << std::endl;
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
    } else {
        std::cout << "Started listening" << std::endl;
    }
    // No need to keep it anymore
    BIO_ADDRINFO_free(result);

    // Now create BIO
    BIO *bio;

    // bio = BIO_new(BIO_s_socket());
    bio = BIO_new(BIO_s_datagram());
    if (bio == NULL) {
        BIO_closesocket(sock);
        return 1;
    }

    BIO_set_fd(bio, sock, BIO_CLOSE);
    BIO_ctrl(SSL_get_rbio(dtls_ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0,
             &address_info);

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
    // int ret = 0;

    char buf[65535] = {};
    size_t readbytes;

    while (!(SSL_get_shutdown(dtls_ssl) & SSL_RECEIVED_SHUTDOWN)) {
        // read message
        for (;;) {

            if (SSL_read_ex(dtls_ssl, buf, sizeof(buf), &readbytes) > 0) {

                std::string in_message_string(buf, readbytes);

                // always true in blocking behavior, usually false in
                // nonblocking
                //
                // if (SSL_get_error(dtls_ssl, ret) != SSL_ERROR_NONE) {
                //     break;
                // }

                in_message.ParseFromString(in_message_string);
                std::cout << std::endl
                          << "Received message: " << in_message.sample_string()
                          << std::endl;

                // reply to it
                out_message.set_sample_string("Received your message: " +
                                              in_message.sample_string());

                out_message.SerializeToString(&out_message_string);

                SSL_write(dtls_ssl, out_message_string.data(),
                          out_message_string.size());
            }
        }
    }

    // cleanup
    std::cout << "Session ended, cleanup" << std::endl;
    SSL_shutdown(dtls_ssl);
}