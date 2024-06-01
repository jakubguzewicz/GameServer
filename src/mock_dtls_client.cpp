#include "mock_dtls_client.hpp"
#include "proto/game_messages.pb.h"
#include <cstddef>
#include <iostream>
#include <openssl/ssl.h>
#include <ostream>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char const *argv[]) {

    if (argc != 5) {
        std::cout << "Bad arguments: hostname, port, username, password"
                  << std::endl;
        return 1;
    }

    std::vector<char> hostname(argv[1], argv[1] + strlen(argv[1]) + 1);
    std::vector<char> port(argv[2], argv[2] + strlen(argv[2]) + 1);
    std::string username(argv[3]);
    std::string password(argv[4]);

    auto dtls_ctx = SSL_CTX_new(DTLS_client_method());
    if (dtls_ctx == NULL) {
        std::cout << "Failed to create SSL_CTX" << std::endl;
    }

    SSL_CTX_set_verify(dtls_ctx, SSL_VERIFY_PEER, NULL);

    if (!SSL_CTX_load_verify_file(dtls_ctx, "certs/cert.pem")) {
        std::cout << "Failed to load cert.pem file" << std::endl;
    }

    auto dtls_ssl = SSL_new(dtls_ctx);
    if (dtls_ssl == NULL) {
        std::cout << "Failed to create SSL" << std::endl;
    }

    int sock = -1;
    BIO_ADDRINFO *result;
    const BIO_ADDRINFO *address_info = NULL;

    if (BIO_lookup_ex(&hostname[0], &port[0], BIO_LOOKUP_CLIENT, AF_INET,
                      SOCK_DGRAM, 0, &result) == 0) {
        std::cout << "BIO_lookup didn't find an address" << std::endl;
    }

    for (address_info = result; address_info != NULL;
         BIO_ADDRINFO_next(address_info)) {
        sock = BIO_socket(BIO_ADDRINFO_family(address_info), SOCK_DGRAM, 0, 0);
        if (sock == -1) {
            continue;
        }

        if (!BIO_connect(sock, BIO_ADDRINFO_address(address_info), 0)) {
            BIO_closesocket(sock);
            sock = -1;
            continue;
        } else {
            // We've got a connection
            break;
        }
    }

    if (sock == -1) {
        std::cout << "Could not connect to server" << std::endl;
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

    BIO_set_fd(bio, sock, BIO_NOCLOSE);

    SSL_set_bio(dtls_ssl, bio, bio);

    if (!SSL_set_tlsext_host_name(dtls_ssl, &hostname[0])) {
        std::cout << "Failed to set the SNI hostname" << std::endl;
        return 1;
    }

    if (!SSL_set1_host(dtls_ssl, &hostname[0])) {
        std::cout << "Failed to set the certificate verification hostname"
                  << std::endl;
        return 1;
    }

    if (SSL_connect(dtls_ssl) < 1) {
        std::cout << "Failed to connect to the server" << std::endl;
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

    // Now let's send something
    // init objects

    /*
    game_messages::SampleString out_message;
    game_messages::SampleString in_message;
    std::string in_message_string;
    std::string out_message_string;

    char buf[65535] = {};

    for (int i = 1; i < 5; i++) {

        // write correct values to proto message and send it;

        out_message.set_sample_string("Test message " + std::to_string(i));
        out_message.SerializeToString(&out_message_string);

        SSL_write(dtls_ssl, out_message_string.data(),
                  out_message_string.size());
        std::cout << std::endl << "Message sent" << std::endl;

        // now listen for response
        size_t readbytes;
        if (SSL_read_ex(dtls_ssl, buf, sizeof(buf), &readbytes) > 0) {
            std::string in_message_string(buf, readbytes);
            std::cout << "Received message raw form: " << in_message_string
                      << std::endl;
            in_message.ParseFromString(in_message_string);
            std::cout << "Received message: " << in_message.sample_string()
                      << std::endl;
        } else {
            std::cout << "Didn't read anything!" << std::endl;
        }
        sleep(1);
    }
    */
    auto login_message = game_messages::GameMessage();
    auto chat_message = game_messages::GameMessage();

    auto in_message = game_messages::GameMessage();

    size_t readbytes;

    char buf[16384] = {};

    auto login_submessage = game_messages::LogInRequest();
    login_submessage.set_password(password);
    login_submessage.set_username(username);
    login_message.set_allocated_log_in_request(&login_submessage);

    auto send_buf = std::string();

    send_buf = login_message.SerializeAsString();
    SSL_write(dtls_ssl, send_buf.data(), send_buf.length());

    std::cout << "Sent login message" << std::endl;
    // Let's hope login passed
    sleep(2);

    auto message_counter = 0;
    auto user_id = std::hash<std::string>{}(username);
    // Now let's send messages and receive responses
    for (;;) {
        auto chat_submessage = game_messages::ChatMessageRequest();
        chat_submessage.set_user_id(user_id);
        chat_submessage.set_chat_group(
            game_messages::ChatGroup::CHAT_GROUP_ALL);
        chat_submessage.set_message("Sent message number " +
                                    std::to_string(message_counter) +
                                    "from user " + username);

        chat_message.set_allocated_chat_message_request(&chat_submessage);
        send_buf = chat_message.SerializeAsString();
        SSL_write(dtls_ssl, send_buf.data(), send_buf.length());

        for (;;) {
            if (SSL_read_ex(dtls_ssl, buf, sizeof(buf), &readbytes) > 0) {
                std::string in_message_string(buf, readbytes);
                std::cout << "Received message raw form: " << in_message_string
                          << std::endl;
                in_message.ParseFromString(in_message_string);
                std::cout << "Received message: \""
                          << in_message.chat_message_request().message()
                          << "\" from user"
                          << in_message.chat_message_request().user_id()
                          << std::endl;
            } else {
                std::cout << "Didn't read anything!" << std::endl;
            }
            if (in_message.chat_message_request().user_id() != user_id) {
                break;
            }
        }

        usleep(500000);
    }

    // cleanup
    std::cout << "Session ended, cleanup" << std::endl;
    SSL_shutdown(dtls_ssl);
}