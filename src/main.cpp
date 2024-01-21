#include "main.hpp"
#include <iostream>

int main(int argc, char const *argv[]) {
    (void)argv;
    (void)argc;
    game_messages::SampleString message;
    message.set_sample_string("hello there");
    std::cout << message.sample_string() << std::endl;

    auto dtls_ctx = SSL_CTX_new(DTLS_server_method());
    std::cout << typeid(dtls_ctx).name();
}