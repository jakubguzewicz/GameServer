#include "main.hpp"
#include "game_messages.pb.h"
#include <iostream>

int main(int argc, char const *argv[]) {
    (void)argv;
    (void)argc;
    game_messages::SampleString message;
    message.set_sample_string("hello there");
    std::cout << message.sample_string() << std::endl;
}