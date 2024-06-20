#include <string>
int main(int argc, char const *argv[]);

struct Credentials {
    std::string password;
    std::string salt;
    std::string hash;
};

bool check_password(Credentials credentials);