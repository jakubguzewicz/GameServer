#include "proto/game_messages.pb.h"
#include <openssl/bio.h>
#include <openssl/ssl.h>

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len);
int verify_cookie(SSL *ssl, const unsigned char *cookie,
                  unsigned int cookie_len);