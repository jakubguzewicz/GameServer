#include <openssl/ssl.h>

#pragma once

struct SslDeleter {
    void operator()(SSL *ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    void operator()(SSL_CTX *ssl) { SSL_CTX_free(ssl); }
};