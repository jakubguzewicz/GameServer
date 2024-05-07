#include <openssl/ssl.h>

#pragma once

struct SslDeleter {
    void operator()(SSL *_p) {
        SSL_shutdown(_p);
        SSL_free(_p);
    }

    void operator()(SSL_CTX *_p) { SSL_CTX_free(_p); }
};