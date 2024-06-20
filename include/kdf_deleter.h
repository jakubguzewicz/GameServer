#include <openssl/kdf.h>

#pragma once

struct KdfDeleter {
    void operator()(EVP_KDF *kdf) { EVP_KDF_free(kdf); }

    void operator()(EVP_KDF_CTX *kdf_ctx) { EVP_KDF_CTX_free(kdf_ctx); }
};