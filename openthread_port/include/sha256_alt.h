#ifndef MBEDTLS_SHA256_ALT_H
#define MBEDTLS_SHA256_ALT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief   SHA-256 context structure for alternative implementation
 */
typedef struct {
    void* sha_hw_ctx; /*!< Pointer to hardware SHA context (e.g. hosal_sha256_ctx_t) */
    uint8_t buffer[64]; /*!< Optional: buffer for leftover input data */
    size_t total_len;   /*!< Total length of input processed */
} mbedtls_sha256_context;

#include "mbedtls/sha256.h"

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_SHA256_ALT_H */