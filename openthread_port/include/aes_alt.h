#ifndef AES_ALT_H
#define AES_ALT_H
#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* padlock.c and aesni.c rely on these values! */
#define MBEDTLS_AES_ENCRYPT     1 /**< AES encryption. */
#define MBEDTLS_AES_DECRYPT     0 /**< AES decryption. */

typedef struct {
    void* aes_dev;
    uint8_t key[16];
} mbedtls_aes_context;

typedef struct mbedtls_aes_xts_context {
    mbedtls_aes_context crypt;
    mbedtls_aes_context tweak;
} mbedtls_aes_xts_context;



#ifdef __cplusplus
}
#endif

#endif // AES_ALT_H