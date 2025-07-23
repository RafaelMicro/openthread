#include "aes_alt.h"
#include <string.h>
#include "hosal_crypto_aes.h"
#include "log.h"

void mbedtls_aes_init(mbedtls_aes_context* ctx) {
    // log_info("%s", __func__);
    ctx->aes_dev = pvPortMalloc(sizeof(hosal_aes_dev_t));
    if (!ctx->aes_dev) {
        log_error("malloc hosal_aes_dev_t failed");
        return;
    }
    memset(ctx->aes_dev, 0, sizeof(hosal_aes_dev_t));
    hosal_crypto_aes_init();
}

void mbedtls_aes_free(mbedtls_aes_context* ctx) {
    // log_info("%s", __func__);
    if (ctx->aes_dev) {
        vPortFree(ctx->aes_dev);
        ctx->aes_dev = NULL;
    } else {
        log_error("aes_dev is NULL");
    }
}

int mbedtls_aes_setkey_enc(mbedtls_aes_context* ctx, const unsigned char* key,
                           unsigned int keybits) {
    // log_info("%s", __func__);
    if (keybits != HOSAL_AES_128_BIT) {
        printf("setkey_enc keybits %d\n", keybits);
        return -1;
    }
    memcpy(ctx->key, key, AES_BLOCKLEN);
    return 0;
}

int mbedtls_aes_setkey_dec(mbedtls_aes_context* ctx, const unsigned char* key,
                           unsigned int keybits) {
    // log_info("%s", __func__);
    if (keybits != HOSAL_AES_128_BIT) {
        printf("setkey_dec keybits %d\n", keybits);
        return -1;
    }
    memcpy(ctx->key, key, AES_BLOCKLEN);
    return 0;
}

int mbedtls_aes_crypt_ecb(mbedtls_aes_context* ctx, int mode,
                          const unsigned char input[16],
                          unsigned char output[16]) {
    // log_info("%s", __func__);
    hosal_aes_dev_t* aes_dev = (hosal_aes_dev_t*)ctx->aes_dev;

    aes_dev->crypto_operation = (mode == MBEDTLS_AES_ENCRYPT)
                                    ? HOSAL_AES_CRYPTO_ENCRYPT
                                    : HOSAL_AES_CRYPTO_DECRYPT;
    aes_dev->bit = HOSAL_AES_128_BIT;
    aes_dev->key_ptr = ctx->key;
    aes_dev->in_ptr = (uint8_t*)input;
    aes_dev->out_ptr = (uint8_t*)output;
    int ret = hosal_crypto_aes_operation(aes_dev) == 0 ? 0 : -1;
    if (ret != 0) {
        log_error("AES ECB operation failed: %d", ret);
        return ret;
    }
    return ret;
}