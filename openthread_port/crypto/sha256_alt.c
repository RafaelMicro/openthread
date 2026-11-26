#include "sha256_alt.h"
#include <stdlib.h>
#include <string.h>
#include "hosal_crypto_sha256.h"
#include "log.h"

void mbedtls_sha256_init(mbedtls_sha256_context* ctx) {
    // log_info("%s", __func__);
    ctx->sha_hw_ctx = pvPortMalloc(sizeof(hosal_sha256_dev_t));
    if (!ctx->sha_hw_ctx) {
        log_error(" malloc failed in sha256_init");
        return;
    }
    memset(ctx->sha_hw_ctx, 0, sizeof(hosal_sha256_dev_t));
    ctx->total_len = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
    hosal_crypto_sha256_init();

// RF1301 uses rt584_hosal (same SHA engine as RT584H): its operations are
// split into INIT (sha256_init) and STARTS (sha256_starts). Without them in this
// list the engine was never started (digest results were wrong).
#if defined(CONFIG_RT584H) || defined(CONFIG_RT584L) || defined(CONFIG_RT584HA4) || \
    defined(CONFIG_RF1301)
    hosal_sha256_dev_t* sha_dev = (hosal_sha256_dev_t*)ctx->sha_hw_ctx;
    sha_dev->crypto_operation = HOSAL_SHA256_DIGEST_INIT;

    if (hosal_crypto_sha256_operation(sha_dev) != 0) {
        log_error("SHA256 init failed");
        return;
    }
#endif
}

void mbedtls_sha256_free(mbedtls_sha256_context* ctx) {
    // log_info("%s", __func__);
    if (ctx->sha_hw_ctx) {
        vPortFree(ctx->sha_hw_ctx);
        ctx->sha_hw_ctx = NULL;
    }
    ctx->total_len = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void mbedtls_sha256_clone(mbedtls_sha256_context* dst,
                          const mbedtls_sha256_context* src) {
    // log_info("%s", __func__);
    if (!src || !dst || src == dst)
        return;

    memcpy(dst->buffer, src->buffer, sizeof(src->buffer));
    dst->total_len = src->total_len;

    // deep copy hw ctx.
    // mbedtls requires dst to be initialized already (mbedtls_md_setup() ->
    // mbedtls_sha256_init() allocated dst->sha_hw_ctx), so reuse that buffer.
    // Allocating unconditionally leaked one hosal_sha256_dev_t per clone
    // (2+ per DTLS handshake: calc_verify / calc_finished), exhausting the
    // FreeRTOS heap after ~200 joins.
    if (src->sha_hw_ctx) {
        if (dst->sha_hw_ctx == NULL) {
            dst->sha_hw_ctx = pvPortMalloc(sizeof(hosal_sha256_dev_t));
        }
        if (dst->sha_hw_ctx) {
            memcpy(dst->sha_hw_ctx, src->sha_hw_ctx,
                   sizeof(hosal_sha256_dev_t));
        } else {
            log_error("malloc failed in sha256_clone");
        }
    } else if (dst->sha_hw_ctx) {
        vPortFree(dst->sha_hw_ctx);
        dst->sha_hw_ctx = NULL;
    }
}

int mbedtls_sha256_starts(mbedtls_sha256_context* ctx, int is224) {
    // log_info("%s is224 = %d", __func__, is224);
    if (is224) {
        log_error("SHA-224 not supported in hardware");
        return -1;
    }
    if (!ctx->sha_hw_ctx)
        return -1;

    hosal_sha256_dev_t* sha_dev = (hosal_sha256_dev_t*)ctx->sha_hw_ctx;
#if defined(CONFIG_RT584H) || defined(CONFIG_RT584L) || defined(CONFIG_RT584HA4) || \
    defined(CONFIG_RF1301)
    sha_dev->crypto_operation = HOSAL_SHA256_DIGEST_STARTS;
#else
    sha_dev->crypto_operation = HOSAL_SHA256_DIGEST_INIT;
#endif
    if (hosal_crypto_sha256_operation(sha_dev) != 0) {
        log_error("SHA256 init failed");
        return -1;
    }

    ctx->total_len = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
    return 0;
}

int mbedtls_sha256_update(mbedtls_sha256_context* ctx,
                          const unsigned char* input, size_t ilen) {
    // log_info("%s", __func__);
    if (!ctx || !ctx->sha_hw_ctx || !input || ilen == 0)
        return 0;

    hosal_sha256_dev_t* sha_dev = (hosal_sha256_dev_t*)ctx->sha_hw_ctx;

    sha_dev->in_ptr = (uint8_t*)input;
    sha_dev->in_length = ilen;
    sha_dev->crypto_operation = HOSAL_SHA256_DIGEST_UPDATE;

    if (hosal_crypto_sha256_operation(sha_dev) != 0) {
        log_error("SHA256 update failed");
        return -1;
    }

    ctx->total_len += ilen;

    return 0;
}

int mbedtls_sha256_finish(mbedtls_sha256_context* ctx, unsigned char* output) {
    // log_info("%s", __func__);
    if (!ctx || !ctx->sha_hw_ctx || !output)
        return -1;

    hosal_sha256_dev_t* sha_dev = (hosal_sha256_dev_t*)ctx->sha_hw_ctx;

    sha_dev->out_ptr = output;
    sha_dev->crypto_operation = HOSAL_SHA256_DIGEST_FINISH;

    if (hosal_crypto_sha256_operation(sha_dev) != 0) {
        log_error("SHA256 finish failed");
        return -1;
    };

    return 0;
}