#include <string.h>
#include "ecjpake_alt.h"
#include "hosal_crypto_ecjpake.h"
#include "hosal_status.h"
#include "log.h"
#include "mbedtls/asn1.h"
#include "mbedtls/sha256.h"

void mbedtls_ecjpake_init(mbedtls_ecjpake_context* ctx) {
    // printf("%s\n", __func__);
    if (ctx == NULL) {
        log_error("ctx is NULL");
        return;
    }

    ctx->ecc_ctx = NULL;
    ctx->dev = NULL;
    ctx->key_array = NULL;
    ctx->gid = MBEDTLS_ECP_DP_NONE;
    ctx->md_type = MBEDTLS_MD_NONE;
    ctx->point_format = MBEDTLS_ECP_PF_UNCOMPRESSED;

    ctx->ecc_ctx = pvPortMalloc(sizeof(ECJPAKE_CTX));
    if (!ctx->ecc_ctx) {
        log_error("Memory allocation failed for ecc_ctx");
        return;
    }
    memset(ctx->ecc_ctx, 0, sizeof(ECJPAKE_CTX));

    ctx->dev = pvPortMalloc(sizeof(hosal_ecjpake_dev_t));
    if (!ctx->dev) {
        log_error("Memory allocation failed for dev");
        vPortFree(ctx->ecc_ctx);
        ctx->ecc_ctx = NULL;
        return;
    }
    memset(ctx->dev, 0, sizeof(hosal_ecjpake_dev_t));

    ctx->key_array = pvPortMalloc(sizeof(ECJPAKEKeyKP) * 4);
    if (!ctx->key_array) {
        log_error("Memory allocation failed for key_array");
        vPortFree(ctx->ecc_ctx);
        ctx->ecc_ctx = NULL;
        vPortFree(ctx->dev);
        ctx->dev = NULL;
        return;
    }
    memset(ctx->key_array, 0, (sizeof(ECJPAKEKeyKP) * 4));

    ((hosal_ecjpake_dev_t*)ctx->dev)->ctx = (ECJPAKE_CTX*)ctx->ecc_ctx;

    // printf("ctx: %p, ctx->ecc_ctx: %p, ctx->dev: %p ctx->key_array: %p\n", ctx,
    //        ctx->ecc_ctx, ctx->dev, ctx->key_array);

    hosal_crypto_ecjpake_init();

    ECPoint_P256* genx;
    genx = (ECPoint_P256*)&Curve_Gx_p256_BE;
    ((hosal_ecjpake_dev_t*)ctx->dev)->gen = genx;
}

void mbedtls_ecjpake_free(mbedtls_ecjpake_context* ctx) {
    // printf("%s\n", __func__);
    if (ctx == NULL) {
        log_error("ctx is NULL");
        return;
    }
    // printf("ctx: %p, ctx->ecc_ctx: %p, ctx->dev: %p\n", ctx, ctx->ecc_ctx,
    //        ctx->dev);
    if (ctx->ecc_ctx) {
        vPortFree(ctx->ecc_ctx);
        ctx->ecc_ctx = NULL;
    }

    if (ctx->dev) {
        vPortFree(ctx->dev);
        ctx->dev = NULL;
    }

    if (ctx->key_array) {
        vPortFree(ctx->key_array);
        ctx->key_array = NULL;
    }

    memset(ctx, 0, sizeof(mbedtls_ecjpake_context));
}

int mbedtls_ecjpake_setup(mbedtls_ecjpake_context* ctx,
                          mbedtls_ecjpake_role role, mbedtls_md_type_t hash,
                          mbedtls_ecp_group_id curve,
                          const unsigned char* secret, size_t len) {
    // printf("%s\n", __func__);

    if (!ctx || !ctx->ecc_ctx || !ctx->dev || !secret || len == 0) {
        log_error("ecjpake_setup ctx: %p, dev: %p !secret %d len %d ",
                  ctx->ecc_ctx, ctx->dev, !secret, len);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    ECJPAKE_CTX* ecc = (ECJPAKE_CTX*)ctx->ecc_ctx;
    ecc->role = (uint32_t)role;
    uint8_t raw_secret[6] = {'J', '0', '1', 'N', 'M', 'E'};
    uint8_t full_secret[32] = {0};

    memcpy(&full_secret[32 - len], secret, len);
    memcpy(ecc->secret, full_secret, 32);

    ctx->md_type = hash;
    ctx->gid = curve;

    return 0;
}

int mbedtls_ecjpake_check(const mbedtls_ecjpake_context* ctx) {
    // printf("%s\n", __func__);
    if (ctx == NULL) {
        log_error("ctx is NULL");
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    if (ctx->ecc_ctx == NULL || ctx->dev == NULL || ctx->key_array == NULL) {
        log_error(" ctx: %p, dev: %p key_array %p ", ctx->ecc_ctx, ctx->dev,
                  ctx->key_array);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    return 0;
}

int mbedtls_ecjpake_set_point_format(mbedtls_ecjpake_context* ctx,
                                     int point_format) {
    // printf("%s\n", __func__);
    if (ctx == NULL) {
        log_error("ctx is NULL");
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    ctx->point_format = point_format;

    return 0;
}

int pick_ecjpake_keykp_to_buf(unsigned char* buf, size_t len,
                              const ECJPAKEKeyKP* key, size_t* out_len) {
    if (len < 1 + 1 + 32 + 32 + 1 + 1 + 32 + 32 + 1 + 32) {
        printf("Buffer too small, need at least %d bytes but got %zu\n",
               1 + 1 + 32 + 32 + 1 + 1 + 32 + 32 + 1 + 32, len);
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }

    size_t offset = 0;

    // X lens 0x41
    buf[offset++] = 0x41;

    // Point format (0x04 = uncompressed)
    buf[offset++] = 0x04;

    // X point (32 bytes)
    memcpy(buf + offset, key->X.x, 32);
    offset += 32;

    // Y point (32 bytes)
    memcpy(buf + offset, key->X.y, 32);
    offset += 32;

    // V lens 0x41
    buf[offset++] = 0x41;

    // Point format (0x04 = uncompressed)
    buf[offset++] = 0x04;

    // V.x (32 bytes)
    memcpy(buf + offset, key->zkp.V.x, 32);
    offset += 32;

    // V.y (32 bytes)
    memcpy(buf + offset, key->zkp.V.y, 32);
    offset += 32;

    // r lens 0x20
    buf[offset++] = 0x20;

    // r (32 bytes)
    memcpy(buf + offset, key->zkp.r, 32);
    offset += 32;

    if (out_len)
        *out_len = offset;

    // printf("pick_ecjpake_keykp_to_buf: wrote %zu bytes\n", offset);
    return 0;
}

int parse_ecjpake_keykp_from_buf(const unsigned char* buf, size_t len,
                                 ECJPAKEKeyKP* key, size_t* parsed_len) {
    size_t offset = 0;
    uint8_t point_format = 0;
    if (len < 1 + 1 + 32 + 32 + 1 + 1 + 32 + 32 + 1 + 32) {
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }
    // X lens 0x41
    if (buf[offset++] != 0x41) {
        log_error("X lens error 0x%02X\n", buf[offset - 1]);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    // Point format (0x04 = uncompressed)
    point_format = buf[offset++];
    if (point_format != 0x04) {
        log_error("X Unexpected point format 0x%02X, expected 0x04\n",
                  point_format);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    // X point (32 bytes)
    memcpy(key->X.x, buf + offset, 32);
    offset += 32;

    // Y point (32 bytes)
    memcpy(key->X.y, buf + offset, 32);
    offset += 32;

    // V lens  0x41
    if (buf[offset++] != 0x41) {
        log_error("V lens error 0x%02X\n", buf[offset - 1]);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    // Point format (0x04 = uncompressed)
    point_format = buf[offset++];
    if (point_format != 0x04) {
        log_error("V Unexpected point format 0x%02X, expected 0x04\n",
                  point_format);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    // V.x (32 bytes)
    memcpy(key->zkp.V.x, buf + offset, 32);
    offset += 32;

    // V.y (32 bytes)
    memcpy(key->zkp.V.y, buf + offset, 32);
    offset += 32;

    // r lens 0x20
    if (buf[offset++] != 0x20) {
        log_error("r lens error 0x%02X\n", buf[offset - 1]);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    // r (32 bytes)
    memcpy(key->zkp.r, buf + offset, 32);
    offset += 32;

    if (parsed_len)
        *parsed_len = offset;

    // printf("parse_ecjpake_keykp_from_buf: parsed %zu bytes\n", offset);
    return 0;
}

// static void print_mpi(const char* title, uint8_t* buf) {
//     printf("%s X: ", title);
//     for (size_t i = 0; i < 32; i++)
//         printf("%02X", buf[i]);
//     printf("\n");
// }

// static void print_ecp_point(const char* title, const ECPoint_P256* P) {
//     printf("%s X: ", title);
//     for (int i = 0; i < 32; i++)
//         printf("%02X", P->x[i]);
//     printf("\n");

//     printf("%s Y: ", title);
//     for (int i = 0; i < 32; i++)
//         printf("%02X", P->y[i]);
//     printf("\n");
// }

// void print_ecjpake_context(const mbedtls_ecjpake_context* ctx) {
//     ECJPAKE_CTX* ecc = (ECJPAKE_CTX*)ctx->ecc_ctx;
//     printf("role: %d \n", ecc->role);
//     print_ecp_point("Xm1 (My public key 1)", &ecc->ecc_point_X1);
//     print_ecp_point("Xm2 (My public key 2)", &ecc->ecc_point_X2);
//     print_ecp_point("Xp1 (Peer public key 1)", &ecc->ecc_point_X3);
//     print_ecp_point("Xp2 (Peer public key 2)", &ecc->ecc_point_X4);
//     print_ecp_point("Xp (Peer combined public key)", &ecc->share_key);

//     print_mpi("xm1 (My private key 1)", (uint8_t*)&ecc->private_key_x1);
//     print_mpi("xm2 (My private key 2)", (uint8_t*)&ecc->private_key_x2);

//     print_mpi("s (Pre-shared secret)", (uint8_t*)&ecc->secret);
// }

int mbedtls_ecjpake_write_round_one(mbedtls_ecjpake_context* ctx,
                                    unsigned char* buf, size_t len,
                                    size_t* olen,
                                    int (*f_rng)(void*, unsigned char*, size_t),
                                    void* p_rng) {
    // printf("%s buf_len %d \n", __func__, len);
    if (ctx == NULL || ctx->dev == NULL) {
        log_error("ctx %p ctx->dev %p", ctx, ctx->dev);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    if (f_rng == NULL) {
        log_error("Error: f_rng is NULL");
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    hosal_ecjpake_dev_t* dev = (hosal_ecjpake_dev_t*)ctx->dev;

    // Make sure dev->ctx is the latest one pointing to ecc_ctx
    dev->ctx = (ECJPAKE_CTX*)ctx->ecc_ctx;
    dev->crypto_operation = HOSAL_ECJPAKE_GENERATE_ZKP;

    size_t offset = 0;
    memset(&dev->ctx->private_key_x1, 0, secp256r1_op_num_in_byte);
    memset(&dev->ctx->private_key_x2, 0, secp256r1_op_num_in_byte);
    f_rng(p_rng, (unsigned char*)&dev->ctx->private_key_x1,
          secp256r1_op_num_in_byte);
    f_rng(p_rng, (unsigned char*)&dev->ctx->private_key_x2,
          secp256r1_op_num_in_byte);

    ECJPAKEKeyKP* key_array = (ECJPAKEKeyKP*)ctx->key_array;
    ECJPAKEKeyKP* key = NULL;
    for (int i = 0; i < 2; i++) {
        if (dev->ctx->role == server_role) {
            key = (ECJPAKEKeyKP*)&key_array[i + 2];
        } else {
            key = (ECJPAKEKeyKP*)&key_array[i];
        }

        dev->key = key;

        dev->private_key = (i == 0) ? dev->ctx->private_key_x1
                                    : dev->ctx->private_key_x2;

        int ret = hosal_crypto_ecjpake_operation(dev);
        if (ret != 0) {
            log_error("ZKP generation failed key %d: %d\n", i, ret);
            return ret;
        }

        size_t pick_len = 0;
        ret = pick_ecjpake_keykp_to_buf(buf + offset, len - offset, key,
                                        &pick_len);
        if (ret != 0) {
            log_error("pick_ecjpake_keykp_from_buf failed on key %d: %d\n", i,
                      ret);
            return ret;
        }
        offset += pick_len;

        if (i == 0) {
            memcpy(&dev->ctx->ecc_point_X1, &key->X, sizeof(ECPoint_P256));
        } else {
            memcpy(&dev->ctx->ecc_point_X2, &key->X, sizeof(ECPoint_P256));
        }
    }
    *olen = offset;
    // print_ecjpake_context(ctx);
    return 0;
}

int mbedtls_ecjpake_read_round_one(mbedtls_ecjpake_context* ctx,
                                   const unsigned char* buf, size_t len) {
    // printf("%s buf_len %d \n", __func__, len);

    if (ctx == NULL || ctx->dev == NULL) {
        log_error("ctx %p ctx->dev %p", ctx, ctx->dev);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    hosal_ecjpake_dev_t* dev = (hosal_ecjpake_dev_t*)ctx->dev;
    dev->ctx = (ECJPAKE_CTX*)ctx->ecc_ctx;
    dev->crypto_operation = HOSAL_ECJPAKE_GENERATE_VERIFY;

    int ret = 0;
    size_t offset = 0;
    ECJPAKEKeyKP* key_array = (ECJPAKEKeyKP*)ctx->key_array;
    ECJPAKEKeyKP* key = NULL;

    for (int i = 0; i < 2; i++) {
        if (dev->ctx->role == server_role) {
            key = &key_array[i];
        } else {
            key = &key_array[i + 2];
        }

        size_t parsed_len = 0;
        ret = parse_ecjpake_keykp_from_buf(buf + offset, len - offset, key,
                                           &parsed_len);
        if (ret != 0) {
            log_error("parse_ecjpake_keykp_from_buf failed on key %d: %d\n", i,
                      ret);
            return ret;
        }
        offset += parsed_len;

        if (offset > len) {
            log_error("Offset exceeded buffer length: offset=%zu len=%zu\n",
                      offset, len);
            return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
        }

        dev->key = key;
        ret = hosal_crypto_ecjpake_operation(dev);
        if (ret != 0) {
            log_error("VERIFY failed key %d: %d\n", i, ret);
            return ret;
        }

        if (i == 0) {
            memcpy(&dev->ctx->ecc_point_X3, &key->X, sizeof(ECPoint_P256));
        } else {
            memcpy(&dev->ctx->ecc_point_X4, &key->X, sizeof(ECPoint_P256));
        }
    }
    // print_ecjpake_context(ctx);
    return 0;
}

int mbedtls_ecjpake_write_round_two(mbedtls_ecjpake_context* ctx,
                                    unsigned char* buf, size_t len,
                                    size_t* olen,
                                    int (*f_rng)(void*, unsigned char*, size_t),
                                    void* p_rng) {
    // printf("%s\n", __func__);
    if (ctx == NULL || ctx->dev == NULL || buf == NULL || olen == NULL) {
        log_error("ctx %p dev %p buf %p olen %p", ctx, ctx->dev, buf, olen);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    hosal_ecjpake_dev_t* dev = (hosal_ecjpake_dev_t*)ctx->dev;
    // Make sure dev->ctx is the latest one pointing to ecc_ctx
    ECJPAKEKeyKP* key_array = (ECJPAKEKeyKP*)ctx->key_array;
    ECJPAKEKeyKP* key = NULL;
    if (dev->ctx->role == server_role) {
        key = (ECJPAKEKeyKP*)&key_array[2];
    } else {
        key = (ECJPAKEKeyKP*)&key_array[0];
    }

    dev->ctx = (ECJPAKE_CTX*)ctx->ecc_ctx;
    dev->key = key;
    dev->crypto_operation = HOSAL_ECJPAKE_GENERATE_ZKP_2;

    int ret = hosal_crypto_ecjpake_operation(dev);
    if (ret != 0) {
        log_error("write_round_two failed key %d\n", ret);
        return ret;
    }

    size_t offset = 0;
    if (dev->ctx->role == server_role) {
        buf[offset++] = MBEDTLS_ECP_TLS_NAMED_CURVE;
        const mbedtls_ecp_curve_info* curve_info;
        if ((curve_info = mbedtls_ecp_curve_info_from_grp_id(ctx->gid))
            == NULL) {
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }
        buf[offset++] = (unsigned char)(curve_info->tls_id >> 8);
        buf[offset++] = (unsigned char)(curve_info->tls_id & 0xFF);
    }

    size_t pick_len = 0;
    ret = pick_ecjpake_keykp_to_buf(buf + offset, len - offset, key, &pick_len);
    if (ret != 0) {
        log_error("pick_ecjpake_keykp_from_buf failed %d\n", ret);
        return ret;
    }
    offset += pick_len;

    *olen = offset;
    // print_ecjpake_context(ctx);
    return 0;
}

int mbedtls_ecjpake_read_round_two(mbedtls_ecjpake_context* ctx,
                                   const unsigned char* buf, size_t len) {
    // printf("%s\n", __func__);
    if (ctx == NULL || ctx->dev == NULL) {
        log_error("ctx %p ctx->dev %p", ctx, ctx->dev);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    hosal_ecjpake_dev_t* dev = (hosal_ecjpake_dev_t*)ctx->dev;
    dev->ctx = (ECJPAKE_CTX*)ctx->ecc_ctx;
    dev->crypto_operation = HOSAL_ECJPAKE_GENERATE_VERIFY_2;

    ECJPAKEKeyKP* key_array = (ECJPAKEKeyKP*)ctx->key_array;
    ECJPAKEKeyKP* key = NULL;
    if (dev->ctx->role == server_role) {
        key = (ECJPAKEKeyKP*)&key_array[0];
    } else {
        key = (ECJPAKEKeyKP*)&key_array[2];
    }

    size_t offset = 0;
    //If the client receives round 2 from the server, it skips the GID prefix
    if (dev->ctx->role != server_role) {
        if (len < 3 || buf[0] != MBEDTLS_ECP_TLS_NAMED_CURVE) {
            log_error("Invalid EC parameters header\n");
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }
        offset = 3;
    }
    size_t parsed_len = 0;
    int ret = parse_ecjpake_keykp_from_buf(buf + offset, len - offset, key,
                                           &parsed_len);
    if (ret != 0) {
        log_error("parse_ecjpake_keykp_from_buf failed %d\n", ret);
        return ret;
    }
    offset += parsed_len;

    if (offset > len) {
        log_error("Offset exceeded buffer length: offset=%zu len=%zu\n", offset,
                  len);
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }

    dev->key = key;

    ret = hosal_crypto_ecjpake_operation(dev);
    if (ret != 0) {
        log_error("VERIFY round two failed: %d\n", ret);
        return ret;
    }

    memcpy(&dev->ctx->share_key, &key->zkp.V, sizeof(ECPoint_P256));

    // print_ecjpake_context(ctx);
    return 0;
}

int mbedtls_ecjpake_derive_secret(mbedtls_ecjpake_context* ctx,
                                  unsigned char* buf, size_t len, size_t* olen,
                                  int (*f_rng)(void*, unsigned char*, size_t),
                                  void* p_rng) {
    // printf("%s\n buf_len %d", __func__, len);
    if (len < 32) {
        log_error("derive_secret: output buf too small!\n");
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }
    hosal_ecjpake_dev_t* dev = (hosal_ecjpake_dev_t*)ctx->dev;

    ECJPAKEKeyKP* key_array = (ECJPAKEKeyKP*)ctx->key_array;
    ECJPAKEKeyKP* key = NULL;
    // printf("dev->role = %d\n", dev->ctx->role);
    if (dev->ctx->role == server_role) {
        key = (ECJPAKEKeyKP*)&key_array[0];
    } else {
        key = (ECJPAKEKeyKP*)&key_array[2];
    }

    dev->crypto_operation = HOSAL_ECJPAKE_COMPUTE_KEY;
    dev->key = key;
    dev->pms = buf;

    int ret = hosal_crypto_ecjpake_operation(dev);
    if (ret == 0 && olen) {
        *olen = 32;
        // print_ecjpake_context(ctx);
    } else {
        log_error("Key derivation failed, ret = %d\n", ret);
    }

    return ret;
}

int mbedtls_ecjpake_write_shared_key(
    mbedtls_ecjpake_context* ctx, unsigned char* buf, size_t len, size_t* olen,
    int (*f_rng)(void*, unsigned char*, size_t), void* p_rng) {
    // printf("%s\n", __func__);
    return mbedtls_ecjpake_derive_secret(ctx, buf, len, olen, f_rng, p_rng);
}