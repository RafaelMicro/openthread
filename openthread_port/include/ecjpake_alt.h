#ifndef ECJPAKE_ALT_H
#define ECJPAKE_ALT_H
#include <stdio.h>
#include "mbedtls/ecp.h"
#include "mbedtls/md.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mbedtls_ecjpake_context {
    void* ecc_ctx;
    void* dev;
    void* key_array;
    mbedtls_ecp_group_id gid;
    mbedtls_md_type_t md_type;
    int point_format;
} mbedtls_ecjpake_context;

#include "mbedtls/ecjpake.h"

#ifdef __cplusplus
}
#endif

#endif // ECJPAKE_ALT_H