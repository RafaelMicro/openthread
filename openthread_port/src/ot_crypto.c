/*
 *  Copyright (c) 2022, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */
/**
 * @file
 *    This file implements the Crypto platform APIs.
 */
#include <assert.h>
#include <openthread_port.h>

#include <openthread-core-config.h>
#include <openthread/config.h>
#include <openthread/platform/crypto.h>
#include <string.h>
#include "hosal_crypto_aes.h"
#include "hosal_crypto_sha256.h"
#include "hosal_gpio.h"
#include "log.h"
#include "hosal_trng.h"
#if 0
static hosal_aes_dev_t aes_dev;
static hosal_sha256_dev_t sha256_dev;
static uint8_t tmp_key[AES_BLOCKLEN] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
                                        0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                        0x09, 0xcf, 0x4f, 0x3c};

typedef struct {
    uint8_t buffer[256];
    uint16_t length;
} otCryptoSha256Context;

static otCryptoSha256Context shaContext;

otError otPlatCryptoAesInit(otCryptoContext* aContext) {
    OT_UNUSED_VARIABLE(aContext);
    memset(&aes_dev, 0, sizeof(aes_dev));
    hosal_crypto_aes_init();
    return OT_ERROR_NONE;
}

otError otPlatCryptoAesSetKey(otCryptoContext* aContext,
                              const otCryptoKey* aKey) {
    OT_UNUSED_VARIABLE(aContext);
    assert(aKey->mKey != NULL);
    assert(aKey->mKeyLength == 16);
    memcpy(tmp_key, aKey->mKey, aKey->mKeyLength);
    aes_dev.bit = HOSAL_AES_128_BIT;
    aes_dev.key_ptr = tmp_key;

    return OT_ERROR_NONE;
}

otError otPlatCryptoAesEncrypt(otCryptoContext* aContext, const uint8_t* aInput,
                               uint8_t* aOutput) {
    aes_dev.crypto_operation = HOSAL_AES_CRYPTO_ENCRYPT;
    aes_dev.in_ptr = (uint8_t*)aInput;
    aes_dev.out_ptr = aOutput;
    hosal_gpio_pin_set(21);
    OT_ENTER_CRITICAL();
    otError ret = hosal_crypto_aes_operation(&aes_dev) ? OT_ERROR_FAILED
                                                       : OT_ERROR_NONE;
    OT_EXIT_CRITICAL();
    hosal_gpio_pin_clear(21);
    return ret;
}

otError otPlatCryptoAesFree(otCryptoContext* aContext) {
    OT_UNUSED_VARIABLE(aContext);
    return OT_ERROR_NONE;
}
#endif
otError otPlatCryptoRandomGet(uint8_t* aBuffer, uint16_t aSize) 
{
    for (size_t i = 0; i < aSize; i++) {
        uint32_t rand;
        hosal_trng_get_random_number(&rand, 1);
        aBuffer[i] = (uint8_t)rand & 0xff;
    }
    return OT_ERROR_NONE;
}