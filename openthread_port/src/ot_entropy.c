/**
 * @file ot_entropy.c
 * @author Rex Huang (rex.huang@rafaelmicro.com)
 * @brief 
 * @version 0.1
 * @date 2023-07-25
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include <openthread/platform/entropy.h>

#include <openthread/platform/radio.h>

#include "code_utils.h"
#include "log.h"
#include "mcu.h"
#include "hosal_trng.h"

extern uint32_t otPlatAlarmMilliGetNow(void);
static uint32_t sRandomSeed = 0;

void ot_entropy_init(void) 
{ 
    hosal_trng_get_random_number(&sRandomSeed, 1); 
}

otError otPlatEntropyGet(uint8_t* aOutput, uint16_t aOutputLength) {
    otError error = OT_ERROR_NONE;

    otEXPECT_ACTION(aOutput, error = OT_ERROR_INVALID_ARGS);

    for (uint16_t index = 0; index < aOutputLength; index++)
    {
        uint32_t rand;
        hosal_trng_get_random_number(&rand, 1);
        aOutput[index] = (uint8_t)rand & 0xff;
    }
exit:
    return error;
}
