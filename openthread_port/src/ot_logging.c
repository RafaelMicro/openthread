/**
 * @file ot_logging.c
 * @author Rex Huang (rex.huang@rafaelmicro.com)
 * @brief 
 * @version 0.1
 * @date 2023-07-25
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <openthread/config.h>
#include <openthread/platform/logging.h>
#include <openthread_port.h>

extern void vprint(const char* fmt, va_list argp);

void otPlatLog(otLogLevel aLogLevel, otLogRegion aLogRegion,
               const char* aFormat, ...) {
    va_list argp;

    va_start(argp, aFormat);
    vprint(aFormat, argp);
    printf("\n\r");
    va_end(argp);
}
