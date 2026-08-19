#include "mbedtls/platform_time.h"

#include "FreeRTOS.h"
#include "task.h"

/* This target has no POSIX/Windows clock backing mbedTLS's built-in
 * mbedtls_ms_time() (see mbedtls/library/platform_util.c), so provide a
 * monotonic millisecond clock from the FreeRTOS tick count instead.
 */
mbedtls_ms_time_t mbedtls_ms_time(void)
{
    return (mbedtls_ms_time_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
}

/* This target's <time.h> does not declare time() either (newlib-nano
 * freestanding build), so also provide the second-resolution clock mbedTLS
 * falls back to (mbedtls_time, see MBEDTLS_PLATFORM_TIME_MACRO below) as a
 * monotonic clock derived from the same FreeRTOS tick count. Not wall-clock
 * time - this build has no RTC and does not use TLS/X.509 time validation.
 */
mbedtls_time_t rafael_mbedtls_time(mbedtls_time_t *aTime)
{
    mbedtls_time_t now = (mbedtls_time_t)(xTaskGetTickCount() * portTICK_PERIOD_MS / 1000);

    if (aTime != NULL)
    {
        *aTime = now;
    }

    return now;
}
