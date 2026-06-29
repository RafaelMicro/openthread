/**
 * @file ot_alarm.c
 * @author Rex Huang (rex.huang@rafaelmicro.com)
 * @brief 
 * @version 0.1
 * @date 2023-07-25
 * 
 * @copyright Copyright (c) 2023
 * 
 */

// #include "openthread-system.h"
#include <assert.h>
#include <openthread/config.h>
#include <openthread/link.h>
#include <openthread/platform/alarm-micro.h>
#include <openthread/platform/alarm-milli.h>
#include <openthread/platform/diag.h>
#include <openthread/platform/radio.h>
#include <openthread/thread.h>
#include <openthread_port.h>
#include <stdbool.h>
#include <stdint.h>
// #include "common/logging.hpp"

#include "code_utils.h"

#include "FreeRTOS.h"
#include "semphr.h"
#include "task.h"
#include "timers.h"

#include "lmac15p4.h"
#include "log.h"
#include "mcu.h"
#include "timer.h"

static TimerHandle_t otAlarm_timerHandle = NULL;
static uint32_t otAlarm_offset = 0xFFFFFFF;

#define OT_US_PER_MS            1000
#if (OPENTHREAD_CONFIG_PLATFORM_USEC_TIMER_ENABLE == 1)
#if defined(CONFIG_RT581) || defined(CONFIG_RT582) || defined(CONFIG_RT583)
    #define ALARM_MICRO_SEC_TO_TIMER_TICK(n)                                        \
        ((uint32_t)((((uint64_t)(n)) + 12ULL) / 25ULL))
#elif defined(CONFIG_RT584H) || defined(CONFIG_RT584L) || defined(CONFIG_RT584HA4)
    #define ALARM_MICRO_SEC_TO_TIMER_TICK(n)                                        \
        ((uint32_t)((((uint64_t)(n) * 4ULL) + 62ULL) / 125ULL))
#endif
#define ALRAM_SLEEP_WAKE_UP_COST_MS   (3ul)
#endif

static void otPlatALarm_msTimerCallback(TimerHandle_t xTimer) {
    OT_NOTIFY(OT_SYSTEM_EVENT_ALARM_MS_EXPIRED);
}

#if (OPENTHREAD_CONFIG_PLATFORM_USEC_TIMER_ENABLE == 1)
static void otPlatALarm_usTimerCallback() {
    OT_NOTIFY_ISR(OT_SYSTEM_EVENT_ALARM_US_EXPIRED);
}
#endif

void ot_alarmInit(void) {
    otAlarm_timerHandle = xTimerCreate("ot_timer", 1, pdFALSE,
                                       (void*)otAlarm_timerHandle,
                                       otPlatALarm_msTimerCallback);
#if (OPENTHREAD_CONFIG_PLATFORM_USEC_TIMER_ENABLE == 1)
    timer_config_mode_t cfg;

    #if defined(CONFIG_RT581) || defined(CONFIG_RT582) || defined(CONFIG_RT583)
    timern_t* TIMER = TIMER3;
    NVIC_DisableIRQ((IRQn_Type)(Timer3_IRQn));
    NVIC_SetPriority((IRQn_Type)(Timer3_IRQn), 2);
    #elif defined(CONFIG_RT584H) || defined(CONFIG_RT584L) || defined(CONFIG_RT584HA4)
    slowtimern_t* TIMER = SLOWTIMER0;
    NVIC_DisableIRQ((IRQn_Type)(SlowTimer0_IRQn));
    NVIC_SetPriority((IRQn_Type)(SlowTimer0_IRQn), 2);
    #endif

    TIMER->load = 0;
    TIMER->clear = 1;
    TIMER->control.reg = 0;

    TIMER->control.bit.prescale = TIMER_PRESCALE_1;
    TIMER->control.bit.mode = TIMER_FREERUN_MODE;
    TIMER->control.bit.en = 0;

    #if defined(CONFIG_RT581) || defined(CONFIG_RT582) || defined(CONFIG_RT583)
    timer_callback_register(3, otPlatALarm_usTimerCallback);
    NVIC_EnableIRQ((IRQn_Type)Timer3_IRQn);
    #elif defined(CONFIG_RT584H) || defined(CONFIG_RT584L) || defined(CONFIG_RT584HA4)
    slowtimer_callback_register(0, otPlatALarm_usTimerCallback);
    NVIC_EnableIRQ((IRQn_Type)SlowTimer0_IRQn);
    #endif
#endif
}

void ot_alarmTask(ot_system_event_t sevent) {
    if (!(OT_SYSTEM_EVENT_ALARM_ALL_MASK & sevent)) {
        return;
    }
    if (OT_SYSTEM_EVENT_ALARM_MS_EXPIRED & sevent) {
        otPlatAlarmMilliFired(otrGetInstance());
    }
#if (OPENTHREAD_CONFIG_PLATFORM_USEC_TIMER_ENABLE == 1)
    if (OT_SYSTEM_EVENT_ALARM_US_EXPIRED & sevent) {
        otPlatAlarmMicroFired(otrGetInstance());
    }
#endif
}

uint16_t otPlatTimeGetXtalAccuracy(void)
{
    return 200;
}

void otPlatAlarmMilliStartAt(otInstance* aInstance, uint32_t aT0,
                             uint32_t aDt) {
    BaseType_t ret;
    uint32_t fireTime = aT0 + aDt;
    uint32_t now = otPlatAlarmMilliGetNow();
    uint32_t diff = now - fireTime;  
    bool isExpired = (diff & (1U << 31)) == 0; 

    if (!isExpired)
    {
        uint32_t remaining = fireTime - now;  
        uint32_t ticks = pdMS_TO_TICKS(remaining);
        ret = xTimerChangePeriod(otAlarm_timerHandle, ticks, 0);  
        configASSERT(ret == pdPASS);
    }
    else
    {
        OT_NOTIFY(OT_SYSTEM_EVENT_ALARM_MS_EXPIRED);
    }
}

void otPlatAlarmMilliStop(otInstance* aInstance) {
    if (otAlarm_timerHandle && xTimerIsTimerActive(otAlarm_timerHandle) == pdTRUE) {
        xTimerStop(otAlarm_timerHandle, 0);
    }
}

uint32_t otPlatAlarmMilliGetNow(void) {
#if (OPENTHREAD_CONFIG_PLATFORM_USEC_TIMER_ENABLE == 1)
    return (uint32_t)(otPlatTimeGet() / OT_US_PER_MS);  
#else
    return xTaskGetTickCount() * portTICK_RATE_MS;
#endif
}

#if (OPENTHREAD_CONFIG_PLATFORM_USEC_TIMER_ENABLE == 1)
inline uint32_t otPlatAlarmMicroGetNow(void) {
    uint32_t rtc_curr_time;
    lmac15p4_rtc_time_read((uint32_t*)&rtc_curr_time);
    return rtc_curr_time;
}

void otPlatAlarmMicroStartAt(otInstance* aInstance, uint32_t aT0,
                             uint32_t aDt) {
    OT_UNUSED_VARIABLE(aInstance);
    #if defined(CONFIG_RT581) || defined(CONFIG_RT582) || defined(CONFIG_RT583)
    timern_t* TIMER = TIMER3;
    #elif defined(CONFIG_RT584H) || defined(CONFIG_RT584L) || defined(CONFIG_RT584HA4)
    slowtimern_t* TIMER = SLOWTIMER0;
    #endif
    uint32_t Curr_us = otPlatTimeGet();
    uint32_t fireTime = (aT0 + aDt);
    uint32_t diff = Curr_us - fireTime;  
    bool isExpired = (diff & (1U << 31)) == 0;

    if (!isExpired) {
        uint32_t remaining = fireTime - Curr_us;
#if (CONFIG_HOSAL_SOC_IDLE_SLEEP == 1)
        if (remaining > (ALRAM_SLEEP_WAKE_UP_COST_MS * OT_US_PER_MS)) {
            remaining -= (ALRAM_SLEEP_WAKE_UP_COST_MS * OT_US_PER_MS);
        }
#endif
        {
            TIMER->load = ALARM_MICRO_SEC_TO_TIMER_TICK(remaining);

            TIMER->clear = 1;
            TIMER->control.bit.int_enable = 1;
            TIMER->control.bit.en = 1;
        }
    } else {
        OT_NOTIFY(OT_SYSTEM_EVENT_ALARM_US_EXPIRED);
    }
}

void otPlatAlarmMicroStop(otInstance* aInstance) {
    OT_UNUSED_VARIABLE(aInstance);
    #if defined(CONFIG_RT581) || defined(CONFIG_RT582) || defined(CONFIG_RT583)
    timern_t* TIMER = TIMER3;
    #elif defined(CONFIG_RT584H) || defined(CONFIG_RT584L) || defined(CONFIG_RT584HA4)
    slowtimern_t* TIMER = SLOWTIMER0;
    #endif
    TIMER->control.bit.en = 0;
    TIMER->control.bit.int_enable = 0;
    TIMER->clear = 1; /*clear interrupt*/
}
#endif

uint64_t otPlatTimeGet(void) {
    static uint32_t timerWraps = 0U;
    static uint32_t prev32Time = 0U;
    uint32_t now32Time;
    uint64_t now64Time;
#if (OPENTHREAD_CONFIG_PLATFORM_USEC_TIMER_ENABLE == 1)
    now32Time = otPlatAlarmMicroGetNow();
#else
    now32Time = otPlatAlarmMilliGetNow();
#endif
    enter_critical_section();
    if (now32Time < prev32Time) {
        timerWraps += 1U;
    }
    prev32Time = now32Time;
    leave_critical_section();
    now64Time = ((uint64_t)timerWraps << 32) + now32Time;

    return now64Time;
}