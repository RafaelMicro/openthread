
#include <assert.h>
#include <errno.h>
#include <stdio.h>

#include <FreeRTOS.h>
#include <semphr.h>
#include <task.h>
// #include <openthread-core-config.h>
#include <openthread/cli.h>
#include <openthread/diag.h>
#include <openthread/ncp.h>
#include <openthread/tasklet.h>

// #include "mbedtls/platform.h"
#include "openthread_port.h"

// #include <mbedtls/platform.h>

#include "log.h"

ot_system_event_t ot_system_event_var = OT_SYSTEM_EVENT_NONE;
static SemaphoreHandle_t ot_extLock = NULL;
static otInstance* ot_instance = NULL;
static TaskHandle_t ot_taskHandle = NULL;

static StaticQueue_t stackLock;

// static StaticTask_t ot_task;

// static StackType_t ot_stackTask_stack[OT_TASK_SIZE];

__attribute__((weak)) void otrAppProcess(ot_system_event_t sevent) {}

void otTaskletsSignalPending(otInstance* aInstance) {
    if (aInstance) {
        OT_NOTIFY(OT_SYSTEM_EVENT_OT_TASKLET);
    }
}

otInstance* otrGetInstance() { return ot_instance; }

void otSysProcessDrivers(otInstance* aInstance) {
    ot_system_event_t sevent = OT_SYSTEM_EVENT_NONE;

    OT_GET_NOTIFY(sevent);
    ot_alarmTask(sevent);
#ifndef CONFIG_OT_RCP_EZMESH
    otrAppProcess(sevent);
#endif
    ot_uartTask(sevent);
    ot_radioTask(sevent);
}

void otSysEventSignalPending(void) {
    if (xPortIsInsideInterrupt()) {
        BaseType_t pxHigherPriorityTaskWoken = pdTRUE;
        vTaskNotifyGiveFromISR(ot_taskHandle, &pxHigherPriorityTaskWoken);
    } else {
        xTaskNotifyGive(ot_taskHandle);
    }
}

void otrLock(void) {
    if (ot_extLock) {
        xSemaphoreTake(ot_extLock, portMAX_DELAY);
    }
}

void otrUnlock(void) {
    if (ot_extLock) {
        xSemaphoreGive(ot_extLock);
    }
}

void otrStackInit(void) {
    ot_instance = otInstanceInitSingle();
    assert(ot_instance);
}

extern void rf_ot_cpc_rcp_process(void);

static void otrStackTask(void* aContext) {
    /** This task is an example to handle both main event loop of openthread task lets and 
     * hardware drivers for openthread, such as radio, alarm timer and also uart shell.
     * Customer can implement own task for both of two these missions with other privoded APIs.  */

    OT_THREAD_SAFE(ot_entropy_init();
                   ot_alarmInit(); ot_radioInit(); otrStackInit();
#if OPENTHREAD_ENABLE_DIAG
                   otDiagInit(ot_instance);
#endif
                   otAppCliInit(ot_instance);
#ifdef CONFIG_OT_RCP_EZMESH
                   rf_ot_cpc_init();
#endif
    );

    while (true) {
        if (ulTaskNotifyTake(pdFALSE, 5) != 0) {
            otTaskletsProcess(ot_instance);
            otSysProcessDrivers(ot_instance);
#ifdef CONFIG_OT_RCP_EZMESH
            rf_ot_cpc_rcp_process();
#endif
        }
    }

    otInstanceFinalize(ot_instance);
    ot_instance = NULL;

    vTaskDelete(NULL);
}

void otrStart(void) {
    ot_extLock = xSemaphoreCreateMutexStatic(&stackLock);
    configASSERT(ot_extLock != NULL);

    OT_THREAD_SAFE(xTaskCreate(otrStackTask, "ot-thread",
                               CONFIG_OPENTHREAD_TASK_SIZE, ot_instance,
                               E_TASK_PRIORITY_OPENTHREAD, &ot_taskHandle);)
}
