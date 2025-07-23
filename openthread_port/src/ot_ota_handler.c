/**
 * @file ota_handle.c
 * @author Jiemin Cao(jiemin.cao@rafaelmicro.com)
 * @brief
 * @version 0.1
 * @date 2023-12-26
 *
 * @copyright Copyright (c) 2022
 *
 */

//=============================================================================
//                Include
//=============================================================================
/* Utility Library APIs */
// #include <openthread-system.h>
#include <openthread/coap.h>
#include <openthread/thread_ftd.h>
#include <openthread/platform/misc.h>
#include <openthread/random_noncrypto.h>
#include <openthread_port.h>
#include "FreeRTOS.h"
#include <semphr.h>
#include <task.h>
#include "timers.h"
#include "log.h"
#include "queue.h"
#include "ot_ota_handler.h"
#include "util_string.h"
#include "cli.h"
//=============================================================================
//                Private Function Declaration
//=============================================================================
unsigned int ota_debug_flags = 0;
#define ota_printf(args, ...)        \
    do {                                \
        if(ota_debug_flags > 0)    \
            printf(args, ##__VA_ARGS__);                 \
    }while(0);

//=============================================================================
//                Private ENUM
//=============================================================================

//=============================================================================
//                Private Struct
//=============================================================================

//=============================================================================
//                Private Function Declaration
//=============================================================================
static void ota_response_table_handler(uint16_t *req_table);
static void ota_change_state_and_timer(uint8_t state, uint32_t timeout);
//=============================================================================
//                Private Global Variables
//=============================================================================
static QueueHandle_t ota_even_queue;

static TimerHandle_t ota_timer;
static TimerHandle_t ota_resp_timer;
otIp6Address ota_sender_addr;
otCoapResource ota_data_resource;
otCoapResource ota_req_resource;
otCoapResource ota_resp_resource;
otCoapResource ota_report_resource;
const char ota_data_Uri_Path[] = RAFAEL_OTA_URL_DATA;
const char ota_req_Uri_Path[] = RAFAEL_OTA_URL_REQ;
const char ota_resp_Uri_Path[] = RAFAEL_OTA_URL_RESP;
const char ota_report_Uri_Path[] = RAFAEL_OTA_URL_REPORT;
static volatile uint8_t g_ota_state = OTA_IDLE;
static uint32_t *g_ota_bitmap = NULL;
static uint8_t g_ota_request_cnt = 0;
static uint8_t g_ota_unicast_try_cnt = 0;
static uint32_t g_ota_request_last_remain = 0;
static uint16_t g_ota_segments_size = 0;
static uint16_t g_ota_data_intervel = 0;
static uint32_t g_ota_image_version = 0;
static uint32_t g_ota_image_size = 0;
static uint32_t g_ota_image_crc = 0;
static uint32_t g_ota_toatol_num = 0;
static uint32_t g_ota_start_index = 0;
static uint32_t g_ota_last_index = 0;
static bool have_data_ack = false;
static bool need_reboot = true;
static uint8_t g_ota_response_k = 2;
static uint8_t g_ota_response_c = 0;
static uint16_t g_resp_table[OTA_RESPONSE_TABLE_SIZE];
//=============================================================================
//                Functions
//=============================================================================
uint32_t crc32checksum(uint32_t flash_addr, uint32_t data_len)
{
    uint16_t k;
    uint32_t i;
    uint8_t *buf = ((uint8_t *)flash_addr);
    uint32_t chkSum = ~0, len = data_len;
    enter_critical_section();
    for (i = 0; i < len; i ++ )
    {
        chkSum ^= *buf++;
        for (k = 0; k < 8; k ++)
        {
            chkSum = chkSum & 1 ? (chkSum >> 1) ^ 0xedb88320 : chkSum >> 1;
        }
    }
    leave_critical_section();
    return ~chkSum;
}

/*bit map*/
uint32_t *ota_bitmap_init(uint32_t lens)
{
    uint16_t bitmap_size;
    uint32_t *bitmap = NULL;
    bitmap_size = (lens >> 5);
    if (lens % 32)
    {
        ++bitmap_size;
    }
    bitmap_size *= sizeof(uint32_t);

    ota_printf("ota_bitmap_init \r\n");
    bitmap = pvPortMalloc(bitmap_size);
    if (NULL == bitmap)
    {
        ota_printf("ota_bitmap_init fail \r\n");
    }
    else
    {
        memset(bitmap, 0x0, bitmap_size);
    }
    return bitmap;
}

void ota_bitmap_set(uint32_t *bitmap, uint32_t index)
{
    if (NULL == bitmap)
    {
        ota_printf("ota_bitmap_set bitmap null \r\n");
        return;
    }
    enter_critical_section();
    uint32_t tmp_index = 0, bit = 0;
    tmp_index = index >> 5;
    bit = index % 32;

    bitmap[tmp_index] |= 0x1 << bit;
    leave_critical_section();
}

void ota_bitmap_delete(uint32_t *bitmap)
{
    ota_printf("ota_bitmap_delete \r\n");
    if (bitmap)
    {
        vPortFree(bitmap);
    }
}

uint32_t ota_bitmap_get_bit(uint32_t *bitmap, uint32_t index)
{
    if (NULL == bitmap)
    {
        ota_printf("bitmap get fail \n");
        ota_change_state_and_timer(OTA_IDLE, 0);
        return 0;
    }
    uint32_t tmp_index = index >> 5, bit = 0;

    bit = index % 32;
    return (bitmap[tmp_index] & (0x1 << bit));
}

uint32_t ota_bitmap_get_remain(uint32_t *bitmap, uint32_t lens)
{
    if (NULL == bitmap)
    {
        ota_printf("bitmap get fail \n");
        ota_change_state_and_timer(OTA_IDLE, 0);
        return 0;
    }
    uint32_t tmp_lens = lens >> 5, i = 0, j = 0, remain = 0;
    if (lens % 32)
    {
        ++tmp_lens;
    }

    for (i = 0; i < tmp_lens; i++)
    {
        if (i == (tmp_lens - 1))
        {
            for (j = 0 ; j < (lens % 32); j++)
            {
                if ((bitmap[i] & (0x1 << j)) == 0)
                {
                    ++remain;
                }
            }
        }
        else
        {
            for (j = 0 ; j < 32; j++)
            {
                if ((bitmap[i] & (0x1 << j)) == 0)
                {
                    ++remain;
                }
            }
        }
    }
    return remain;
}

void ota_bitmap_print(uint32_t *bitmap, uint32_t lens)
{
    uint32_t tmp_lens = lens >> 5, i = 0;
    if (lens % 32)
    {
        ++tmp_lens;
    }

    for (i = 0; i < tmp_lens; i++)
    {
        ota_printf("%X ", bitmap[i]);
    }
    ota_printf("\n\n");
}

static void ota_change_state_and_timer(uint8_t state, uint32_t timeout)
{
    if (state == OTA_IDLE && timeout == 0)
    {
        xTimerStop(ota_timer, 0);

        ota_printf("\n============ota done============\n");
        ota_bitmap_delete(g_ota_bitmap);
        g_ota_bitmap = NULL;
    }
    else
    {
        xTimerChangePeriod(ota_timer, pdMS_TO_TICKS(timeout), 0);
        if (!xTimerIsTimerActive(ota_timer))
        {
            xTimerStart(ota_timer, 0);
        }
    }
    g_ota_state = state;
}

uint32_t ota_get_image_version()
{
    return g_ota_image_version;
}

void ota_set_image_version(uint32_t version)
{
    g_ota_image_version = version;
}

uint32_t ota_get_image_size()
{
    return g_ota_image_size;
}

void ota_set_image_size(uint32_t size)
{
    g_ota_image_size = size;
}

uint32_t ota_get_image_crc()
{
    return g_ota_image_crc;
}

void ota_set_image_crc(uint32_t crc)
{
    g_ota_image_crc = crc;
}

uint8_t ota_get_state()
{
    return g_ota_state;
}

const char *OtaStateToString(ota_state_t state)
{
    static const char *const kOtaStateStrings[] =
    {
        "Idle",
        "DataSending",
        "DataReceiving",
        "RequestSending",
        "Done",
        "Reboot",
    };

    return ((state > OTA_REBOOT) && (state < OTA_IDLE))  ? "invalid" : kOtaStateStrings[state - OTA_IDLE];
}

void ota_bootloader_info_check()
{
    uint32_t file_ver, crc32;
    fota_information_t t_bootloader_ota_info = {0};
    memcpy(&t_bootloader_ota_info, (uint8_t *)FOTA_UPDATE_BANK_INFO_ADDRESS, sizeof(t_bootloader_ota_info));
    file_ver = (uint32_t)t_bootloader_ota_info.reserved[0];

    do
    {
        if (t_bootloader_ota_info.fotabank_ready == FOTA_IMAGE_READY)
        {
            if (t_bootloader_ota_info.fota_result == FOTA_RESULT_SUCCESS)
            {
                ota_set_image_version(file_ver);
                ota_set_image_size((t_bootloader_ota_info.fotabank_datalen + 0x20));
                ota_set_image_crc(t_bootloader_ota_info.fotabank_crc);
                t_bootloader_ota_info.fotabank_ready = FOTA_IMAGE_READY + 1;
            }
            else
            {
                t_bootloader_ota_info.fotabank_ready = FOTA_IMAGE_READY + 1;
            }
        }
        else
        {
            if (t_bootloader_ota_info.fotabank_startaddr == (OTA_FLASH_START + 0x20) &&
                    t_bootloader_ota_info.fotabank_datalen <= SIZE_OF_FOTA_BANK_1MB)
            {
                crc32 = crc32checksum(t_bootloader_ota_info.fotabank_startaddr, t_bootloader_ota_info.fotabank_datalen);
                if (crc32 == t_bootloader_ota_info.fotabank_crc)
                {
                    ota_set_image_version(file_ver);
                    ota_set_image_size((t_bootloader_ota_info.fotabank_datalen + 0x20));
                    ota_set_image_crc(t_bootloader_ota_info.fotabank_crc);
                }
                else
                {
                    log_error("ota crc fail %04X %04X\n", crc32, t_bootloader_ota_info.fotabank_crc);
                }
                t_bootloader_ota_info.fotabank_ready = FOTA_IMAGE_READY + 1;
            }
        }
        enter_critical_section();
        while (flash_check_busy());
        flash_erase(FLASH_ERASE_SECTOR, FOTA_UPDATE_BANK_INFO_ADDRESS);
        while (flash_check_busy());
        flash_write_page((uint32_t)&t_bootloader_ota_info, FOTA_UPDATE_BANK_INFO_ADDRESS);
        while (flash_check_busy());
        leave_critical_section();
    } while (0);

    printf("ota ver : 0x%08x\n", ota_get_image_version());
}

static void ota_reboot_handler()
{
    ota_printf("Reboot");
    otPlatReset(NULL);
}

static void ota_bootinfo_ready()
{
    static uint8_t program_data[0x100];
    static fota_information_t t_bootloader_ota_info = {0};
    memcpy(&t_bootloader_ota_info, (uint8_t *)FOTA_UPDATE_BANK_INFO_ADDRESS, sizeof(t_bootloader_ota_info));

    t_bootloader_ota_info.fotabank_ready = FOTA_IMAGE_READY;

    memset(&program_data, 0xFF, 0x100);
    memcpy(&program_data, (uint8_t *)&t_bootloader_ota_info, sizeof(fota_information_t));

    enter_critical_section();
    while (flash_check_busy());
    flash_erase(FLASH_ERASE_SECTOR, FOTA_UPDATE_BANK_INFO_ADDRESS);

    while (flash_check_busy());
    flash_write_page((uint32_t)&program_data, FOTA_UPDATE_BANK_INFO_ADDRESS);
    while (flash_check_busy());
    leave_critical_section();

    ota_printf("bootinfo ready");
}

void ota_bootinfo_reset()
{
    static uint8_t program_data[0x100];
    static fota_information_t t_bootloader_ota_info = {0};
    // memcpy(&t_bootloader_ota_info, (uint8_t *)FOTA_UPDATE_BANK_INFO_ADDRESS, sizeof(t_bootloader_ota_info));
    t_bootloader_ota_info.fotabank_startaddr = (OTA_FLASH_START + 0x20);
    t_bootloader_ota_info.signature_len = 0;
    t_bootloader_ota_info.target_startaddr = APP_START_ADDRESS;
    t_bootloader_ota_info.fotabank_datalen = ota_get_image_size() - 0x20;
    t_bootloader_ota_info.fota_image_info = FOTA_IMAGE_INFO_COMPRESSED;
    t_bootloader_ota_info.reserved[0] = ota_get_image_version();
    t_bootloader_ota_info.fota_result = 0xFF;
    t_bootloader_ota_info.fotabank_crc =  ota_get_image_crc();


    memset(&program_data, 0xFF, 0x100);
    memcpy(&program_data, (uint8_t *)&t_bootloader_ota_info, sizeof(fota_information_t));

    enter_critical_section();
    while (flash_check_busy());
    flash_erase(FLASH_ERASE_SECTOR, FOTA_UPDATE_BANK_INFO_ADDRESS);

    while (flash_check_busy());
    flash_write_page((uint32_t)&program_data, FOTA_UPDATE_BANK_INFO_ADDRESS);
    while (flash_check_busy());
    leave_critical_section();

    ota_printf("bootinfo reset\n");
}

static void ota_check_have_sleep_child()
{
    ota_printf("ota_check_have_sleep_child \n");
    // wait ota done after reboot
    ota_bootinfo_ready();
    ota_change_state_and_timer(OTA_DONE, OTA_DONE_TIMEOUT);
}

static void ota_event_queue_push(uint8_t event, uint8_t *data, uint16_t data_lens)
{
    ota_event_data_t event_data;
    ota_printf("event push %u \r\n", event);
    event_data.event = event;
    memcpy(&event_data.data, data, data_lens);
    event_data.data_lens = data_lens;
    if (xQueueSend(ota_even_queue, (void *)&event_data, 0) == pdPASS)
    {
        OT_NOTIFY(OT_SYSTEM_EVENT_OTA_HANDLER);
    }
    else
    {
        ota_printf("event queue full \r\n");
    }
}

static int ota_data_parse(uint8_t type, uint8_t *payload, uint16_t payloadlength, void *data)
{
    ota_data_t *ota_data = NULL;
    ota_data_ack_t *ota_data_ack = NULL;
    ota_request_t *ota_request = NULL;
    ota_response_t *ota_response = NULL;
    uint16_t ota_data_lens = 0;
    uint32_t toatol_num = 0;

    uint8_t *tmp = payload;

    if (type == OTA_PAYLOAD_TYPE_DATA)
    {
        ota_data = (ota_data_t *)data;
        memcpy(&ota_data->version, tmp, 4);
        tmp += 4;
        memcpy(&ota_data->size, tmp, 4);
        tmp += 4;
        memcpy(&ota_data->crc, tmp, 4);
        tmp += 4;
        memcpy(&ota_data->seq, tmp, 2);
        tmp += 2;
        memcpy(&ota_data->segments, tmp, 2);
        tmp += 2;
        memcpy(&ota_data->intervel, tmp, 2);
        tmp += 2;
        ota_data->is_unicast = *tmp++;
        toatol_num = (ota_data->size / ota_data->segments);
        if (ota_data->size % ota_data->segments)
        {
            ++toatol_num;
        }
        if (ota_data->seq == (toatol_num - 1))
        {
            ota_data_lens = ota_data->size % ota_data->segments;
        }
        else
        {
            ota_data_lens = ota_data->segments;
        }

        memcpy(&ota_data->data, tmp, ota_data_lens);
        tmp += ota_data_lens;
    }
    else if (type == OTA_PAYLOAD_TYPE_DATA_ACK)
    {
        ota_data_ack = (ota_data_ack_t *)data;
        ota_data_ack->data_type = *tmp++;
        memcpy(&ota_data_ack->version, tmp, 4);
        tmp += 4;
        memcpy(&ota_data_ack->seq, tmp, 2);
        tmp += 2;
    }
    else if (type == OTA_PAYLOAD_TYPE_REQUEST)
    {
        ota_request = (ota_request_t *)data;
        memcpy(&ota_request->version, tmp, 4);
        tmp += 4;
        memcpy(&ota_request->size, tmp, 4);
        tmp += 4;
        memcpy(&ota_request->segments, tmp, 2);
        tmp += 2;
        memcpy(&ota_request->req_table, tmp, (OTA_REQUEST_TABLE_SIZE * 2));
        tmp += (OTA_REQUEST_TABLE_SIZE * 2);
    }
    else if (type == OTA_PAYLOAD_TYPE_RESPONSE)
    {
        ota_response = (ota_response_t *)data;
        memcpy(&ota_response->version, tmp, 4);
        tmp += 4;
        memcpy(&ota_response->size, tmp, 4);
        tmp += 4;
        memcpy(&ota_response->crc, tmp, 4);
        tmp += 4;
        memcpy(&ota_response->seq, tmp, 2);
        tmp += 2;
        memcpy(&ota_response->segments, tmp, 2);
        tmp += 2;
        toatol_num = (ota_response->size / ota_response->segments);
        if (ota_response->size % ota_response->segments)
        {
            ++toatol_num;
        }
        if (ota_response->seq == (toatol_num - 1))
        {
            ota_data_lens = ota_response->size % ota_response->segments;
        }
        else
        {
            ota_data_lens = ota_response->segments;
        }

        memcpy(&ota_response->data, tmp, ota_data_lens);
        tmp += ota_data_lens;
    }
    else
    {
        ota_printf("unknow parse type %u \n", type);
    }
    if ((tmp - payload) != payloadlength)
    {
        ota_printf("parse fail %u (%u/%u)\n", type, (tmp - payload), payloadlength);
        return 1;
    }
    return 0;
}

static void ota_data_piece(uint8_t type, uint8_t *payload, uint16_t *payloadlength, void *data)
{
    ota_data_t *ota_data = NULL;
    ota_data_ack_t *ota_data_ack = NULL;
    ota_request_t *ota_request = NULL;
    ota_response_t *ota_response = NULL;
    uint16_t ota_data_lens = 0;
    uint32_t toatol_num = 0;

    uint8_t *tmp = payload;

    if (type == OTA_PAYLOAD_TYPE_DATA)
    {
        ota_data = (ota_data_t *)data;
        memcpy(tmp, &ota_data->version, 4);
        tmp += 4;
        memcpy(tmp, &ota_data->size, 4);
        tmp += 4;
        memcpy(tmp, &ota_data->crc, 4);
        tmp += 4;
        memcpy(tmp, &ota_data->seq, 2);
        tmp += 2;
        memcpy(tmp, &ota_data->segments, 2);
        tmp += 2;
        memcpy(tmp, &ota_data->intervel, 2);
        tmp += 2;
        *tmp++ = ota_data->is_unicast;
        toatol_num = (ota_data->size / ota_data->segments);
        if (ota_data->size % ota_data->segments)
        {
            ++toatol_num;
        }
        if (ota_data->seq == (toatol_num - 1))
        {
            ota_data_lens = ota_data->size % ota_data->segments;
        }
        else
        {
            ota_data_lens = ota_data->segments;
        }

        memcpy(tmp, &ota_data->data, ota_data_lens);
        tmp += ota_data_lens;
    }
    else if (type == OTA_PAYLOAD_TYPE_DATA_ACK)
    {
        ota_data_ack = (ota_data_ack_t *)data;
        *tmp++ = ota_data_ack->data_type;
        memcpy(tmp, &ota_data_ack->version, 4);
        tmp += 4;
        memcpy(tmp, &ota_data_ack->seq, 2);
        tmp += 2;
    }
    else if (type == OTA_PAYLOAD_TYPE_REQUEST)
    {
        ota_request = (ota_request_t *)data;
        memcpy(tmp, &ota_request->version, 4);
        tmp += 4;
        memcpy(tmp, &ota_request->size, 4);
        tmp += 4;
        memcpy(tmp, &ota_request->segments, 2);
        tmp += 2;
        memcpy(tmp, &ota_request->req_table, (OTA_REQUEST_TABLE_SIZE * 2));
        tmp += (OTA_REQUEST_TABLE_SIZE * 2);
    }
    else if (type == OTA_PAYLOAD_TYPE_RESPONSE)
    {
        ota_response = (ota_response_t *)data;
        memcpy(tmp, &ota_response->version, 4);
        tmp += 4;
        memcpy(tmp, &ota_response->size, 4);
        tmp += 4;
        memcpy(tmp, &ota_response->crc, 4);
        tmp += 4;
        memcpy(tmp, &ota_response->seq, 2);
        tmp += 2;
        memcpy(tmp, &ota_response->segments, 2);
        tmp += 2;
        toatol_num = (ota_response->size / ota_response->segments);
        if (ota_response->size % ota_response->segments)
        {
            ++toatol_num;
        }
        if (ota_response->seq == (toatol_num - 1))
        {
            ota_data_lens = ota_response->size % ota_response->segments;
        }
        else
        {
            ota_data_lens = ota_response->segments;
        }

        memcpy(tmp, &ota_response->data, ota_data_lens);
        tmp += ota_data_lens;
    }
    else
    {
        ota_printf("unknow piece type %u \n", type);
    }
    *payloadlength = (tmp - payload);
}

/*coap proccess*/
static void ota_coap_data_proccess(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo)
{
    char string[OT_IP6_ADDRESS_STRING_SIZE];
    uint8_t  *buf = NULL;
    uint16_t length, payloadlength = 0;
    otMessage *responseMessage = NULL;
    otCoapCode responseCode = OT_COAP_CODE_EMPTY;
    ota_data_t ota_data;
    ota_data_ack_t ota_data_ack;
    otError       error   = OT_ERROR_NONE;
    uint8_t *payload = NULL;

    otIp6AddressToString(&aMessageInfo->mPeerAddr, string, sizeof(string));
    length = otMessageGetLength(aMessage) - otMessageGetOffset(aMessage);
    do
    {
        otInstance *instance = otrGetInstance();
        if (instance && length > 0)
        {
            buf = pvPortMalloc(length);
            if (NULL != buf)
            {
                otMessageRead(aMessage, otMessageGetOffset(aMessage), buf, length);
                ota_event_queue_push(OTA_DATA_RECEIVE_EVENT, buf, length);
                if (otCoapMessageGetType(aMessage) == OT_COAP_TYPE_CONFIRMABLE)
                {
                    if (ota_data_parse(OTA_PAYLOAD_TYPE_DATA, buf, length, &ota_data))
                    {
                        break;
                    }
                    /*do ack packet*/
                    responseCode = OT_COAP_CODE_VALID;

                    responseMessage = otCoapNewMessage(instance, NULL);
                    if (responseMessage == NULL)
                    {
                        error = OT_ERROR_NO_BUFS;
                        break;
                    }
                    error = otCoapMessageInitResponse(responseMessage, aMessage, OT_COAP_TYPE_ACKNOWLEDGMENT, responseCode);
                    if (error != OT_ERROR_NONE)
                    {
                        break;
                    }
                    ota_data_ack.data_type =  OTA_PAYLOAD_TYPE_DATA_ACK;
                    ota_data_ack.version = ota_data.version;
                    ota_data_ack.seq = ota_data.seq;
                    payload = pvPortMalloc(sizeof(ota_data_ack_t));
                    if (payload)
                    {
                        ota_data_piece(OTA_PAYLOAD_TYPE_DATA_ACK, payload, &payloadlength, &ota_data_ack);
                        error = otCoapMessageSetPayloadMarker(responseMessage);
                        if (error != OT_ERROR_NONE)
                        {
                            break;
                        }
                        error = otMessageAppend(responseMessage, payload, payloadlength);
                        if (error != OT_ERROR_NONE)
                        {
                            break;
                        }
                    }
                    error = otCoapSendResponseWithParameters(instance, responseMessage, aMessageInfo, NULL);
                    if (error != OT_ERROR_NONE)
                    {
                        break;
                    }
                }
            }
        }
    } while (0);
    if (buf)
    {
        vPortFree(buf);
    }
    if (payload)
    {
        vPortFree(payload);
    }
    if (error != OT_ERROR_NONE && responseMessage != NULL)
    {
        otMessageFree(responseMessage);
    }
}

static void ota_coap_request_proccess(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo)
{
    char string[OT_IP6_ADDRESS_STRING_SIZE];
    uint8_t  *buf = NULL;
    uint16_t length;
    otIp6AddressToString(&aMessageInfo->mPeerAddr, string, sizeof(string));
    length = otMessageGetLength(aMessage) - otMessageGetOffset(aMessage);
    do
    {
        if (length > 0)
        {
            buf = pvPortMalloc(length);
            if (NULL != buf)
            {
                otMessageRead(aMessage, otMessageGetOffset(aMessage), buf, length);
                ota_event_queue_push(OTA_REQUEST_RECEIVE_EVENT, buf, length);
            }
        }
    } while (0);

    if (buf)
    {
        vPortFree(buf);
    }
}

static void ota_coap_response_proccess(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo)
{
    char string[OT_IP6_ADDRESS_STRING_SIZE];
    uint8_t  *buf = NULL;
    uint16_t length;
    otIp6AddressToString(&aMessageInfo->mPeerAddr, string, sizeof(string));
    length = otMessageGetLength(aMessage) - otMessageGetOffset(aMessage);
    do
    {
        if (length > 0)
        {
            buf = pvPortMalloc(length);
            if (NULL != buf)
            {
                otMessageRead(aMessage, otMessageGetOffset(aMessage), buf, length);
                ota_event_queue_push(OTA_RESPONSE_RECEIVE_EVENT, buf, length);
            }
        }
    } while (0);

    if (buf)
    {
        vPortFree(buf);
    }
}

static void ota_coap_report_proccess(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo)
{
    char string[OT_IP6_ADDRESS_STRING_SIZE];
    uint8_t  buf[16];
    uint16_t bytesToPrint;
    uint16_t bytesPrinted = 0;
    uint16_t length;
    char UriPath[32];
    otIp6AddressToString(&aMessageInfo->mPeerAddr, string, sizeof(string));
    length = otMessageGetLength(aMessage) - otMessageGetOffset(aMessage);
    ota_printf("%d bytes from \n", length);
    ota_printf("ip : %s\n", string);
    ota_printf("port : %d \n", aMessageInfo->mSockPort);
    ota_printf("code : %d \n", otCoapMessageGetCode(aMessage));
    ota_printf("type : %d \n", otCoapMessageGetType(aMessage));

    if (length > 0)
    {
        ota_printf(" with payload: ");

        while (length > 0)
        {
            bytesToPrint = (length < sizeof(buf)) ? length : sizeof(buf);
            otMessageRead(aMessage, otMessageGetOffset(aMessage) + bytesPrinted, buf, bytesToPrint);

            for (uint16_t i = 0; i < bytesToPrint; i++)
            {
                ota_printf("%02x", buf[i]);
            }
            ota_printf("\n");
            length -= bytesToPrint;
            bytesPrinted += bytesToPrint;
        }
    }
}
static void ota_coap_ack_process(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo, otError aResult)
{
    char string[OT_IP6_ADDRESS_STRING_SIZE];
    uint8_t  *buf = NULL;
    uint16_t length;
    ota_data_ack_t ota_data_ack;
    otIp6AddressToString(&aMessageInfo->mPeerAddr, string, sizeof(string));
    length = otMessageGetLength(aMessage) - otMessageGetOffset(aMessage);
    do
    {
        if (length > 0)
        {
            buf = pvPortMalloc(length);
            if (NULL != buf)
            {
                otMessageRead(aMessage, otMessageGetOffset(aMessage), buf, length);
                if (buf[0] == OTA_PAYLOAD_TYPE_DATA_ACK)
                {
                    if (ota_data_parse(OTA_PAYLOAD_TYPE_DATA_ACK, buf, length, &ota_data_ack))
                    {
                        break;
                    }
                    if (ota_data_ack.version != ota_get_image_version())
                    {
                        ota_printf("ota_data_ack version %x %x\n", ota_data_ack.version, ota_get_image_version());
                        break;
                    }
                    if (ota_data_ack.seq == g_ota_start_index)
                    {
                        have_data_ack = true;
                        ota_change_state_and_timer(OTA_DATA_SENDING, 1);
                    }
                }
            }
        }
    } while (0);

    if (buf)
    {
        vPortFree(buf);
    }
}

otError ota_coap_request(otCoapCode aCoapCode, otIp6Address coapDestinationIp, otCoapType coapType, uint8_t *payload, uint16_t payloadLength, const char *coap_Path)
{
    otError       error   = OT_ERROR_NONE;
    otMessage    *message = NULL;
    otMessageInfo messageInfo;

    // Default parameters

    do
    {
        otInstance *instance = otrGetInstance();
        if (instance)
        {
            message = otCoapNewMessage(instance, NULL);
            if (NULL == message)
            {
                error = OT_ERROR_NO_BUFS;
                break;
            }
            otCoapMessageInit(message, coapType, aCoapCode);
            otCoapMessageGenerateToken(message, OT_COAP_DEFAULT_TOKEN_LENGTH);

            error = otCoapMessageAppendUriPathOptions(message, coap_Path);
            if (OT_ERROR_NONE != error)
            {
                break;
            }

            if (payloadLength > 0)
            {
                error = otCoapMessageSetPayloadMarker(message);
                if (OT_ERROR_NONE != error)
                {
                    break;
                }
            }

            // Embed content into message if given
            if (payloadLength > 0)
            {
                error = otMessageAppend(message, payload, payloadLength);
                if (OT_ERROR_NONE != error)
                {
                    break;
                }
            }

            memset(&messageInfo, 0, sizeof(messageInfo));
            messageInfo.mPeerAddr = coapDestinationIp;
            messageInfo.mPeerPort = OT_DEFAULT_COAP_PORT;

            if ((coapType == OT_COAP_TYPE_CONFIRMABLE) || (aCoapCode == OT_COAP_CODE_GET))
            {
                error = otCoapSendRequestWithParameters(instance, message, &messageInfo, &ota_coap_ack_process,
                                                        NULL, NULL);
            }
            else
            {
                error = otCoapSendRequestWithParameters(instance, message, &messageInfo, NULL, NULL, NULL);
            }
        }
    } while (0);

    if ((error != OT_ERROR_NONE) && (message != NULL))
    {
        ota_printf("ota coap send response error %d: %s \r\n", error, otThreadErrorToString(error));
        otMessageFree(message);
    }
    return error;
}

static void ota_data_send_handler()
{
    ota_data_t ota_data;
    uint8_t *payload = NULL;
    uint16_t payloadlength = 0, ota_data_lens = 0, i = 0;
    uint32_t *temp_addr = NULL;
    bool is_unicst = false;
    do
    {
        if (g_ota_toatol_num == 0)
        {
            ota_printf("g_ota_toatol_num 0\n");
            ota_change_state_and_timer(OTA_IDLE, 0);
            break;
        }
        if (ota_sender_addr.mFields.m8[0] != 0xff && ota_sender_addr.mFields.m8[1] != 0x03)
        {
            is_unicst = true;
        }
        if (g_ota_start_index < (g_ota_toatol_num - 1))
        {
            ota_data_lens = g_ota_segments_size;
        }
        else if (g_ota_start_index == (g_ota_toatol_num - 1))
        {
            ota_data_lens = (ota_get_image_size() % g_ota_segments_size);
        }
        else
        {
            if (is_unicst == true)
            {
                ota_change_state_and_timer(OTA_IDLE, 0);
            }
            else
            {
                ota_printf("\n============wait for ota request============\n");
                ota_change_state_and_timer(OTA_DONE, OTA_DONE_TIMEOUT);
            }
            break;
        }

        if (is_unicst == true)
        {
            if (have_data_ack == true)
            {
                ++g_ota_start_index;
            }
        }

        if (g_ota_start_index == g_ota_last_index)
        {
            ++g_ota_unicast_try_cnt;
            if (g_ota_unicast_try_cnt >= 10)
            {
                ota_change_state_and_timer(OTA_IDLE, 0);
                break;
            }
        }
        else
        {
            g_ota_last_index = g_ota_start_index;
            g_ota_unicast_try_cnt = 0;
        }

        ota_data.version = ota_get_image_version();
        ota_data.size = ota_get_image_size();
        ota_data.crc = ota_get_image_crc();
        ota_data.seq = g_ota_start_index;
        ota_data.segments = g_ota_segments_size;
        ota_data.intervel = g_ota_data_intervel;
        ota_data.is_unicast = is_unicst;
        enter_critical_section();
        temp_addr = (uint32_t *)(OTA_FLASH_START + (ota_data.seq * ota_data.segments));
        memcpy(&ota_data.data, temp_addr, ota_data_lens);
        leave_critical_section();

        payload = pvPortMalloc(sizeof(ota_data_t));
        if (payload)
        {
            memset(payload, 0x0, sizeof(ota_data_t));
            ota_data_piece(OTA_PAYLOAD_TYPE_DATA, payload, &payloadlength, &ota_data);
            ota_event_queue_push(OTA_DATA_SEND_EVENT, payload, payloadlength);
            ota_printf("\r [s] ota data: [%3d%%] [%u/%u]", ((ota_data.seq * 100) / (g_ota_toatol_num - 1)), ota_data.seq, (g_ota_toatol_num - 1));
            if (is_unicst == true)
            {
                have_data_ack = false;
            }
            else
            {
                g_ota_start_index++;
            }
        }
        ota_change_state_and_timer(OTA_DATA_SENDING, g_ota_data_intervel);
    } while (0);

    if (payload)
    {
        vPortFree(payload);
    }
    return;
}

static void ota_response_send_handler()
{
    uint8_t *payload = NULL;
    uint8_t random_index = 0;
    uint16_t resp_table_num = 0, i = 0;
    ota_response_t ota_response;
    uint16_t payloadlength = 0, ota_response_data_lens = 0;
    uint32_t *temp_addr = NULL;
    uint32_t toatol_num = (g_ota_image_size / g_ota_segments_size);
    if (g_ota_image_size % g_ota_segments_size)
    {
        ++toatol_num;
    }

    do
    {
        for (i = 0 ; i < OTA_RESPONSE_TABLE_SIZE ; i++)
        {
            if (g_resp_table[i] != 0xFFFF)
            {
                ++resp_table_num;
            }
        }
        if (resp_table_num == 0)
        {
            break;
        }
        if (resp_table_num > 1)
        {
            random_index = otRandomNonCryptoGetUint8InRange(1, resp_table_num);
        }
        else
        {
            random_index = 1;
        }
        resp_table_num = 0;

        for (i = 0 ; i < OTA_RESPONSE_TABLE_SIZE ; i++)
        {
            if (g_resp_table[i] != 0xFFFF)
            {
                ++resp_table_num;
                if (resp_table_num == random_index)
                {
                    random_index = i;
                    break;
                }
            }
        }
        if (i >= OTA_RESPONSE_TABLE_SIZE)
        {
            ota_printf("not find random index %u \n", random_index);
            break;
        }
        if (random_index >= OTA_RESPONSE_TABLE_SIZE)
        {
            ota_printf("random index %u is bit than %u \n", random_index, OTA_RESPONSE_TABLE_SIZE);
            break;
        }

        if (0 == ota_bitmap_get_bit(g_ota_bitmap, g_resp_table[random_index]))
        {
            ota_printf("doesn't have %u \n", g_resp_table[random_index]);
            break;
        }

        ota_response.version = g_ota_image_version;
        ota_response.size = g_ota_image_size;
        ota_response.seq = g_resp_table[random_index];
        ota_response.segments = g_ota_segments_size;
        ota_response.crc = g_ota_image_crc;
        if (ota_response.seq != (toatol_num - 1))
        {
            ota_response_data_lens = g_ota_segments_size;
        }
        else
        {
            ota_response_data_lens = g_ota_image_size % g_ota_segments_size;
        }
        enter_critical_section();
        temp_addr = (uint32_t *)(OTA_FLASH_START + (ota_response.seq * g_ota_segments_size));

        memcpy(&ota_response.data, temp_addr, ota_response_data_lens);
        leave_critical_section();

        payload = pvPortMalloc(sizeof(ota_response_t));
        if (payload)
        {
            memset(payload, 0x0, sizeof(ota_response_t));
            ota_data_piece(OTA_PAYLOAD_TYPE_RESPONSE, payload, &payloadlength, &ota_response);
            ota_event_queue_push(OTA_RESPONSE_SEND_EVENT, payload, payloadlength);
            ota_printf("[s] ota response %u %u %x \n", random_index, ota_response.seq, (uint32_t)temp_addr);
            g_resp_table[random_index] = 0xFFFF;
        }

    } while (0);

    if (payload)
    {
        vPortFree(payload);
    }

    resp_table_num = 0;
    for (i = 0 ; i < OTA_RESPONSE_TABLE_SIZE ; i++)
    {
        if (g_resp_table[i] != 0xFFFF)
        {
            ++resp_table_num;
        }
    }
    if (!xTimerIsTimerActive(ota_resp_timer) && resp_table_num > 0)
    {
        uint16_t timeout = otRandomNonCryptoGetUint16InRange(1, (OTA_RESPONESE_TIMEOUT));
        if (0 == timeout)
        {
            timeout = 1;
        }
        xTimerChangePeriod(ota_resp_timer, pdMS_TO_TICKS(timeout), 0);
        xTimerStart(ota_resp_timer, 0);
        g_ota_response_c = 0;
    }
}

static void ota_request_handler()
{
    ota_request_t ota_request;
    uint16_t i = 0, remain_index = 0, index = 0;
    uint8_t *payload = NULL;
    uint16_t payloadlength = 0;
    uint32_t timeout = 0, remain = 0, crc32 = 0, intervel = 0, req_index = 0;
    uint32_t toatol_num = (g_ota_image_size / g_ota_segments_size);
    if (g_ota_image_size % g_ota_segments_size)
    {
        ++toatol_num;
    }
    remain = ota_bitmap_get_remain(g_ota_bitmap, toatol_num);
    if (remain != 0)
    {
        do
        {
            if (g_ota_request_last_remain == remain)
            {
                ++g_ota_request_cnt;

                if (g_ota_request_cnt > OTA_REQUEST_TRY_MAX)
                {
                    ota_printf("ota_request fail \n");
                    ota_change_state_and_timer(OTA_IDLE, 0);
                    break;
                }
            }
            else
            {
                g_ota_request_cnt = 0;
                g_ota_request_last_remain = remain;
            }

            intervel = g_ota_data_intervel;
            if (intervel < 200)
            {
                intervel = 200;
            }
            timeout = intervel;
            if (remain > OTA_REQUEST_TABLE_SIZE)
            {
                timeout += otRandomNonCryptoGetUint32InRange(1, (OTA_REQUEST_TABLE_SIZE * OTA_RESPONESE_TIMEOUT));
            }
            else if (g_ota_request_cnt != 0)
            {
                timeout = OTA_REQUEST_TABLE_SIZE * OTA_RESPONESE_TIMEOUT;
            }
            else
            {
                timeout += otRandomNonCryptoGetUint32InRange(1, (remain * OTA_RESPONESE_TIMEOUT));
            }

            if (timeout == 0)
            {
                timeout = 1;
            }

            ota_request.version = g_ota_image_version;
            ota_request.size = g_ota_image_size;
            ota_request.segments = g_ota_segments_size;
            memset(ota_request.req_table, 0xff, sizeof(ota_request.req_table));

            req_index = otRandomNonCryptoGetUint32InRange(0, remain);
            ota_printf("[s] req [ ");
            for (i = 0 ; i < toatol_num; i++)
            {
                if (0 == ota_bitmap_get_bit(g_ota_bitmap, i))
                {
                    if (remain > OTA_REQUEST_TABLE_SIZE)
                    {
                        if ((remain - req_index) < OTA_REQUEST_TABLE_SIZE)
                        {
                            if (remain_index < (OTA_REQUEST_TABLE_SIZE - (remain - req_index - 1)) || (remain_index >= req_index))
                            {
                                ota_request.req_table[index] = i;
                                ota_printf("%u ", ota_request.req_table[index]);
                                index++;
                            }
                        }
                        else
                        {
                            if ((remain_index >= req_index))
                            {
                                ota_request.req_table[index] = i;
                                ota_printf("%u ", ota_request.req_table[index]);
                                index++;
                            }
                        }
                        remain_index++;
                    }
                    else
                    {
                        ota_request.req_table[index] = i;
                        ota_printf("%u ", ota_request.req_table[index]);
                        index++;
                    }

                    if (index > OTA_REQUEST_TABLE_SIZE)
                    {
                        break;
                    }
                }
            }
            ota_printf(" ] \r\n");
            payload = pvPortMalloc(sizeof(ota_request_t));
            if (payload)
            {
                memset(payload, 0x0, sizeof(ota_request_t));
                ota_data_piece(OTA_PAYLOAD_TYPE_REQUEST, payload, &payloadlength, &ota_request);
                ota_event_queue_push(OTA_REQUEST_SEND_EVENT, payload, payloadlength);
                ota_printf("[s] ota request rm %u try %u\n", remain, g_ota_request_cnt);
                ota_change_state_and_timer(OTA_REQUEST_SENDING, timeout);
            }
            else
            {
                ota_change_state_and_timer(OTA_REQUEST_SENDING, (OTA_REQUEST_TABLE_SIZE * OTA_RESPONESE_TIMEOUT));
                ota_printf("ota request alloc fail \n");
            }
        } while (0);
    }
    else
    {
        crc32 = crc32checksum((OTA_FLASH_START + 0x20), (g_ota_image_size - 0x20));
        if (crc32 != g_ota_image_crc)
        {
            ota_printf("ota request upgrade fail %X %X\n", crc32, g_ota_image_crc);
            ota_change_state_and_timer(OTA_IDLE, 0);
        }
        else
        {
            ota_check_have_sleep_child();
        }
    }

    if (payload)
    {
        vPortFree(payload);
    }
}

static void ota_response_table_handler(uint16_t *req_table)
{
    uint16_t timeout = 0, i = 0, j = 0;
    bool need_response = false;
    if (!xTimerIsTimerActive(ota_resp_timer))
    {
        memset(g_resp_table, 0xff, sizeof(g_resp_table));
    }
    enter_critical_section();
    for (i = 0 ; i < OTA_REQUEST_TABLE_SIZE ; i++)
    {
        if (req_table[i] != 0xFFFF)
        {
            if (ota_bitmap_get_bit(g_ota_bitmap, req_table[i]))
            {
                for (j = 0 ; j < OTA_RESPONSE_TABLE_SIZE ; j++)
                {
                    if (g_resp_table[j] == req_table[i])
                    {
                        break;
                    }
                }
                if (j >= OTA_RESPONSE_TABLE_SIZE)
                {
                    for (j = 0 ; j < OTA_RESPONSE_TABLE_SIZE ; j++)
                    {
                        if (g_resp_table[j] == 0xFFFF)
                        {
                            g_resp_table[j] = req_table[i];
                            break;
                        }
                    }
                }
            }
        }
    }
    for (j = 0 ; j < OTA_RESPONSE_TABLE_SIZE ; j++)
    {
        if (g_resp_table[j] != 0xFFFF)
        {
            need_response = true;
            break;
        }
    }
    leave_critical_section();
    if (need_response == true && !xTimerIsTimerActive(ota_resp_timer))
    {
        timeout = otRandomNonCryptoGetUint16InRange(1, (OTA_RESPONESE_TIMEOUT));
        if (0 == timeout)
        {
            timeout = 1;
        }
        xTimerChangePeriod(ota_resp_timer, pdMS_TO_TICKS(timeout), 0);
        xTimerStart(ota_resp_timer, 0);
        g_ota_response_c = 0;
    }
}

static void ota_request_start()
{
    uint32_t timeout = 0, remain = 0 ;
    uint32_t toatol_num = (g_ota_image_size / g_ota_segments_size);
    if (g_ota_image_size % g_ota_segments_size)
    {
        ++toatol_num;
    }
    remain = ota_bitmap_get_remain(g_ota_bitmap, toatol_num);
    if (remain > OTA_REQUEST_TABLE_SIZE)
    {
        remain = OTA_REQUEST_TABLE_SIZE;
    }
    timeout = otRandomNonCryptoGetUint32InRange(1, (remain * 2000));
    if (timeout == 0 )
    {
        timeout = 1;
    }
    ota_change_state_and_timer(OTA_REQUEST_SENDING, timeout);
}

static void ota_image_received_handler()
{
    uint32_t crc32 = 0, remain = 0;
    uint32_t toatol_num = (g_ota_image_size / g_ota_segments_size);

    if (g_ota_image_size % g_ota_segments_size)
    {
        ++toatol_num;
    }

    remain = ota_bitmap_get_remain(g_ota_bitmap, toatol_num);

    ota_printf("ota data remain %u (%3d%%) \n", remain, ((remain * 100) / (toatol_num - 1)));

    if (remain == 0)
    {
        crc32 = crc32checksum((OTA_FLASH_START + 0x20), (g_ota_image_size - 0x20));
        if (crc32 != g_ota_image_crc)
        {
            ota_printf("ota data upgrade fail \n");
            ota_change_state_and_timer(OTA_IDLE, 0);
            //restart ota request
        }
        //wait request packet
    }
    else
    {
        //do the ota request
        ota_request_start();
    }
}

static void ota_unicast_received_handler()
{
    uint32_t crc32 = 0, remain = 0;
    uint32_t toatol_num = (g_ota_image_size / g_ota_segments_size);

    if (g_ota_image_size % g_ota_segments_size)
    {
        ++toatol_num;
    }

    remain = ota_bitmap_get_remain(g_ota_bitmap, toatol_num);

    ota_printf("ota data remain %u (%3d%%) \n", remain, ((remain * 100) / (toatol_num - 1)));

    if (remain == 0)
    {
        crc32 = crc32checksum((OTA_FLASH_START + 0x20), (g_ota_image_size - 0x20));
        if (crc32 != g_ota_image_crc)
        {
            ota_printf("ota data upgrade fail \n");
            ota_change_state_and_timer(OTA_IDLE, 0);
            //restart ota request
        }
        //wait request packet
    }
    else
    {
        ota_change_state_and_timer(OTA_IDLE, 0);
    }
}

static void ota_response_timer_handler()
{
    ota_response_send_handler();
}

static void ota_timer_handler()
{
    ota_printf("state %s \n", OtaStateToString(g_ota_state));
    switch (g_ota_state)
    {
    case OTA_DATA_SENDING:
        ota_data_send_handler();
        break;
    case OTA_DATA_RECEIVING:
        ota_image_received_handler();
        break;
    case OTA_UNICASE_RECEIVING:
        ota_unicast_received_handler();
        break;
    case OTA_REQUEST_SENDING:
        ota_request_handler();
        break;
    case OTA_DONE:
        if (need_reboot == false)
        {
            need_reboot = true;
            ota_change_state_and_timer(OTA_IDLE, 0);
            return;
        }
        else
        {
            ota_change_state_and_timer(OTA_REBOOT, OTA_REBOOT_TIMEOUT);
        }
        break;
    case OTA_REBOOT:
        ota_reboot_handler();
        break;
    default:
        break;
    }
}

void ota_start(uint16_t segments_size, uint16_t intervel)
{
    otError error   = OT_ERROR_NONE;
    if (g_ota_state != OTA_IDLE)
    {
        printf("ota in progress %u \n", g_ota_state);
        return;
    }
    if (segments_size > OTA_SEGMENTS_MAX_SIZE)
    {
        printf("ota segments_size size can't big than 256 (%u) \n", segments_size);
        return;
    }
    // Initiator send parameter
    g_ota_segments_size = 255;
    g_ota_data_intervel = 1000;
    if (segments_size != 0)
    {
        g_ota_segments_size = segments_size;
    }
    if (intervel != 0)
    {
        g_ota_data_intervel = intervel;
    }

    g_ota_toatol_num = ota_get_image_size() / g_ota_segments_size;
    g_ota_start_index = 0;
    if (ota_get_image_size() % g_ota_segments_size)
    {
        ++g_ota_toatol_num;
    }
    // Initiator bitmap set all
    g_ota_bitmap = ota_bitmap_init(g_ota_toatol_num);
    for (uint32_t i = 0 ; i < g_ota_toatol_num; i++)
    {
        ota_bitmap_set(g_ota_bitmap, i);
    }

    ota_printf("ota_toatol_num %u \n", g_ota_toatol_num);
    uint32_t crc32 = crc32checksum((OTA_FLASH_START + 0x20), (ota_get_image_size() - 0x20));
    if (crc32 != ota_get_image_crc())
    {
        printf("crc fail %x %x \n", crc32, ota_get_image_crc());
        return;
    }
    else
    {
        ota_printf("crc %x %x \n", crc32, ota_get_image_crc());
    }
    char peer_addr[] = "ff03:0:0:0:0:0:0:2";
    error = otIp6AddressFromString(peer_addr, &ota_sender_addr);

    ota_change_state_and_timer(OTA_DATA_SENDING, g_ota_data_intervel);
    need_reboot = false;
}

void ota_send(char *ipaddr_str)
{
    otError error   = OT_ERROR_NONE;
    error = otIp6AddressFromString(ipaddr_str, &ota_sender_addr);
    if (OT_ERROR_NONE == error)
    {
        g_ota_segments_size = 255;
        g_ota_data_intervel = 3000;
        g_ota_toatol_num = ota_get_image_size() / g_ota_segments_size;
        g_ota_start_index = 0;
        if (ota_get_image_size() % g_ota_segments_size)
        {
            ++g_ota_toatol_num;
        }
        ota_printf("ota_toatol_num %u \n", g_ota_toatol_num);
        uint32_t crc32 = crc32checksum((OTA_FLASH_START + 0x20), (ota_get_image_size() - 0x20));
        if (crc32 != ota_get_image_crc())
        {
            printf("crc fail %x %x \n", crc32, ota_get_image_crc());
            return;
        }
        else
        {
            ota_printf("crc %x %x \n", crc32, ota_get_image_crc());
        }
        ota_change_state_and_timer(OTA_DATA_SENDING, g_ota_data_intervel);
        need_reboot = false;
    }
    else
    {
        printf("ip error(%u) %s \n", error, ipaddr_str);
    }
}

void ota_stop()
{
    ota_change_state_and_timer(OTA_IDLE, 0);
}

void ota_debug_level(unsigned int level)
{
    ota_debug_flags = level;
}

static void ota_data_sended_event_handler(uint8_t *data, uint16_t lens)
{
    otError error   = OT_ERROR_NONE;
    otCoapCode CoapCode = OT_COAP_CODE_POST;
    otIp6Address coapDestinationIp;
    otCoapType coapType;
    char peer_addr[] = "ff03:0:0:0:0:0:0:2";
    if (ota_sender_addr.mFields.m8[0] != 0xff && ota_sender_addr.mFields.m8[1] != 0x03)
    {
        coapDestinationIp = ota_sender_addr;
        coapType = OT_COAP_TYPE_CONFIRMABLE;
    }
    else
    {
        error = otIp6AddressFromString(peer_addr, &coapDestinationIp);
        coapType = OT_COAP_TYPE_NON_CONFIRMABLE;
    }
    uint8_t *payload = (uint8_t *) data;
    uint16_t payloadLength = lens;
    error = ota_coap_request(CoapCode, coapDestinationIp, coapType, payload, payloadLength, RAFAEL_OTA_URL_DATA);
}

static void ota_request_sended_event_handler(uint8_t *data, uint16_t lens)
{
    otError error   = OT_ERROR_NONE;
    otCoapCode CoapCode = OT_COAP_CODE_POST;
    otIp6Address coapDestinationIp;
    char peer_addr[] = "ff02:0:0:0:0:0:0:1";
    error = otIp6AddressFromString(peer_addr, &coapDestinationIp);
    otCoapType coapType = OT_COAP_TYPE_NON_CONFIRMABLE;
    uint8_t *payload = (uint8_t *) data;
    uint16_t payloadLength = lens;
    error = ota_coap_request(CoapCode, coapDestinationIp, coapType, payload, payloadLength, RAFAEL_OTA_URL_REQ);
}

static void ota_response_sended_event_handler(uint8_t *data, uint16_t lens)
{
    otError error   = OT_ERROR_NONE;
    otCoapCode CoapCode = OT_COAP_CODE_POST;
    otIp6Address coapDestinationIp;
    char peer_addr[] = "ff02:0:0:0:0:0:0:1";
    error = otIp6AddressFromString(peer_addr, &coapDestinationIp);
    otCoapType coapType = OT_COAP_TYPE_NON_CONFIRMABLE;
    uint8_t *payload = (uint8_t *) data;
    uint16_t payloadLength = lens;
    error = ota_coap_request(CoapCode, coapDestinationIp, coapType, payload, payloadLength, RAFAEL_OTA_URL_RESP);
}

static void ota_data_received_event_handler(uint8_t *data, uint16_t lens)
{
    ota_data_t ota_data;
    uint32_t i = 0;
    uint32_t toatol_num = 0, timeout = 0, ota_data_lens = 0, tmp_addr = 0, crc32 = 0;

    do
    {
        if (ota_data_parse(OTA_PAYLOAD_TYPE_DATA, data, lens, &ota_data))
        {
            break;
        }
        toatol_num = (ota_data.size / ota_data.segments);
        if (ota_data.size % ota_data.segments)
        {
            ++toatol_num;
        }

        if (ota_get_state() == OTA_IDLE && ota_get_image_version() == ota_data.version)
        {
            crc32 = crc32checksum((OTA_FLASH_START + 0x20), (ota_data.size - 0x20));
            if (crc32 == ota_get_image_crc())
            {
                // Initiator bitmap set all
                if (g_ota_bitmap)
                {
                    ota_bitmap_delete(g_ota_bitmap);
                    g_ota_bitmap = NULL;
                }
                g_ota_bitmap = ota_bitmap_init(toatol_num);
                for (i = 0 ; i < toatol_num; i++)
                {
                    ota_bitmap_set(g_ota_bitmap, i);
                }
                g_ota_toatol_num = toatol_num;
                g_ota_segments_size = ota_data.segments;
                ota_change_state_and_timer(OTA_DONE, OTA_DONE_TIMEOUT);
                need_reboot = false;
            }
        }

        if (OTA_IDLE != ota_get_state() &&
                0 != ota_get_image_version() &&
                ota_get_image_version() != ota_data.version)
        {
            ota_printf("different version %08X %08X \n", ota_data.version, ota_get_image_version());
            break;
        }

        if (ota_get_state() == OTA_DONE)
        {
            ota_change_state_and_timer(OTA_DONE, OTA_DONE_TIMEOUT);
            break;
        }

        timeout = 1 + (ota_data.intervel * 2 * (toatol_num - ota_data.seq));
        ota_data_lens = ota_data.segments;
        if (ota_data.seq == (toatol_num - 1))
        {
            ota_data_lens = ota_data.size % ota_data.segments;
        }

        if (NULL != g_ota_bitmap)
        {
            if (g_ota_state == OTA_IDLE)
            {
                ota_printf("ota data OTA_IDLE \r\n");
                break;
            }
            if (ota_bitmap_get_bit(g_ota_bitmap, ota_data.seq))
            {
                ota_printf("ota upgrade data same %u\n", ota_data.seq);
                break;
            }
        }
        else
        {
            if (ota_data.is_unicast == true && ota_data.seq != 0)
            {
                ota_printf("is not seq 0 \n");
                break;
            }
            g_ota_image_version = ota_data.version;
            g_ota_image_size = ota_data.size;
            g_ota_image_crc = ota_data.crc;
            g_ota_segments_size = ota_data.segments;
            g_ota_data_intervel = ota_data.intervel;
            ota_bootinfo_reset();
            g_ota_bitmap = ota_bitmap_init(toatol_num);

            if (ota_data.is_unicast == true)
            {
                ota_change_state_and_timer(OTA_UNICASE_RECEIVING, timeout);
            }
            else
            {
                ota_change_state_and_timer(OTA_DATA_RECEIVING, timeout);
            }
            enter_critical_section();
            for (i = 0; i < 0x57; i++)
            {
                // Page erase (4096 bytes)
                while (flash_check_busy());
                flash_erase(FLASH_ERASE_SECTOR, OTA_FLASH_START + (0x1000 * i));
                while (flash_check_busy());
            }
            leave_critical_section();
        }

        ota_printf("[R] ota data seq %u remain %u\n", ota_data.seq, ota_bitmap_get_remain(g_ota_bitmap, toatol_num));

        ota_bitmap_set(g_ota_bitmap, ota_data.seq);

        enter_critical_section();
        tmp_addr = OTA_FLASH_START + (ota_data.segments * ota_data.seq);
        for (i = 0; i < ota_data_lens ; i++)
        {
            while (flash_check_busy());
            flash_write_byte(tmp_addr + i, ota_data.data[i]);
            while (flash_check_busy());
        }
        leave_critical_section();

        if (0 == ota_bitmap_get_remain(g_ota_bitmap, toatol_num))
        {
            crc32 = crc32checksum((OTA_FLASH_START + 0x20), (ota_data.size - 0x20));
            if (crc32 != ota_data.crc)
            {
                ota_printf("ota data upgrade fail %X %X\n", crc32, ota_data.crc);
                ota_change_state_and_timer(OTA_IDLE, 0);
            }
            else
            {
                if (ota_data.is_unicast == true)
                {
                    ota_bootinfo_ready();
                    ota_change_state_and_timer(OTA_REBOOT, 1);
                }
                else
                {
                    ota_check_have_sleep_child();
                }
            }
            break;
        }
        else
        {
            if (ota_data.is_unicast == true)
            {
                ota_change_state_and_timer(OTA_UNICASE_RECEIVING, timeout);
            }
            else
            {
                ota_change_state_and_timer(OTA_DATA_RECEIVING, timeout);
            }
        }

    } while (0);
}

static void ota_request_received_event_handler(uint8_t *data, uint16_t lens)
{
    ota_request_t ota_request;
    uint16_t index = 0, req_num = 0;
    uint32_t crc32 = 0, toatol_num = 0, i = 0;
    do
    {
        if (ota_data_parse(OTA_PAYLOAD_TYPE_REQUEST, data, lens, &ota_request))
        {
            break;
        }

        toatol_num = (ota_request.size / ota_request.segments);
        if (ota_request.size % ota_request.segments)
        {
            ++toatol_num;
        }

        if (ota_get_state() == OTA_IDLE)
        {
            if (ota_get_image_version() == ota_request.version)
            {
                crc32 = crc32checksum((OTA_FLASH_START + 0x20), (ota_request.size - 0x20));
                if (crc32 == ota_get_image_crc())
                {
                    // Initiator bitmap set all
                    ota_printf("same version and idle \n");
                    if (g_ota_bitmap)
                    {
                        ota_bitmap_delete(g_ota_bitmap);
                        g_ota_bitmap = NULL;
                    }
                    g_ota_bitmap = ota_bitmap_init(toatol_num);
                    for (i = 0 ; i < toatol_num; i++)
                    {
                        ota_bitmap_set(g_ota_bitmap, i);
                    }
                    g_ota_toatol_num = toatol_num;
                    g_ota_segments_size = ota_request.segments;
                    ota_change_state_and_timer(OTA_DONE, OTA_DONE_TIMEOUT);
                    need_reboot = false;
                }
                else
                {
                    break;
                }
            }
            else
            {
                ota_printf("ota request OTA_IDLE\n");
                break;
            }
        }

        if (ota_request.segments != g_ota_segments_size)
        {
            ota_printf("ota request segments fail %u %u \n", ota_request.segments, g_ota_segments_size);
            break;
        }

        if (ota_request.version != g_ota_image_version)
        {
            ota_printf("ota request differnt version %x %x \n", ota_request.version, g_ota_image_version);
            break;
        }

        if (NULL == g_ota_bitmap)
        {
            ota_printf("ota request bitmap NULL\n");
            break;
        }
        //have other node not upgrade, need wait
        if (g_ota_state == OTA_DONE)
        {
            ota_change_state_and_timer(OTA_DONE, OTA_DONE_TIMEOUT);
        }
        ota_printf("[R] res seq : ");
        for (index = 0; index < OTA_REQUEST_TABLE_SIZE; index++)
        {
            if (ota_request.req_table[index] == 0xFFFF)
            {
                break;
            }
            ota_printf("%u ", ota_request.req_table[index]);
            ++req_num;
        }
        ota_printf("\n");
        if (req_num > 0)
        {
            ota_response_table_handler(ota_request.req_table);
        }
    } while (0);
}

static void ota_response_received_event_handler(uint8_t *data, uint16_t lens)
{
    ota_response_t ota_response;
    uint16_t i = 0, ota_data_lens = 0;
    uint32_t toatol_num = 0, tmp_addr = 0, crc32 = 0;
    do
    {
        if (ota_data_parse(OTA_PAYLOAD_TYPE_RESPONSE, data, lens, &ota_response))
        {
            break;
        }
        toatol_num = ota_response.size / ota_response.segments;

        if (ota_response.size % ota_response.segments)
        {
            ++toatol_num;
        }

        if (g_ota_state == OTA_IDLE)
        {
            ota_printf("ota response %s\n", OtaStateToString(g_ota_state));
            if (ota_get_image_version() == ota_response.version)
            {
                crc32 = crc32checksum((OTA_FLASH_START + 0x20), (ota_response.size - 0x20));
                if (crc32 == ota_get_image_crc())
                {
                    // Initiator bitmap set all
                    ota_printf("response same version and idle \n");
                    if (g_ota_bitmap)
                    {
                        ota_bitmap_delete(g_ota_bitmap);
                        g_ota_bitmap = NULL;
                    }
                    g_ota_bitmap = ota_bitmap_init(toatol_num);
                    for (i = 0 ; i < toatol_num; i++)
                    {
                        ota_bitmap_set(g_ota_bitmap, i);
                    }
                    g_ota_toatol_num = toatol_num;
                    g_ota_segments_size = ota_response.segments;
                    ota_change_state_and_timer(OTA_DONE, OTA_DONE_TIMEOUT);
                    need_reboot = false;
                }
                else
                {
                    ota_printf("crc fail %x %x \n", crc32, ota_get_image_crc());
                    if (g_ota_bitmap)
                    {
                        ota_bitmap_delete(g_ota_bitmap);
                        g_ota_bitmap = NULL;
                    }
                    g_ota_bitmap = ota_bitmap_init(toatol_num);
                    g_ota_toatol_num = toatol_num;
                    g_ota_segments_size = ota_response.segments;
                    ota_bootinfo_reset();
                    enter_critical_section();
                    for (i = 0; i < 0x57; i++)
                    {
                        // Page erase (4096 bytes)
                        while (flash_check_busy());
                        flash_erase(FLASH_ERASE_SECTOR, OTA_FLASH_START + (0x1000 * i));
                        while (flash_check_busy());
                    }
                    leave_critical_section();
                    ota_change_state_and_timer(OTA_REQUEST_SENDING, (OTA_REQUEST_TABLE_SIZE * OTA_RESPONESE_TIMEOUT));
                    break;
                }
            }
            else
            {
                break;
            }
        }

        if (ota_response.segments != g_ota_segments_size)
        {
            ota_printf("ota response segments fail %u %u \n", ota_response.segments, g_ota_segments_size);
            break;
        }

        if (NULL == g_ota_bitmap)
        {
            ota_printf("ota response bitmap NULL\n");
            break;
        }

        if (ota_response.version != g_ota_image_version)
        {
            ota_printf("ota response differnt version %x %x \n", ota_response.version, g_ota_image_version);
            break;
        }
        //have other node not upgrade, need wait
        if (g_ota_state == OTA_DONE)
        {
            ota_change_state_and_timer(OTA_DONE, OTA_DONE_TIMEOUT);
        }
        enter_critical_section();
        for (i = 0 ; i < OTA_RESPONSE_TABLE_SIZE ; i++)
        {
            if (g_resp_table[i] == ota_response.seq)
            {
                if (xTimerIsTimerActive(ota_resp_timer))
                {
                    if (++g_ota_response_c >= g_ota_response_k)
                    {
                        g_ota_response_c = 0;
                        xTimerStop(ota_resp_timer, 0);
                    }
                }
                g_resp_table[i] = 0xFFFF;
                break;
            }
        }
        g_ota_request_cnt = 0;
        leave_critical_section();
        if (ota_bitmap_get_bit(g_ota_bitmap, ota_response.seq))
        {
            // ota_printf("ota response seq same %u\n",ota_response_header->seq);
            break;
        }
        else
        {
            ota_data_lens = ota_response.segments;
            if (ota_response.seq == (toatol_num - 1))
            {
                ota_data_lens = ota_response.size % ota_response.segments;
            }

            ota_bitmap_set(g_ota_bitmap, ota_response.seq);
            ota_printf("[R] ota response %u remain %u\n", ota_response.seq, ota_bitmap_get_remain(g_ota_bitmap, toatol_num));

            enter_critical_section();
            tmp_addr = OTA_FLASH_START + (ota_response.segments * ota_response.seq);
            // ota_bitmap_print(ota_bitmap,toatol_num);

            for (i = 0; i < ota_data_lens ; i++)
            {
                while (flash_check_busy());
                flash_write_byte(tmp_addr + i, ota_response.data[i]);
                while (flash_check_busy());
            }
            leave_critical_section();
            if (0 == ota_bitmap_get_remain(g_ota_bitmap, toatol_num))
            {
                crc32 = crc32checksum((OTA_FLASH_START + 0x20), (ota_response.size - 0x20));
                if (crc32 != ota_response.crc)
                {
                    ota_printf("ota response upgrade fail %X %X\n", crc32, ota_response.crc);
                    ota_change_state_and_timer(OTA_IDLE, 0);
                }
                else
                {
                    ota_check_have_sleep_child();
                }
                break;
            }
        }
    } while (0);
}

void ota_event_handler(ot_system_event_t sevent)
{
    ota_event_data_t event_data;
    memset(&event_data, 0x0, sizeof(ota_event_data_t));
    /*process ota event*/
    if (sevent & OT_SYSTEM_EVENT_RADIO_RX_DONE)
    {
        if (xQueueReceive(ota_even_queue, (void *)&event_data, 0) == pdPASS)
        {
            ota_printf("data event %u \r\n", event_data.event);
            switch (event_data.event)
            {
            case OTA_DATA_SEND_EVENT:
                ota_data_sended_event_handler(event_data.data, event_data.data_lens);
                break;
            case OTA_REQUEST_SEND_EVENT:
                ota_request_sended_event_handler(event_data.data, event_data.data_lens);
                break;
            case OTA_RESPONSE_SEND_EVENT:
                ota_response_sended_event_handler(event_data.data, event_data.data_lens);
                break;
            case OTA_DATA_RECEIVE_EVENT:
                ota_data_received_event_handler(event_data.data, event_data.data_lens);
                break;
            case OTA_REQUEST_RECEIVE_EVENT:
                ota_request_received_event_handler(event_data.data, event_data.data_lens);
                break;
            case OTA_RESPONSE_RECEIVE_EVENT:
                ota_response_received_event_handler(event_data.data, event_data.data_lens);
                break;
            default:
                ota_printf("unknow event %u\n", event_data.event);
                break;
            }
            ota_printf("data event %u end\r\n", event_data.event);
        }
    }
}

otError ota_init(otInstance *aInstance)
{
    otError error = OT_ERROR_NONE;
    BaseType_t xReturned;
    do
    {
        error = otCoapStart(aInstance, OT_DEFAULT_COAP_PORT);
        if (error != OT_ERROR_NONE)
        {
            break;
        }

        memset(&ota_data_resource, 0, sizeof(ota_data_resource));
        memset(&ota_req_resource, 0, sizeof(ota_req_resource));
        memset(&ota_resp_resource, 0, sizeof(ota_resp_resource));
        memset(&ota_report_resource, 0, sizeof(ota_report_resource));

        ota_data_resource.mUriPath = RAFAEL_OTA_URL_DATA;
        ota_data_resource.mContext = aInstance;
        ota_data_resource.mHandler = &ota_coap_data_proccess;
        ota_data_resource.mNext = NULL;

        ota_req_resource.mUriPath = RAFAEL_OTA_URL_REQ;
        ota_req_resource.mContext = aInstance;
        ota_req_resource.mHandler = &ota_coap_request_proccess;
        ota_req_resource.mNext = NULL;

        ota_resp_resource.mUriPath = RAFAEL_OTA_URL_RESP;
        ota_resp_resource.mContext = aInstance;
        ota_resp_resource.mHandler = &ota_coap_response_proccess;
        ota_resp_resource.mNext = NULL;

        ota_report_resource.mUriPath = RAFAEL_OTA_URL_REPORT;
        ota_report_resource.mContext = aInstance;
        ota_report_resource.mHandler = &ota_coap_report_proccess;
        ota_report_resource.mNext = NULL;

        otCoapAddResource(aInstance, &ota_data_resource);
        otCoapAddResource(aInstance, &ota_req_resource);
        otCoapAddResource(aInstance, &ota_resp_resource);
        otCoapAddResource(aInstance, &ota_report_resource);

        if (NULL == ota_timer)
        {
            ota_timer = xTimerCreate("ota_timer_t",
                                     portMAX_DELAY,
                                     false,
                                     NULL,
                                     ota_timer_handler);
        }
        else
        {
            ota_printf("ota_timer exist\n");
        }

        if (NULL == ota_resp_timer)
        {
            ota_resp_timer = xTimerCreate("ota_resp_timer",
                                          portMAX_DELAY,
                                          false,
                                          NULL,
                                          ota_response_timer_handler);
        }
        else
        {
            ota_printf("ota_resp_timer exist\n");
        }
        char peer_addr[] = "ff03:0:0:0:0:0:0:2";
        error = otIp6AddressFromString(peer_addr, &ota_sender_addr);

        /* Init rx done queue*/
        ota_even_queue = xQueueCreate(5, sizeof(ota_event_data_t));

    } while (0);

    return error;
}

static int _cli_cmd_ota(int argc, char **argv, cb_shell_out_t log_out, void *pExtra)
{
    if (argc > 2)
    {
        if (!strcmp(argv[1], "debug"))
        {
            if (utility_strtoul(argv[2], 0) == 0)
            {
                ota_debug_level(0);
            }
            else
            {
                ota_debug_level(1);
            }
        }
    }
    else
    {
        printf("ota state : %s \n", OtaStateToString(ota_get_state()));
        if (ota_get_state() != OTA_IDLE)
        {
            uint32_t toatol_num = (g_ota_image_size / g_ota_segments_size);
            if (g_ota_image_size % g_ota_segments_size)
            {
                ++toatol_num;
            }
            printf("ota remain : %u \r\n", ota_bitmap_get_remain(g_ota_bitmap, toatol_num));
        }
        printf("ota image version : 0x%08x\n", ota_get_image_version());
        printf("ota image size : 0x%08x \n", ota_get_image_size());
        printf("ota image crc : 0x%08x \n", ota_get_image_crc());
    }
    return 0;
}

const sh_cmd_t g_cli_cmd_ota STATIC_CLI_CMD_ATTRIBUTE =
{
    .pCmd_name    = "ota",
    .pDescription = "ota <debug> <0 or 1>",
    .cmd_exec     = _cli_cmd_ota,
};
