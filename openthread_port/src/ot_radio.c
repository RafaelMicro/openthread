/**
 * @file ot_radio.c
 * @author Rex Huang (rex.huang@rafaelmicro.com)
 * @brief 
 * @version 0.1
 * @date 2023-07-26
 * 
 * @copyright Copyright (c) 2023
 * 
 */
//=============================================================================
//                Include
//=============================================================================
#include "string.h"
// #include <openthread-system.h>
#include <assert.h>
#include <openthread/config.h>
#include <openthread/link.h>
#include <openthread/platform/alarm-micro.h>
#include <openthread/platform/alarm-milli.h>
#include <openthread/platform/diag.h>
#include <openthread/platform/radio.h>
#include <openthread/platform/time.h>
#include <openthread_port.h>

#include "code_utils.h"
#include "common/logging.hpp"
#include "mac_frame.h"

#include "lmac15p4.h"
#include "soft_source_match_table.h"
#include "util_list.h"
#include "util_string.h"
#include "cli.h"
#include "log.h"
#include "lpm.h"
#include "flashctl.h"
//=============================================================================
//                Private Definitions of const value
//=============================================================================
#define CCA_THRESHOLD_UNINIT (127)
#define CCA_THRESHOLD_DEFAULT (85) // dBm  - default for 2.4GHz 802.15.4

#define RAFAEL_RECEIVE_SENSITIVITY (101)

#define RX_CONTROL_FIELD_LENGTH (7)
#define RX_STATUS_LENGTH        (5)
#define PHR_LENGTH              (1)
#define CRC16_LENGTH            (2)
#define RX_HEADER_LENGTH        (RX_CONTROL_FIELD_LENGTH + PHR_LENGTH)
#define RX_APPEND_LENGTH        (RX_STATUS_LENGTH + CRC16_LENGTH)
#define RX_LENGTH               (MAX_RF_LEN + RX_HEADER_LENGTH + RX_APPEND_LENGTH)
#define FCF_LENGTH              (2)

#define PHY_PIB_TURNAROUND_TIMER    192
#define PHY_PIB_CCA_DETECTED_TIME   128 // 8 symbols
#define PHY_PIB_CCA_DETECT_MODE     0
#define PHY_PIB_CCA_THRESHOLD       CCA_THRESHOLD_DEFAULT
#define MAC_PIB_UNIT_BACKOFF_PERIOD 320
#define MAC_PIB_MAC_ACK_WAIT_DURATION                                          \
    544 // non-beacon mode; 864 for beacon mode
#define MAC_PIB_MAC_MAX_BE                    8
#define MAC_PIB_MAC_MAX_FRAME_TOTAL_WAIT_TIME 16416
#define MAC_PIB_MAC_MAX_FRAME_RETRIES         4
#define MAC_PIB_MAC_MAX_CSMACA_BACKOFFS       10
#define MAC_PIB_MAC_MIN_BE                    5


#define MAC_RX_BUFFERS 100
#define FREQ (2405)

extern uint8_t rfb_port_ack_packet_read(uint8_t* rx_data_address);
static bool hasFramePending(const otRadioFrame* aFrame);
//=============================================================================
//                Private ENUM
//=============================================================================
enum {
    kMinChannel = 11,
    kMaxChannel = 26,
};

enum {
    IEEE802154_MIN_LENGTH = 5,
    IEEE802154_MAX_LENGTH = 2047,
    IEEE802154_ACK_LENGTH = 5,
    IEEE802154_FRAME_TYPE_MASK = 0x7,
    IEEE802154_FRAME_TYPE_COMMAND = 0x3,
    IEEE802154_FRAME_TYPE_ACK = 0x2,
    IEEE802154_FRAME_PENDING = 1 << 4,
    IEEE802154_ACK_REQUEST = 1 << 5,
    IEEE802154_DSN_OFFSET = 2,
};

#define OTRADIO_MAC_HEADER_ACK_REQUEST_MASK (1 << 5)
#define OTRADIO_MAX_PSDU                    152
#define OTRADIO_RX_FRAME_BUFFER_NUM         8

typedef struct _otRadio_rxFrame_t {
    utils_dlist_t dlist;
    otRadioFrame frame;
} otRadio_rxFrame_t;

#define ALIGNED_RX_FRAME_SIZE ((sizeof(otRadio_rxFrame_t) + 3) & 0xfffffffc)
#define TOTAL_RX_FRAME_SIZE   (ALIGNED_RX_FRAME_SIZE + OTRADIO_MAX_PSDU)

//=============================================================================
//                Private Struct
//=============================================================================
typedef struct _otRadio_t {
    otInstance* aInstance;
    utils_dlist_t rxFrameList;
    utils_dlist_t frameList;
    otRadioFrame* pTxFrame;
    otRadioFrame* pAckFrame;
    uint32_t isCoexEnabled;

    uint64_t tstx;
    uint64_t tsIsr;

    uint32_t dbgRxFrameNum;
    uint32_t dbgFrameNum;
    uint32_t dbgMaxAckFrameLenth;
    uint32_t dbgMaxPendingFrameNum;

    uint8_t buffPool[TOTAL_RX_FRAME_SIZE * (OTRADIO_RX_FRAME_BUFFER_NUM + 2)];
} otRadio_t;

static otRadio_t otRadio_var;
//=============================================================================
//                Private Global Variables
//=============================================================================
static bool sIsSrcMatchEnabled = false;
static int8_t sCcaThresholdDbm = CCA_THRESHOLD_DEFAULT;
static otExtAddress sExtAddress;

static uint8_t sIEEE_EUI64Addr[OT_EXT_ADDRESS_SIZE] = {0xAA, 0x02, 0x03, 0x04,
                                                       0x05, 0x06, 0x07, 0x08};

static uint16_t sTurnaroundTime = PHY_PIB_TURNAROUND_TIMER;
static uint8_t sCCAMode = PHY_PIB_CCA_DETECT_MODE;
static uint8_t sCCAThreshold = PHY_PIB_CCA_THRESHOLD;
static uint16_t sCCADuration = PHY_PIB_CCA_DETECTED_TIME;


// static uint8_t sPhyTxPower = TX_POWER_20dBm;
// static uint8_t sPhyModulation = MOD_1;
static uint8_t sPromiscuous = false;
static uint16_t sShortAddress = 0xFFFF;
static uint32_t sExtendAddr_0 = 0x01020304;
static uint32_t sExtendAddr_1 = 0x05060709;
static uint16_t sPANID = 0xFFFF;
static uint8_t sCoordinator = 0;
static uint8_t sCurrentChannel = kMinChannel;
static otRadioState sState = OT_RADIO_STATE_DISABLED;

// static queue_t rf_rx_queue;

static uint32_t sMacFrameCounter;
#if OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2

static uint8_t sKeyId;
static otMacKeyMaterial sPrevKey;
static otMacKeyMaterial sCurrKey;
static otMacKeyMaterial sNextKey;
static otRadioKeyType sKeyType;
#endif

#if OPENTHREAD_CONFIG_MAC_CSL_RECEIVER_ENABLE
static uint32_t sCslSampleTime;
static uint32_t sCslPeriod;
#endif

static bool sAuto_State_Set = false;
static uint8_t sMacAddrReadMode = 1;

//=============================================================================
//                Functions
//=============================================================================
static uint64_t longtime_to_longlong_time(uint32_t* prev32Time,
                                          uint32_t now32Time,
                                          uint32_t* timerWraps) {
    if (now32Time < *prev32Time) {
        *timerWraps += 1U;
    }
    *prev32Time = now32Time;

    return ((uint64_t)*timerWraps << 32) + now32Time;
}

static void ReverseExtAddress(otExtAddress* aReversed,
                              const otExtAddress* aOrigin) {
    for (size_t i = 0; i < sizeof(*aReversed); i++) {
        aReversed->m8[i] = aOrigin->m8[sizeof(*aOrigin) - 1 - i];
    }
}

/* Radio Configuration */
/**
 * @brief                               Get the bus speed in bits/second between the host and radio chip
 *
 * @param aInstance                     A pointer to an OpenThread instance
 * @return uint32_t                     The bus speed in bits/second between the host and the radio chip.
 *                                      Return 0 when the MAC and above layer and Radio layer resides
 *                                      on the same chip.
 */
uint32_t otPlatRadioGetBusSpeed(otInstance* aInstance) {
    // log_info("%s", __func__);
    OT_UNUSED_VARIABLE(aInstance);

    return 2000000;
}

/**
 * @brief                               Get the radio capabilities.
 *
 * @param aInstance                     The OpenThread instance structure.
 * @return otRadioCaps                  The radio capability bit vector (see OT_RADIO_* definitions)
 */
otRadioCaps otPlatRadioGetCaps(otInstance* aInstance) {
    // log_info("%s", __func__);
    OT_UNUSED_VARIABLE(aInstance);

    /* clang-format off */
    otRadioCaps capabilities = (OT_RADIO_CAPS_ACK_TIMEOUT |
                                OT_RADIO_CAPS_TRANSMIT_RETRIES |
                                OT_RADIO_CAPS_SLEEP_TO_TX |
#if OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2
                                OT_RADIO_CAPS_TRANSMIT_SEC      |
#ifdef CONFIG_OT_DEVICE_TYPE_RCP
                                OT_RADIO_CAPS_TRANSMIT_TIMING   |
#endif
#endif
                                OT_RADIO_CAPS_CSMA_BACKOFF
                               );
    return capabilities;
}

/**
 * @brief                               Get the radio's CCA ED threshold in dBm measured at antenna connector
 *                                      per IEEE 802.15.4 - 2015 section 10.1.4
 * @param aInstance                     The OpenThread instance structure.
 * @param aThreshold                    The CCA ED threshold in dBm.
 * @return otError                      OT_ERROR_NONE               Successfully retrieved the CCA ED threshold.
 *                                      OT_ERROR_INVALID_ARGS       aThreasold was NULL.
 *                                      OT_ERROR_NOT_IMPLEMENTED    CCA ED threshold configuration via dBm is
 *                                                                  not implemented.
 */
otError otPlatRadioGetCcaEnergyDetectThreshold(otInstance *aInstance, int8_t *aThreshold)
{
    // log_info("%s", __func__);
    
    OT_UNUSED_VARIABLE(aInstance);

    otError error = OT_ERROR_NONE;
    otEXPECT_ACTION(aThreshold != NULL, error = OT_ERROR_INVALID_ARGS);

    *aThreshold = -(sCcaThresholdDbm);

exit:
    return error;
}

/**
 * @brief                               Get the external FEM's Rx LNA gain in dBm.
 *
 * @param aInstance                     The OpenThread instance structure.
 * @param aGain                         The external FEM's Rx LNA gain in dBm.
 * @return otError                      OT_ERROR_NONE               Successfully retrieved the external FEM's LNA gain.
 *                                      OT_ERROR_INVALID_ARGS       aGain was NULL.
 *                                      OT_ERROR_NOT_IMPLEMENTED    External FEM's LNA setting is
 *                                                                  not implemented.
 */
otError otPlatRadioGetFemLnaGain(otInstance *aInstance, int8_t *aGain)
{
    OT_UNUSED_VARIABLE(aInstance);
    
    return OT_ERROR_NOT_IMPLEMENTED;
}

/**
 * @brief                               Get the factory-assigned IEEE EUI-64 for this interface.
 *
 * @param aInstance                     The OpenThread instance structure.
 * @param aIeeeEui64                    A pointer to the factory-assigned IEEE EUI-64.
 */
void otPlatRadioGetIeeeEui64(otInstance *aInstance, uint8_t *aIeeeEui64)
{
    OT_UNUSED_VARIABLE(aInstance);
    
    memcpy(aIeeeEui64, sIEEE_EUI64Addr, OT_EXT_ADDRESS_SIZE);
}

/**
 * @brief                               Get the current estimated time(in microseconds) of the radio chip.
 *
 *                                      This microsecond timer must be a free-running timer. The timer must
 *                                      continue to advance with microsecond presision even when the radio is
 *                                      in the sleep state.
 *
 * @param aInstance                     The OpenThread instance structure.
 * @return uint64_t                     The current time in microseconds. UINT64_MAX when platform does not
 *                                      support or radio time is not ready.
 */
uint64_t otPlatRadioGetNow(otInstance *aInstance)
{
    // log_info("%s", __func__);
    OT_UNUSED_VARIABLE(aInstance);
    
    return otPlatTimeGet();
}

/**
 * Get current state of the radio.
 *
 * This function is not required by OpenThread. It may be used for debugging and/or application-specific purposes.
 *
 * @note This function may be not implemented. It does not affect OpenThread.
 *
 * @param[in] aInstance  The OpenThread instance structure.
 *
 * @return  Current state of the radio.
 *
 */
otRadioState otPlatRadioGetState(otInstance *aInstance)
{
    // log_info("%s", __func__);
    OT_UNUSED_VARIABLE(aInstance);
    

    return sState;
}

/**
 * @brief                               Get the status of promiscuous mode.
 *
 * @param aInstance                     The OpenThread instance structure.
 * @return true                         Promiscuous mode is enabled.
 * @return false                        Promiscuous mode is disable.
 */
bool otPlatRadioGetPromiscuous(otInstance *aInstance)
{
    // log_info("%s", __func__);
    OT_UNUSED_VARIABLE(aInstance);
    

    return sPromiscuous;
}

/**
 * @brief                               Get the radio receive sensitivity value.
 *
 * @param aInstance                     The OpenThread instance structure.
 * @return int8_t                       The radio receive sensitivity value in dBm.
 */
int8_t otPlatRadioGetReceiveSensitivity(otInstance *aInstance)
{
    // log_info("%s", __func__);
    OT_UNUSED_VARIABLE(aInstance);
    

    return -(RAFAEL_RECEIVE_SENSITIVITY);
}

/**
 * @brief                               Get the radio's transmit power in dBm.
 *
 * @param aInstance                     The OpenThread instance structure.
 * @param aPower                        The transmit power in dBm.
 * @return otError                      OT_ERROR_NONE               Successfully retrieved the transmit power.
 *                                      OT_ERROR_INVALID_ARGS       aPower was NULL.
 *                                      OT_ERROR_NOT_IMPLEMENTED    Transmit power configuration via
 *                                                                  dBm is not implemented.
 */
otError otPlatRadioGetTransmitPower(otInstance *aInstance, int8_t *aPower)
{
    // log_info("%s", __func__);
    OT_UNUSED_VARIABLE(aInstance);
    

    otError error = OT_ERROR_NONE;

    // error = OT_ERROR_NOT_IMPLEMENTED;

    otEXPECT_ACTION(aPower != NULL, error = OT_ERROR_INVALID_ARGS);

    *aPower = 10;

exit:
    return error;
}

/**
 * @brief                               Set the radio's CCA ED threshold in dBm measured at antenna
 *                                      connector per IEEE 802.15.4-2015 section 10.1.4.
 *
 * @param aInstance                     The OpenThread instance structure.
 * @param aThreshold                    The CCA ED threshold in dBm.
 * @return otError                      OT_ERROR_NONE               Successfully retrieved the CCA ED threshold.
 *                                      OT_ERROR_INVALID_ARGS       Given threshold is out of range.
 *                                      OT_ERROR_NOT_IMPLEMENTED    CCA ED threshold configuration via
 *                                                                  dBm is not implemented.
 */
otError otPlatRadioSetCcaEnergyDetectThreshold(otInstance *aInstance, int8_t aThreshold)
{
    // log_info("%s", __func__);
    OT_UNUSED_VARIABLE(aInstance);

    sCCAThreshold = aThreshold;

    lmac15p4_phy_pib_set(sTurnaroundTime, sCCAMode, sCCAThreshold, sCCADuration);

    return OT_ERROR_NONE;
}

/**
 * @brief                               Set the Extended Address for address filtering.
 *
 * @param aInstance                     The OpenThread instance structure.
 * @param aAddress                      A pointer to the IEEE 802.15.4 Extended Address stored in
 *                                      little-endian byte order.
 */
void otPlatRadioSetExtendedAddress(otInstance *aInstance, const otExtAddress *aAddress)
{
    // log_info("%s", __func__);
    OT_UNUSED_VARIABLE(aInstance);
    

    ReverseExtAddress(&sExtAddress, aAddress);


    sExtendAddr_0 = (aAddress->m8[0] | (aAddress->m8[1] << 8) | (aAddress->m8[2] << 16) | (aAddress->m8[3] << 24));
    sExtendAddr_1 = (aAddress->m8[4] | (aAddress->m8[5] << 8) | (aAddress->m8[6] << 16) | (aAddress->m8[7] << 24));

    lmac15p4_address_filter_set(0, sPromiscuous, sShortAddress, sExtendAddr_0, sExtendAddr_1, sPANID, sCoordinator);
}

/**
 * @brief                               Set the external FEM's Rx LNA gain in dBm.
 *
 * @param aInstance                     The OpenThread instance structure.
 * @param aGain                         The external FEM's RX LNA gain in dBm.
 * @return otError                      OT_ERROR_NONE               Successfully set the external FEM's RX LNA gain.
 *                                      OT_ERROR_INVALID_ARGS       Given gain is out of range.
 *                                      OT_ERROR_NOT_IMPLEMENTED    External FEM's Rx LNA gain
 *                                                                  setting is not implemented.
 */
otError otPlatRadioSetFemLnaGain(otInstance *aInstance, int8_t aGain)
{
    // log_info("%s", __func__);
    OT_UNUSED_VARIABLE(aInstance);
    

    assert(aInstance != NULL);

    return OT_ERROR_NOT_IMPLEMENTED;
}

/**
 * @brief                               Set the PAN ID for address filitering.
 *
 * @param aInstance                     The OpenThread instance structure.
 * @param aPanId                        The IEEE 802.15.4 PAN ID.
 */
void otPlatRadioSetPanId(otInstance *aInstance, uint16_t aPanId)
{
    // log_info("%s", __func__);
    OT_UNUSED_VARIABLE(aInstance);

    sPANID = aPanId;

    utilsSoftSrcMatchSetPanId(aPanId);


    lmac15p4_address_filter_set(0, sPromiscuous, sShortAddress, sExtendAddr_0, sExtendAddr_1, sPANID, sCoordinator);
}

/**
 * @brief                               Enable or disable promiscuous mode.
 *
 * @param aInstance                     The OpenThread instance structure.
 * @param aEnable                       TURE to enable or FALSE to disable promiscuous mode.
 */
void otPlatRadioSetPromiscuous(otInstance *aInstance, bool aEnable)
{
    // log_info("%s", __func__);
    OT_UNUSED_VARIABLE(aInstance);
    

    sPromiscuous = aEnable;

    lmac15p4_address_filter_set(0, sPromiscuous, sShortAddress, sExtendAddr_0, sExtendAddr_1, sPANID, sCoordinator);
}

/**
 * @brief                               Set the Short Address for address filitering.
 *
 * @param aInstance                     The OpenThread instance structure.
 * @param aAddress                      The IEEE 802.15.4 Short Address.
 */
void otPlatRadioSetShortAddress(otInstance *aInstance, uint16_t aAddress)
{
    // log_info("%s", __func__);
    OT_UNUSED_VARIABLE(aInstance);
    

    sShortAddress = aAddress;

    lmac15p4_address_filter_set(0, sPromiscuous, sShortAddress, sExtendAddr_0, sExtendAddr_1, sPANID, sCoordinator);
}

/**
 * @brief                               Set the radio's transmit power in dBm.
 *
 * @param aInstance                     The OpenThread instance structure.
 * @param aPower                        The transimit power in dBm.
 * @return otError                      OT_ERROR_NONE               Successfully set the transmit power.
 *                                      OT_ERROR_INVALID_ARGS       aPower is out of range.
 *                                      OT_ERROR_NOT_IMPLEMENTED    Transmit power configuration via
 *                                                                  dBm is not implemented.
 */
otError otPlatRadioSetTransmitPower(otInstance *aInstance, int8_t aPower)
{
    // log_info("%s", __func__);
    OT_UNUSED_VARIABLE(aInstance);
    

    return OT_ERROR_NOT_IMPLEMENTED;
}

/* Radio Operation */

/**
 * @brief                               Disable the radio.
 *
 * @param aInstance                     The OpenThread instance structure.
 * @return otError                      OT_ERROR_NONE               Successfully transitioned to Disable.
 *                                      OT_ERROR_INVALID_STATE      The radio was not in sleep state.
 */
otError otPlatRadioDisable(otInstance *aInstance)
{
    // log_info("%s", __func__);
    OT_UNUSED_VARIABLE(aInstance);
    
    if (otPlatRadioIsEnabled(aInstance))
    {
        otLogDebgPlat("State=OT_RADIO_STATE_DISABLED");
        sState = OT_RADIO_STATE_DISABLED;
        lmac15p4_auto_state_set(false);
        sAuto_State_Set = false;
    }

    return OT_ERROR_NONE;
}

/**
 * @brief                               Enable the radio.
 *
 * @param aInstance                     The OpenThread instance structure.
 * @return otError                      OT_ERROR_NONE               Successfully transitioned to enable.
 *                                      OT_ERROR_INVALID_FAILED     The radio could not be enabled.
 */
otError otPlatRadioEnable(otInstance *aInstance)
{
    // log_info("%s", __func__);
    
    if (!otPlatRadioIsEnabled(aInstance))
    {
        sState = OT_RADIO_STATE_SLEEP;
    }

    return OT_ERROR_NONE;
}

/**
 * @brief                               Enable/Disable source address match feature.
 *
 *                                      The source address match feature controls how the radio layer descides
 *                                      the "frame pending" bit for acks sent in response to data request commands
 *                                      from children.
 *
 *                                      If disable, the radio layer must set the "frame panding" on all acks to
 *                                      data request commands.
 *
 *                                      If enable, the radio layer uses the source address match table to determine
 *                                      whether to set or clear the "frame pending" bit in an ack to data request command.
 *
 *                                      The source address match table provide the list of children for which there is a
 *                                      pending frame. Either a short address or an extended/long address can be added
 *                                      to the source address match table.
 *
 * @param aInstance                     The OpenThread instance structure.
 * @param aEnable                       Enable/disable source address match feature.
 */
void otPlatRadioEnableSrcMatch(otInstance *aInstance, bool aEnable)
{
    // log_info("%s", __func__);
    OT_UNUSED_VARIABLE(aInstance);
    // set Frame Pending bit for all outgoing ACKs if aEnable is false
    sIsSrcMatchEnabled = aEnable;

    lmac15p4_src_match_ctrl(0, aEnable);
}

/**
 * @brief                               Biging the energy scan sequence on the radio.
 *                                      The function is used when radio provides OT_RADIO_CAPS_ENERGY_SCAN capability.
 *
 * @param aInstance                     The OpenThread instance structure.
 * @param aScanChannel                  The channel to perform the energy scan on.
 * @param aScanDuration                 The duration, in milliseconds, for the channel to be scanned.
 * @return otError                      OT_ERROR_NONE               Successfully started scanning the channel.
 *                                      OT_ERROR_NOT_IMPLEMENTED    The radio doesn't support energy scanning.
 */
otError otPlatRadioEnergyScan(otInstance *aInstance, uint8_t aScanChannel, uint16_t aScanDuration)
{
    // log_info("%s", __func__);
    OT_UNUSED_VARIABLE(aInstance);
    

    uint8_t rssi_value;
    //if (aScanChannel != sCurrentChannel)
    {
        sCurrentChannel        = aScanChannel;
        lmac15p4_channel_set((lmac154_channel_t)(sCurrentChannel - kMinChannel));
    }

    rssi_value = lmac15p4_read_rssi();

    otPlatRadioEnergyScanDone(aInstance, -rssi_value);

    return OT_ERROR_NONE;
}

/**
 * @brief                               Get the most recent RSSI measurement.
 *
 * @param aInstance                     The OpenThread instance structure.
 * @return int8_t                       The RSSI in dBm when it is valid. 127 when RSSI is invalid.
 */
int8_t otPlatRadioGetRssi(otInstance *aInstance)
{
    uint8_t   rssi = OT_RADIO_RSSI_INVALID;

    OT_UNUSED_VARIABLE(aInstance);

    rssi = lmac15p4_read_rssi();

    return -rssi;
}


/**
 * @brief                               Get the radio transmit frame buffer.
 *
 *                                      OpenThread forms the IEEE 802.15.4 frame in this buffer then calls
 *                                      otPlatRadioTransmit() to request transmission.
 *
 * @param aInstance                     The OpenThread instance structure.
 * @return otRadioFrame*                A pointer ti the transimit frame buffer.
 */
otRadioFrame *otPlatRadioGetTransmitBuffer(otInstance *aInstance)
{
    otRadio_var.aInstance = aInstance;
    
    otRadioFrame * txframe = (otRadioFrame *)otRadio_var.buffPool;
    txframe->mPsdu = otRadio_var.buffPool + ALIGNED_RX_FRAME_SIZE;

    return txframe;
}

/**
 * @brief                               Check whether radio is enabled or not.
 *
 * @param aInstance                     The OpenThread instance structure.
 * @return true                         If the radio is enabled.
 * @return false                        If the radio is not enabled.
 */
bool otPlatRadioIsEnabled(otInstance *aInstance)
{
    OT_UNUSED_VARIABLE(aInstance);
    

    return (sState != OT_RADIO_STATE_DISABLED) ? true : false;
}

/**
 * @brief                               Transition the radio from Sleep to Receive(turn on the radio)
 *
 * @param aInstance                     The OpenThread instance structure.
 * @param aChannel                      The channel to use for receiving.
 * @return otError                      OT_ERROR_NONE               Successfully transitioned to Receive.
 *                                      OT_ERROR_INVALID_STATE      The radio was disabled or transmiting.
 */
otError otPlatRadioReceive(otInstance *aInstance, uint8_t aChannel)
{
    OT_UNUSED_VARIABLE(aInstance);


    assert(aInstance != NULL);
    otError error = OT_ERROR_INVALID_STATE;

    if (sState != OT_RADIO_STATE_DISABLED)
    {
        error = OT_ERROR_NONE;
        sState = OT_RADIO_STATE_RECEIVE;
        if (aChannel != sCurrentChannel)
        {
            sCurrentChannel = aChannel;
            lmac15p4_channel_set((lmac154_channel_t)(sCurrentChannel - kMinChannel));
        }

        lmac15p4_auto_state_set(true);
        sAuto_State_Set = true;
    }

    return OT_ERROR_NONE;
}


/**
 * @brief                               Transition the radio from Receive to Sleep (turn off the radio)
 *
 * @param aInstance                     The OpenThread instance structure.
 * @return otError                      OT_ERROR_NONE               Successfully transitioned to Sleep.
 *                                      OT_ERROR_BUSY               The radio was transmiting.
 *                                      OT_ERROR_INVALID_STATE      The radio was disabled.
 */
otError otPlatRadioSleep(otInstance *aInstance)
{
    OT_UNUSED_VARIABLE(aInstance);

    otError error = OT_ERROR_INVALID_STATE;

    if (sState == OT_RADIO_STATE_SLEEP || sState == OT_RADIO_STATE_RECEIVE)
    {
        error  = OT_ERROR_NONE;
        sState = OT_RADIO_STATE_SLEEP;
        /* Disable RX, and enter sleep*/
        if (sAuto_State_Set != false)
        {
            lmac15p4_auto_state_set(false);
            sAuto_State_Set = false;
        }
    }

    return error;
}
#if 1

#if OPENTHREAD_CONFIG_MAC_CSL_RECEIVER_ENABLE
static uint16_t getCslPhase(void)
{
    uint32_t curTime       = otPlatAlarmMicroGetNow();//rfb_port_rtc_time_read();
    uint32_t cslPeriodInUs = sCslPeriod * OT_US_PER_TEN_SYMBOLS;
    uint32_t diff = ((sCslSampleTime % cslPeriodInUs) - (curTime % cslPeriodInUs) + cslPeriodInUs) % cslPeriodInUs;

    return (uint16_t)(diff / OT_US_PER_TEN_SYMBOLS);
}
#endif

static otError radioProcessTransmitSecurity(otRadioFrame *aFrame)
{
    otError error = OT_ERROR_NONE;
#if OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2
    otMacKeyMaterial *key = NULL;
    uint8_t           keyId;

    otEXPECT(otMacFrameIsSecurityEnabled(aFrame) && otMacFrameIsKeyIdMode1(aFrame) &&
             !aFrame->mInfo.mTxInfo.mIsSecurityProcessed);

    if (otMacFrameIsAck(aFrame))
    {
        keyId = otMacFrameGetKeyId(aFrame);

        otEXPECT_ACTION(keyId != 0, error = OT_ERROR_FAILED);

        if (keyId == sKeyId)
        {
            key = &sCurrKey;
        }
        else if (keyId == sKeyId - 1)
        {
            key = &sPrevKey;
        }
        else if (keyId == sKeyId + 1)
        {
            key = &sNextKey;
        }
        else
        {
            error = OT_ERROR_SECURITY;
            otEXPECT(false);
        }
    }
    else
    {
        key   = &sCurrKey;
        keyId = sKeyId;
    }

    aFrame->mInfo.mTxInfo.mAesKey = key;

    if (!aFrame->mInfo.mTxInfo.mIsHeaderUpdated)
    {
        otMacFrameSetKeyId(aFrame, keyId);
        otMacFrameSetFrameCounter(aFrame, sMacFrameCounter++);
    }
#else
    otEXPECT(!aFrame->mInfo.mTxInfo.mIsSecurityProcessed);
#endif // OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2

    otMacFrameProcessTransmitAesCcm(aFrame, &sExtAddress);

exit:
    return error;
}
#endif

/**
 * @brief                               Begin the transmit sequence on the radio.
 *
 *                                      The caller must from the IEEE 802.15.4 frame in the buffer provided by
 *                                      otPlatRadioTransmitBuffer() before requesting transmission. The channel
 *                                      and transmit power are also include in otRadioFrame structure.
 *
 *                                      The transmit sequence consists of:
 *                                          1. Transitioning the radio to Transmit from on of following state:
 *                                              * Receive if Rx is on when the device idle or OT_RADIO_CAPS_SLEEP_TO_TX
 *                                                is not supported.
 *                                              * Sleep if Rx is off when the device is idle or OT_RADIO_CAPS_SLEEP_TO_TX
 *                                                is supported.
 *                                          2. Transmits the psdu on the given channel and at the given transmit power.
 *
 * @param aInstance                     The OpenThread instance structure.
 * @param aFrame                        A pointer to the frame to be transmitted.
 * @return otError                      OT_ERROR_NONE               Successfully transitioned to Transmit.
 *                                      OT_ERROR_INVALID_STATE      The radio was not in Receive state.
 */
otError otPlatRadioTransmit(otInstance *aInstance, otRadioFrame *aFrame)
{
    OT_UNUSED_VARIABLE(aInstance);
    OT_UNUSED_VARIABLE(aFrame);

    assert(aInstance != NULL);
    assert(aFrame != NULL);

    static uint32_t tx_timerWraps = 0U, tx_prev32Time = 0U;       

    uint8_t tx_control = 0;
    uint8_t temp[OT_RADIO_FRAME_MAX_SIZE + 4];    

    otError error = OT_ERROR_INVALID_STATE;

    if (otRadio_var.pTxFrame == NULL) 
    {
        otRadio_var.pTxFrame = aFrame;
        //if (sCurrentChannel != aFrame->mChannel)
        {
            sCurrentChannel = aFrame->mChannel;
            lmac15p4_channel_set((lmac154_channel_t)(sCurrentChannel - kMinChannel));
        }
    }
#if OPENTHREAD_CONFIG_MAC_CSL_RECEIVER_ENABLE
    if(sCslPeriod > 0 && !aFrame->mInfo.mTxInfo.mIsHeaderUpdated)
    {
        otMacFrameSetCslIe(aFrame, (uint16_t)sCslPeriod, getCslPhase());
        aFrame->mInfo.mTxInfo.mCsmaCaEnabled = false;
    }
#endif
    radioProcessTransmitSecurity(aFrame);
    if ((otRadio_var.pTxFrame->mPsdu[0] & IEEE802154_ACK_REQUEST))
    {
        tx_control = 0x03;
    }
    else
    {
        tx_control = 0x02;
    }
    
    tx_control |= (1 << 2 );
    if (otMacFrameIsSecurityEnabled(aFrame))
    {
        uint32_t temp_fc = 0U;
        temp_fc = lmac15p4_frame_counter_get();
        if (sMacFrameCounter < temp_fc)
        {
            sMacFrameCounter = temp_fc + 1;
        }
    }
    temp[0] = ((sMacFrameCounter >> 0) & 0xFF);
    temp[1] = ((sMacFrameCounter >> 8) & 0xFF);
    temp[2] = ((sMacFrameCounter >> 16) & 0xFF);
    temp[3] = ((sMacFrameCounter >> 24) & 0xFF);

    memcpy(temp + 4, otRadio_var.pTxFrame->mPsdu, otRadio_var.pTxFrame->mLength);
    if (otRadio_var.pTxFrame->mInfo.mTxInfo.mTxDelay != 0)
    {
        tx_control ^= (1 << 1);
    }
    if (aFrame->mInfo.mTxInfo.mCsmaCaEnabled == false)
    {
        tx_control ^= (1 << 1);
    }
    if(lmac15p4_tx_data_send(0, temp,
                          otRadio_var.pTxFrame->mLength + 2,
                          tx_control,
                          otMacFrameGetSequence(aFrame)) != 0)
    {
        log_error("Tx failed !");
        OT_NOTIFY(OT_SYSTEM_EVENT_RADIO_TX_NO_ACK);
    }
    
    otPlatRadioTxStarted(aInstance, aFrame);
    otRadio_var.tstx = otPlatTimeGet()+1;
    error = OT_ERROR_NONE;
    return error;
}

#if OPENTHREAD_CONFIG_MAC_CSL_RECEIVER_ENABLE
otError otPlatRadioEnableCsl(otInstance         *aInstance,
                             uint32_t            aCslPeriod,
                             otShortAddress      aShortAddr,
                             const otExtAddress *aExtAddr)
{
    OT_UNUSED_VARIABLE(aInstance);
    OT_UNUSED_VARIABLE(aShortAddr);
    OT_UNUSED_VARIABLE(aExtAddr);

    otError error = OT_ERROR_NONE;

    sCslPeriod = aCslPeriod;
    if (sCslPeriod > 0)
    {
        lmac15p4_csl_receiver_ctrl(1, sCslPeriod);
    }
    else
    {
        lmac15p4_csl_receiver_ctrl(0, 0);
    }
    return error;
}

void otPlatRadioUpdateCslSampleTime(otInstance *aInstance, uint32_t aCslSampleTime)
{
    OT_UNUSED_VARIABLE(aInstance);

    sCslSampleTime = aCslSampleTime;
    lmac15p4_csl_sample_time_update(sCslSampleTime);
}


#endif // OPENTHREAD_CONFIG_MAC_CSL_RECEIVER_ENABLE
uint8_t otPlatRadioGetCslAccuracy(otInstance *aInstance)
{
    OT_UNUSED_VARIABLE(aInstance);
    
    //return spRFBCtrl->csl_accuracy_get();
    return 255;
}

uint8_t otPlatRadioGetCslUncertainty(otInstance *aInstance)
{
    OT_UNUSED_VARIABLE(aInstance);
    //return spRFBCtrl->csl_uncertainty_get();
#ifdef CONFIG_OT_DEVICE_TYPE_RCP
    return 255;
#else
    return 175;
#endif

}

#if OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2
void otPlatRadioSetMacKey(otInstance             *aInstance,
                          uint8_t                 aKeyIdMode,
                          uint8_t                 aKeyId,
                          const otMacKeyMaterial *aPrevKey,
                          const otMacKeyMaterial *aCurrKey,
                          const otMacKeyMaterial *aNextKey,
                          otRadioKeyType          aKeyType)
{
    OT_UNUSED_VARIABLE(aInstance);
    OT_UNUSED_VARIABLE(aKeyIdMode);
    

    otEXPECT(aPrevKey != NULL && aCurrKey != NULL && aNextKey != NULL);

    sKeyId   = aKeyId;
    sKeyType = aKeyType;
    memcpy(&sPrevKey, aPrevKey, sizeof(otMacKeyMaterial));
    memcpy(&sCurrKey, aCurrKey, sizeof(otMacKeyMaterial));
    memcpy(&sNextKey, aNextKey, sizeof(otMacKeyMaterial));

    lmac15p4_key_set(0, sCurrKey.mKeyMaterial.mKey.m8);
exit:
    return;
}

/**
 * @brief                               The method sets the current MAC frame counter value.
 *
 * @param aInstance                     The OpenThread instance structure.
 * @param aMacFrameCounter              The MAC frame counter value.
 */
void otPlatRadioSetMacFrameCounter(otInstance *aInstance, uint32_t aMacFrameCounter)
{
    OT_UNUSED_VARIABLE(aInstance);
    

    sMacFrameCounter = aMacFrameCounter;
}
#endif

/**
 * @brief                               The method get the cca value.
 */
otError otPlatRadioGetCca(otInstance *aInstance, int8_t *aThreshold, uint16_t *turnaroundtime, uint16_t *duration)
{
    *aThreshold = -(sCCAThreshold);
    *turnaroundtime = sTurnaroundTime;
    *duration = sCCADuration;
    

    return OT_ERROR_NONE;
}

/**
 * @brief                               The method sets the cca value.
 * @return otError                                          OT_ERROR_NONE               Successfully set the transmit power.
 *                                      OT_ERROR_INVALID_ARGS       cca value is error.
 */
otError otPlatRadioSetCca(otInstance *aInstance, int8_t aThreshold, uint16_t turnaroundtime, uint16_t duration)
{
    // log_info("%s", __func__);
    
    if (aThreshold <= 0)
    {
        return OT_ERROR_INVALID_ARGS;
    }
    if (turnaroundtime <= 0)
    {
        return OT_ERROR_INVALID_ARGS;
    }
    if (duration <= 0)
    {
        return OT_ERROR_INVALID_ARGS;
    }
    sCCAThreshold = aThreshold;
    sTurnaroundTime = turnaroundtime;
    sCCADuration = duration;
    lmac15p4_phy_pib_set(sTurnaroundTime, sCCAMode, sCCAThreshold, sCCADuration);
    return OT_ERROR_NONE;
}

#if OPENTHREAD_CONFIG_MLE_LINK_METRICS_SUBJECT_ENABLE
otError otPlatRadioConfigureEnhAckProbing(otInstance          *aInstance,
        otLinkMetrics        aLinkMetrics,
        const otShortAddress aShortAddress,
        const otExtAddress *aExtAddress)
{
    OT_UNUSED_VARIABLE(aInstance);
    if ((aLinkMetrics.mLqi + aLinkMetrics.mLinkMargin + aLinkMetrics.mRssi) < 3 )
    {
        uint8_t temp_extaddr[OT_EXT_ADDRESS_SIZE];
        for (uint8_t i = 0; i < OT_EXT_ADDRESS_SIZE; i++)
        {
            temp_extaddr[i] = aExtAddress->m8[7 - i];
        }
        if (aLinkMetrics.mLqi)
        {
           lmac15p4_src_match_short_entry(3, (uint8_t *)&aShortAddress);
           lmac15p4_src_match_extended_entry(3, temp_extaddr);
        }
        else
        {
           lmac15p4_src_match_short_entry(4, (uint8_t *)&aShortAddress);
           lmac15p4_src_match_extended_entry(4, temp_extaddr);
        }

        if (aLinkMetrics.mLinkMargin)
        {
           lmac15p4_src_match_short_entry(5, (uint8_t *)&aShortAddress);
           lmac15p4_src_match_extended_entry(5, temp_extaddr);
        }
        else
        {
           lmac15p4_src_match_short_entry(6, (uint8_t *)&aShortAddress);
           lmac15p4_src_match_extended_entry(6, temp_extaddr);
        }

        if (aLinkMetrics.mRssi)
        {
           lmac15p4_src_match_short_entry(7, (uint8_t *)&aShortAddress);
           lmac15p4_src_match_extended_entry(7, temp_extaddr);
        }
        else
        {
            lmac15p4_src_match_short_entry(8, (uint8_t *)&aShortAddress);
            lmac15p4_src_match_extended_entry(8, temp_extaddr);
        }
    }

    return OT_ERROR_NONE;
}
#endif

static bool hasFramePending(const otRadioFrame *aFrame)
{
    bool         rval = false;
    otMacAddress src;

    otEXPECT_ACTION(sIsSrcMatchEnabled, rval = true);
    otEXPECT(otMacFrameGetSrcAddr(aFrame, &src) == OT_ERROR_NONE);

    switch (src.mType)
    {
    case OT_MAC_ADDRESS_TYPE_SHORT:
        rval = utilsSoftSrcMatchShortFindEntry(src.mAddress.mShortAddress) >= 0;
        break;
    case OT_MAC_ADDRESS_TYPE_EXTENDED:
    {
        otExtAddress extAddr;

        ReverseExtAddress(&extAddr, &src.mAddress.mExtAddress);
        rval = utilsSoftSrcMatchExtFindEntry(&extAddr) >= 0;
        break;
    }
    default:
        break;
    }

exit:
    return rval;
}
void ot_radioTask(ot_system_event_t trxEvent)
{
    otRadio_rxFrame_t *pframe;
    otRadioFrame        *txframe;

    if (!(OT_SYSTEM_EVENT_RADIO_ALL_MASK & trxEvent)) 
    {
        return;
    }

    if (otRadio_var.pTxFrame) 
    {
        if ((OT_SYSTEM_EVENT_RADIO_TX_ALL_MASK & trxEvent)) 
        {
            txframe = otRadio_var.pTxFrame;
            otRadio_var.pTxFrame = NULL;
            otRadio_var.tstx = 0;
            
            if (trxEvent & OT_SYSTEM_EVENT_RADIO_TX_DONE_NO_ACK_REQ) 
            {
                otPlatRadioTxDone(otRadio_var.aInstance, txframe, NULL, OT_ERROR_NONE);
            }
            if (trxEvent & OT_SYSTEM_EVENT_RADIO_TX_ACKED) 
            {
                otPlatRadioTxDone(otRadio_var.aInstance, txframe, otRadio_var.pAckFrame, OT_ERROR_NONE);
                // log_info_hexdump("ack", otRadio_var.pAckFrame->mPsdu, otRadio_var.pAckFrame->mLength);
            }
            if (trxEvent & OT_SYSTEM_EVENT_RADIO_TX_NO_ACK) 
            {
                otPlatRadioTxDone(otRadio_var.aInstance, txframe, NULL, OT_ERROR_NO_ACK);
                // log_warn_hexdump("Tx No ACK", txframe->mPsdu, txframe->mLength);
            }
            if (trxEvent & OT_SYSTEM_EVENT_RADIO_TX_CCA_FAIL) 
            {
                //otPlatRadioTxDone(otRadio_var.aInstance, txframe, NULL, OT_ERROR_CHANNEL_ACCESS_FAILURE);
                otPlatRadioTxDone(otRadio_var.aInstance, txframe, NULL, OT_ERROR_CHANNEL_ACCESS_FAILURE);
                // log_warn_hexdump("Tx CCA Fail", txframe->mPsdu, txframe->mLength);
            }
        }
    }
    
    if (trxEvent & OT_SYSTEM_EVENT_RADIO_RX_DONE ) 
    {

        pframe = NULL;
        OT_ENTER_CRITICAL();
        if (!utils_dlist_empty(&otRadio_var.rxFrameList)) 
        {
            pframe = (otRadio_rxFrame_t *)otRadio_var.rxFrameList.next;
            otRadio_var.dbgRxFrameNum --;
            utils_dlist_del(&pframe->dlist);
        }
        OT_EXIT_CRITICAL();

        if (pframe) 
        {
            otPlatRadioReceiveDone(otRadio_var.aInstance, &pframe->frame, OT_ERROR_NONE);

            OT_ENTER_CRITICAL();
            utils_dlist_add_tail(&pframe->dlist, &otRadio_var.frameList);
            otRadio_var.dbgFrameNum ++;

            if (!utils_dlist_empty(&otRadio_var.rxFrameList)) 
            {
                vTaskDelay(5);
                OT_NOTIFY(OT_SYSTEM_EVENT_RADIO_RX_DONE);
            }
            OT_EXIT_CRITICAL();
        }
        else
        {
            log_warn("otRadio_var.dbgRxFrameNum %d", otRadio_var.dbgRxFrameNum);
        }
    }
    else if (trxEvent & OT_SYSTEM_EVENT_RADIO_RX_NO_BUFF) 
    {
        log_warn("no buffer");
        // otPlatRadioReceiveDone(otRadio_var.aInstance, NULL, OT_ERROR_NO_BUFS);
    }
}

#if 1
/**
 * @brief
 *
 * @param u8_tx_status
 */
static void _TxDoneEvent(uint32_t tx_status)
{
    uint32_t ack_now32Time = 0U;
    static uint32_t ack_timerWraps = 0U, ack_prev32Time = 0U;
    otRadioFrame        *txframe;

    // log_info("tx d");
    // lmac15p4_auto_state_set(true);
    if (otRadio_var.pTxFrame) 
    {      
        txframe = otRadio_var.pTxFrame;
        if (0 == tx_status) 
        {
            OT_NOTIFY(OT_SYSTEM_EVENT_RADIO_TX_DONE_NO_ACK_REQ);
            // otPlatRadioTxDone(otRadio_var.aInstance, txframe, NULL, OT_ERROR_NONE);
        }
        else if(0x10 == tx_status)
        {
            OT_NOTIFY(OT_SYSTEM_EVENT_RADIO_TX_CCA_FAIL);
            // otPlatRadioTxDone(otRadio_var.aInstance, txframe, NULL, OT_ERROR_NO_ACK);
        }
        else if (0x20 == tx_status ) 
        {
            OT_NOTIFY(OT_SYSTEM_EVENT_RADIO_TX_NO_ACK);
            // otPlatRadioTxDone(otRadio_var.aInstance, txframe, NULL, OT_ERROR_NO_ACK);
        }
        else if (0x40 == tx_status || 0x80 == tx_status) 
        {
            otRadio_var.pAckFrame->mLength = lmac15p4_read_ack((uint8_t *)otRadio_var.pAckFrame->mPsdu, (uint8_t *)&ack_now32Time, 0);
            otRadio_var.pAckFrame->mInfo.mRxInfo.mTimestamp = longtime_to_longlong_time(&ack_prev32Time, ack_now32Time, &ack_timerWraps);
            otRadio_var.pAckFrame->mInfo.mRxInfo.mTimestamp -= (130 + (otRadio_var.pAckFrame->mLength + 1) * 32);


            OT_NOTIFY(OT_SYSTEM_EVENT_RADIO_TX_ACKED);
            // otPlatRadioTxDone(otRadio_var.aInstance, txframe, otRadio_var.pAckFrame, OT_ERROR_NONE);
        }
        lpm_low_power_unmask(LOW_POWER_MASK_BIT_RESERVED4);
    }
    else 
    {
        //log_error("lmac154_txDoneEvent, %ld, invalid", tx_status);
    }
}

/**
 * @brief
 *
 * @param packet_length
 * @param rx_data_address
 * @param crc_status
 * @param rssi
 * @param snr
 */
static void _RxDoneEvent(uint16_t packet_length, uint8_t *rx_data_address,
                           uint8_t crc_status, uint8_t rssi, uint8_t snr)
{
    otRadio_rxFrame_t *p = NULL;
    uint32_t rx_now32Time = 0U;
    static uint32_t rx_timerWraps = 0U, rx_prev32Time = 0U;    
    static uint8_t rx_done_cnt = 0;

    if (crc_status == 0)
    {
        OT_ENTER_CRITICAL();
        if (!utils_dlist_empty(&otRadio_var.frameList))
        {
            p = (otRadio_rxFrame_t *)otRadio_var.frameList.next;
            otRadio_var.dbgFrameNum --;
            utils_dlist_del(&p->dlist);
        }
        OT_EXIT_CRITICAL();

        if (p) 
        {
            lmac15p4_rx_rtc_time_read(rx_done_cnt, &rx_now32Time);
            // rx_now32Time = otPlatAlarmMicroGetNow();
            // rx_now32Time = otPlatTimeGet() - (255 *10);
            p->frame.mInfo.mRxInfo.mTimestamp = longtime_to_longlong_time(&rx_prev32Time, rx_now32Time, &rx_timerWraps);
            // log_info("rx time %ld", p->frame.mInfo.mRxInfo.mTimestamp);
            memcpy(p->frame.mPsdu, (rx_data_address + 8), (packet_length-9));
            p->frame.mLength = (packet_length-9);          
            p->frame.mChannel = sCurrentChannel;
            p->frame.mInfo.mRxInfo.mRssi = -rssi;
            p->frame.mInfo.mRxInfo.mLqi = ((RAFAEL_RECEIVE_SENSITIVITY - rssi) * 0xFF) / RAFAEL_RECEIVE_SENSITIVITY;

#ifdef CONFIG_OT_DEVICE_TYPE_RCP
            p->frame.mInfo.mRxInfo.mTimestamp -= (2500);
#else
            p->frame.mInfo.mRxInfo.mTimestamp -= (50 + (p->frame.mLength + 1) * 32);
#endif
            p->frame.mInfo.mRxInfo.mAckedWithFramePending = false;
            if( 
#if OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2                
            ((otMacFrameIsVersion2015(&p->frame) && otMacFrameIsCommand(&p->frame)) ||
              otMacFrameIsData(&p->frame) || otMacFrameIsDataRequest(&p->frame))  
#else
        otMacFrameIsDataRequest(&p->frame)
#endif              
             && hasFramePending(&p->frame))
            {
                p->frame.mInfo.mRxInfo.mAckedWithFramePending = true;
            }

#if OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2
        if (otMacFrameIsVersion2015(&p->frame) &&
            otMacFrameIsSecurityEnabled(&p->frame) &&
            otMacFrameIsAckRequested(&p->frame))
        {
            p->frame.mInfo.mRxInfo.mAckedWithSecEnhAck = true;
            p->frame.mInfo.mRxInfo.mAckFrameCounter = ++sMacFrameCounter;
        }
#endif // OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2            

            OT_ENTER_CRITICAL();
            utils_dlist_add_tail(&p->dlist, &otRadio_var.rxFrameList);
            otRadio_var.dbgRxFrameNum ++;
            if (otRadio_var.dbgMaxPendingFrameNum < otRadio_var.dbgRxFrameNum) 
            {
                otRadio_var.dbgMaxPendingFrameNum = otRadio_var.dbgRxFrameNum;
            }
            OT_EXIT_CRITICAL();

            OT_NOTIFY(OT_SYSTEM_EVENT_RADIO_RX_DONE);
        }
        else 
        {
            OT_NOTIFY(OT_SYSTEM_EVENT_RADIO_RX_NO_BUFF);
        }
    }

    ++rx_done_cnt > 4 ? rx_done_cnt = 0 : rx_done_cnt;
}
#endif
void ot_radio_short_addr_ctrl(uint8_t ctrl_type, uint8_t *short_addr)
{
    lmac15p4_src_match_short_entry(ctrl_type, short_addr);
}

void ot_radio_extend_addr_ctrl(uint8_t ctrl_type, uint8_t *extend_addr)
{
    lmac15p4_src_match_extended_entry(ctrl_type, extend_addr);
}

void rafael_radio_cca_threshold_set(uint8_t cca_threshold)
{
    if (sCCAThreshold != cca_threshold)
    {
        sCCAThreshold = cca_threshold;
    }
}

void rafael_radio_mac_read_config_set(uint8_t mode)
{
    sMacAddrReadMode = mode;
}

static void rafael_otp_mac_addr(uint8_t *addr)
{
    uint8_t  temp[256];
    flash_read_sec_register((uint32_t)temp, 0x1100);
    memcpy(addr, temp + OT_EXT_ADDRESS_SIZE, OT_EXT_ADDRESS_SIZE);
}

void ot_radioInit()
{
    lmac15p4_callback_t mac_cb;
    uint8_t ieeeAddr[OT_EXT_ADDRESS_SIZE] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    otRadio_rxFrame_t *pframe = NULL;

    if (sMacAddrReadMode == 1)
    {
        rafael_otp_mac_addr(sIEEE_EUI64Addr);

        if (!memcmp(ieeeAddr, sIEEE_EUI64Addr, OT_EXT_ADDRESS_SIZE))
        {
            flash_get_unique_id((uint32_t)sIEEE_EUI64Addr, OT_EXT_ADDRESS_SIZE);
        }
    }
    else
    {
        flash_get_unique_id((uint32_t)sIEEE_EUI64Addr, OT_EXT_ADDRESS_SIZE);
    }

    
    memset(&otRadio_var, 0, offsetof(otRadio_t, buffPool));
    otRadio_var.pAckFrame = (otRadioFrame *)(otRadio_var.buffPool + TOTAL_RX_FRAME_SIZE);
    otRadio_var.pAckFrame->mPsdu = ((uint8_t *)otRadio_var.pAckFrame) + ALIGNED_RX_FRAME_SIZE;

    OT_ENTER_CRITICAL();
    utils_dlist_init(&otRadio_var.frameList);
    utils_dlist_init(&otRadio_var.rxFrameList);

    for (int i = 0; i < OTRADIO_RX_FRAME_BUFFER_NUM; i ++) {
        pframe = (otRadio_rxFrame_t *) (otRadio_var.buffPool + TOTAL_RX_FRAME_SIZE * (i + 2));
        pframe->frame.mPsdu = ((uint8_t *)pframe) + ALIGNED_RX_FRAME_SIZE;
        utils_dlist_add_tail(&pframe->dlist, &otRadio_var.frameList);
    }

    otRadio_var.dbgFrameNum = OTRADIO_RX_FRAME_BUFFER_NUM;
    OT_EXIT_CRITICAL();
    mac_cb.rx_cb = _RxDoneEvent;
    mac_cb.tx_cb = _TxDoneEvent;
    lmac15p4_cb_set(0, &mac_cb);

    lmac15p4_channel_set((lmac154_channel_t)(sCurrentChannel - kMinChannel));  
    /* Auto ACK */
    lmac15p4_auto_ack_set(true);
    /* Auto State */
    lmac15p4_auto_state_set(sAuto_State_Set);

    lmac15p4_src_match_ctrl(0, true);
    lmac15p4_src_match_short_entry(0, NULL);
    lmac15p4_src_match_short_entry(0, NULL);
}

static int _cli_cmd_mac_csma(int argc, char **argv, cb_shell_out_t log_out, void *pExtra)
{
    uint8_t max_be, min_be, backoffs;

    do
    {    
        if(argc < 3)
        {
            log_out("mac_csma max_be min_be backoffs\r\n");
            break;
        }
        max_be = utility_strtol(argv[1], 0);
        min_be = utility_strtol(argv[2], 0);
        backoffs = utility_strtol(argv[3], 0);
        /* code */
        lmac15p4_mac_pib_set(320, 544, 
                            max_be, 
                            backoffs, 
                            16416, 4, 
                            min_be);
        log_out("Set csma parameter[%d %d %d] done\r\n",max_be, min_be, backoffs);
        
    } while (0);
    
  
    return 0;
}


const sh_cmd_t g_cli_cmd_mac_csma STATIC_CLI_CMD_ATTRIBUTE =
{ 
    .pCmd_name    = "mac_csma", 
    .pDescription = "Setting MAC CSMA parameter", 
    .cmd_exec     = _cli_cmd_mac_csma,
};