#ifndef OT_RADIO_BAND_H
#define OT_RADIO_BAND_H

/**
 * Radio band selection for the OpenThread port (Kconfig OT_RADIO_BAND).
 *
 * 2.4 GHz is the original code path and needs nothing from this header.
 *
 * 915 MHz Sub-G runs OpenThread in PROPRIETARY radio mode on the Rafael Sub-G
 * O-QPSK 800 kchip/s PHY (RT584 family only). The channel plan
 * comes from Kconfig OT_SUBG_*: defaults follow the Silicon Labs single-band
 * proprietary sub-GHz plan (page 23, channel 0-24, 903.0 MHz + 1 MHz * ch).
 * OT_SUBG_CHANNEL_PAGE and the channel mask are only needed by the OpenThread
 * core and are passed on by components/network/thread/CMakeLists.txt.
 *
 * ot_radio.c and the example main.c files read the OT_BAND_* values below.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(CONFIG_OT_BAND_SUBG_915)

/* ---- channel plan ------------------------------------------------------- */

#ifndef CONFIG_OT_SUBG_CHANNEL_MIN
#define CONFIG_OT_SUBG_CHANNEL_MIN 0
#endif
#ifndef CONFIG_OT_SUBG_CHANNEL_MAX
#define CONFIG_OT_SUBG_CHANNEL_MAX 24
#endif
#ifndef CONFIG_OT_SUBG_FREQUENCY_BASE_KHZ
#define CONFIG_OT_SUBG_FREQUENCY_BASE_KHZ 903000
#endif
#ifndef CONFIG_OT_SUBG_CHANNEL_SPACING_KHZ
#define CONFIG_OT_SUBG_CHANNEL_SPACING_KHZ 1000
#endif

#define OT_BAND_CHANNEL_MIN CONFIG_OT_SUBG_CHANNEL_MIN
#define OT_BAND_CHANNEL_MAX CONFIG_OT_SUBG_CHANNEL_MAX

/* Center frequency in kHz (HOSAL_RF_IOCTL_FREQUENCY_SET takes kHz). */
#define OT_BAND_FREQUENCY_KHZ(ch)\
    ((uint32_t)CONFIG_OT_SUBG_FREQUENCY_BASE_KHZ\
     + (uint32_t)CONFIG_OT_SUBG_CHANNEL_SPACING_KHZ\
           * (uint32_t)((ch) - CONFIG_OT_SUBG_CHANNEL_MIN))

/* ---- PHY / MAC parameters (us unless noted) ------------------------------ */

/* O-QPSK 800 kchip/s (HOSAL_RF_PHY_DATA_RATE_OQPSK_800K, RT584 family only).
 * One symbol is 32 chips = 40 us, 2.5x the 2.4 GHz symbol time (16 us), so the
 * 2.4 GHz timing values are scaled by 2.5. Derived, not from a specification. */
#define OT_BAND_SUBG_DATA_RATE            HOSAL_RF_PHY_DATA_RATE_OQPSK_800K
#define OT_BAND_SUBG_RATE_NAME            "O-QPSK 800K"
#define OT_BAND_PHY_TURNAROUND_TIMER      480 /* 12 symbols */
#define OT_BAND_PHY_CCA_DETECTED_TIME     320 /* 8 symbols */
#define OT_BAND_PHY_CCA_DETECT_MODE       0x10
/* 800K reports RSSI about 57 dB higher than 25K for the same link (-47 vs -104
 * dBm in subg-trx) and its idle noise floor reads about -65 dBm, so the 25K
 * threshold (-75 dBm) made every CCA fail. 55 (-55 dBm) was enough in a quiet room
 * (noise floor -65 dBm), but with other Sub-G devices nearby the measured floor
 * is -35 to -47 dBm (RCP and FTD alike, 915-917 MHz up to 0 dBm) and 55 gave
 * ChannelAccessFailure on every frame; with -30 or looser there were none.
 * The RSSI offset itself is not calibrated. */
#define OT_BAND_PHY_CCA_THRESHOLD         30
#define OT_BAND_MAC_UNIT_BACKOFF_PERIOD   800 /* 20 symbols */
#define OT_BAND_MAC_ACK_WAIT_DURATION     1360 /* 34 symbols, non-beacon */
#define OT_BAND_MAC_FRAME_TOTAL_WAIT_TIME 41040
#define OT_BAND_MAC_MAX_BE                8
#define OT_BAND_MAC_MAX_CSMACA_BACKOFFS   10
#define OT_BAND_MAC_MIN_BE                0
#define OT_BAND_MAC_MAX_FRAME_RETRIES     4
#define OT_BAND_RECEIVE_SENSITIVITY       101 /* dBm, absolute value */
/* 80 us per byte (2.4 GHz: 32 us), fixed part scaled 2.5x */
#define OT_BAND_RX_TS_ADJUST_US(len)      (125 + ((len) + 1) * 80)
#define OT_BAND_ACK_TS_ADJUST_US(len)     (325 + ((len) + 1) * 80)

/* ---- debug -------------------------------------------------------------- */

/* 1: log every RX done event (length, CRC status, RSSI, SNR) in ot_radio.c.
 * Off by default, the UART output slows the RX path. */
#define OT_BAND_RX_DONE_LOG 0

#endif /* CONFIG_OT_BAND_SUBG_915 */

/* 2.4 GHz is the original code path. Older .config files carry no band symbol,
 * so it is also the fallback when neither band is selected. */
#if !defined(CONFIG_OT_BAND_SUBG_915) && !defined(CONFIG_OT_BAND_2P4G)
#define CONFIG_OT_BAND_2P4G 1
#endif

#ifdef __cplusplus
}
#endif

#endif /* OT_RADIO_BAND_H */
