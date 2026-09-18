#pragma once
#include <stdint.h>

/* A breadcrumb trail that survives a panic reboot.
 *
 * RTC_NOINIT_ATTR memory is not zeroed by the startup code on a software
 * reset, so whichever crumb was set last before a panic is still readable once
 * the device comes back. That turns "it reboots when I toggle BLE" into a
 * named line of code without a serial console attached, which matters here
 * because this device is updated from SD and normally runs untethered — and
 * because panic output over TinyUSB CDC does not reliably escape the chip.
 *
 * The trail is latched lazily on first use, so no boot hook is needed. */

enum : uint16_t {
    MKC_NONE                = 0x0000,

    /* tool_detect: begin/stop */
    MKC_TD_BEGIN            = 0x1001,
    MKC_TD_STOP_ENTER       = 0x1002,
    MKC_TD_STOP_SCAN_STOP   = 0x1003,
    MKC_TD_STOP_BLE_DEINIT  = 0x1004,
    MKC_TD_STOP_PROMISC     = 0x1005,
    MKC_TD_STOP_DONE        = 0x1006,
    MKC_TD_TRACKS           = 0x1007,

    /* tool_detect: BLE bring-up, step by step */
    MKC_TD_BLE_DEINIT       = 0x1008,
    MKC_TD_BLE_SETTLE       = 0x1009,
    MKC_TD_BLE_INIT         = 0x100A,
    MKC_TD_BLE_REGCB        = 0x100B,
    MKC_TD_BLE_SCANPARAMS   = 0x100C,
    MKC_TD_BLE_READY        = 0x100D,

    /* tool_detect: inside the GAP callback */
    MKC_TD_GAP_PARAM_CPL    = 0x100E,
    MKC_TD_GAP_START_CPL    = 0x100F,
    MKC_TD_GAP_RESULT       = 0x1010,
    MKC_TD_GAP_PARSE        = 0x1011,
    MKC_TD_GAP_TRACK        = 0x1012,
    MKC_TD_GAP_STOP_CPL     = 0x1013,

    /* tool_detect: WiFi mode + steady state */
    MKC_TD_WIFI_BEGIN       = 0x1014,
    MKC_TD_LOOP             = 0x1015,
};

/* Drop a crumb. Safe from an ISR or a critical section: a single 16-bit store
 * to RTC RAM, no locks, no allocation. */
void mk_crumb_set(uint16_t id);

/* The crumb that was current when the device last went down, or MKC_NONE if
 * this was a clean power-on. */
uint16_t mk_crumb_last(void);

/* esp_reset_reason() captured at the first call into this module. */
uint8_t mk_crumb_reset_reason(void);

/* Short label for a crumb id, e.g. "ble_init". Never null. */
const char* mk_crumb_name(uint16_t id);

/* Short label for a reset reason, e.g. "panic". Never null. */
const char* mk_crumb_reset_name(uint8_t reason);
