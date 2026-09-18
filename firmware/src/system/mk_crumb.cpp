#include "mk_crumb.h"

#include <esp_attr.h>
#include <esp_system.h>

namespace {

constexpr uint32_t MAGIC = 0x4D4B4342;   /* "MKCB" */

/* Not .bss: RTC_NOINIT_ATTR is what makes this readable after a panic. */
RTC_NOINIT_ATTR uint32_t s_magic;
RTC_NOINIT_ATTR uint16_t s_crumb;

uint16_t s_last   = MKC_NONE;
uint8_t  s_reason = 0;
bool     s_armed  = false;

/* Latch the previous boot's trail before anything overwrites it. Called from
 * every entry point so there is no ordering requirement on the caller. */
inline void arm()
{
    if (s_armed) return;
    s_armed = true;
    s_reason = (uint8_t)esp_reset_reason();
    if (s_magic == MAGIC) {
        s_last = s_crumb;          /* RTC RAM survived: trust the crumb */
    } else {
        s_magic = MAGIC;           /* cold boot: RTC RAM was garbage */
        s_last  = MKC_NONE;
    }
    s_crumb = MKC_NONE;
}

} // namespace

void mk_crumb_set(uint16_t id)
{
    arm();
    s_crumb = id;
}

uint16_t mk_crumb_last(void)
{
    arm();
    return s_last;
}

uint8_t mk_crumb_reset_reason(void)
{
    arm();
    return s_reason;
}

const char* mk_crumb_name(uint16_t id)
{
    switch (id) {
        case MKC_NONE:               return "-";
        case MKC_TD_BEGIN:           return "td_begin";
        case MKC_TD_STOP_ENTER:      return "stop_enter";
        case MKC_TD_STOP_SCAN_STOP:  return "gap_scan_stop";
        case MKC_TD_STOP_BLE_DEINIT: return "stop_deinit";
        case MKC_TD_STOP_PROMISC:    return "stop_promisc";
        case MKC_TD_STOP_DONE:       return "stop_done";
        case MKC_TD_TRACKS:          return "alloc_tracks";
        case MKC_TD_BLE_DEINIT:      return "ble_deinit";
        case MKC_TD_BLE_SETTLE:      return "ble_settle";
        case MKC_TD_BLE_INIT:        return "ble_init";
        case MKC_TD_BLE_REGCB:       return "ble_reg_cb";
        case MKC_TD_BLE_SCANPARAMS:  return "ble_scanparams";
        case MKC_TD_BLE_READY:       return "ble_ready";
        case MKC_TD_GAP_PARAM_CPL:   return "gap_param_cpl";
        case MKC_TD_GAP_START_CPL:   return "gap_start_cpl";
        case MKC_TD_GAP_RESULT:      return "gap_result";
        case MKC_TD_GAP_PARSE:       return "gap_parse";
        case MKC_TD_GAP_TRACK:       return "gap_track";
        case MKC_TD_GAP_STOP_CPL:    return "gap_stop_cpl";
        case MKC_TD_WIFI_BEGIN:      return "wifi_begin";
        case MKC_TD_LOOP:            return "td_loop";
        default:                     return "?";
    }
}

const char* mk_crumb_reset_name(uint8_t reason)
{
    switch (reason) {
        case ESP_RST_POWERON:  return "poweron";
        case ESP_RST_EXT:       return "ext";
        case ESP_RST_SW:        return "sw";
        case ESP_RST_PANIC:     return "PANIC";
        case ESP_RST_INT_WDT:   return "int_wdt";
        case ESP_RST_TASK_WDT:  return "task_wdt";
        case ESP_RST_WDT:       return "wdt";
        case ESP_RST_DEEPSLEEP: return "deepsleep";
        case ESP_RST_BROWNOUT:  return "BROWNOUT";
        case ESP_RST_SDIO:      return "sdio";
        default:                return "unknown";
    }
}
