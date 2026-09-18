/**
 * @file  mk_psram_buf.h
 * @brief One-time working buffers in PSRAM, for arrays that belong in neither
 *        the stack nor internal RAM.
 *
 * The list/copy-out paths need multi-KB scratch arrays, and both obvious homes
 * are wrong:
 *
 *   - **Stack**: the ELF app runs on the launcher task with roughly 6 KB of
 *     headroom, and these frames nest. ~4 KB of nested arrays hard-reset the
 *     device when scrolling a list.
 *   - **Internal .bss**: moving ~20 KB there fixed the stack overflow but
 *     starved the Bluetooth controller, which needs *internal* heap
 *     specifically. BLE init then reset the device on a mode toggle.
 *
 * PSRAM is 8 MB and otherwise idle, and these are UI-rate buffers where the
 * slower access is irrelevant. Allocated once on first use and never freed —
 * they are singletons by nature.
 *
 * Returns nullptr if the allocation fails; every caller must handle that.
 */
#pragma once
#include <esp_heap_caps.h>
#include <cstddef>

inline void* mk_psram_buf(void** slot, size_t bytes)
{
    if (!*slot) {
        *slot = heap_caps_malloc(bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        /* No PSRAM (or exhausted): fall back to internal rather than fail the
         * feature outright. Small boards would rather lose the RAM than the
         * screen. */
        if (!*slot) *slot = heap_caps_malloc(bytes, MALLOC_CAP_8BIT);
    }
    return *slot;
}
