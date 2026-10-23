# Hardware

## Board

- **Model**: Waveshare ESP32-C5-Touch-LCD-3.5
- **SoC**: ESP32-C5HR8 (RISC-V, dual-band Wi-Fi 6 802.11ax, BLE 5, 802.15.4)
- **Memory**: 32 MB flash, 8 MB PSRAM
- **Display**: 3.5" 320×480 IPS, ST7796 via SPI
- **Touch**: FT6336 capacitive, I²C
- **Audio**: ES8311 I²S codec
- **Camera**: BF3901 (DVP)
- **PMU**: AXP2101
- **IMU**: QMI8658
- **RTC**: PCF85063
- **Sensor**: SHTC3
- **Storage**: microSD via SPI (SDSPI), **shared with the LCD**
- **Interface**: USB-C native USB / USB-Serial/JTAG

## Key connections

The vendored BSP in `components/waveshare__esp32_c5_touch_lcd_3_5/` is the authoritative pin map. The important board-level relationships are:

- **IO expander (CH32V003)**: owns LCD reset, touch reset, and backlight PWM. `bsp_io_expander_init()` **must** run before `bsp_display_start()` or the FT6336 will not ACK.
- **Display**: ST7796 on SPI2. The build uses a 60 MHz LCD SPI clock, 80-pixel draw-buffer slices, and a two-entry transaction queue.
- **Touch**: FT6336 on the BSP I²C bus (I²C0, fast mode). Reset is routed through the IO expander.
- **microSD**: SDSPI on the same SPI2 host as the LCD. The card is mounted at 10 MHz and all web/PCAP SD I/O is serialized against display flushes.
- **USB**: native USB-Serial/JTAG is the console and CLI transport. On Linux it is normally `/dev/ttyACM0`.
- **Power**: AXP2101 PMU; the board also exposes battery and power-path controls. See the Waveshare schematic for the exact rail assignments.
- **Audio/camera/IMU/RTC/sensor**: initialized by the BSP only when their respective APIs are used; `pwni` does not currently start the audio, camera, IMU, RTC, or SHTC3 paths.

## Bring-up order (`main/app_main.c`)

1. `nvs_flash_init()` (erase and re-init on version/page errors)
2. `bsp_io_expander_init()`
3. `capture_init()` — mounts microSD before LVGL starts, so the first panel flush is not competing with a mount
4. `bsp_display_start()` + `bsp_display_backlight_on()` — ST7796, LVGL adapter, touch registration
5. `pwn_wifi_start()` — STA mode, promiscuous sniffer, recon task, hopping
6. `net_init()` — station manager, NVS credentials, autoconnect
7. `web_start()` — HTTP server on port 80
8. `pet_init()` — loads the brain/policy from NVS
9. `ui_init()` — builds the face and the SCAN/LOOT/SET screens
10. `cli_start()` — USB-Serial/JTAG CLI task
11. Main loop calls `pet_tick()` every 100 ms

## Display

- 320×480 portrait, RGB565, LVGL 9.
- The display adapter allocates draw buffers in PSRAM. The build sets `CONFIG_BSP_LCD_BUFFER_HEIGHT=80`, `CONFIG_BSP_LCD_TRANS_QUEUE_DEPTH=2`, and `CONFIG_BSP_LCD_SPI_CLOCK_HZ=60000000`.
- Backlight is controlled through the IO expander/PWM. The settings slider writes 10–100% and the web API exposes `/api/brightness`.
- The panel is used at `ESP_LV_ADAPTER_ROTATE_0`.

## Touch

- **Controller**: FT6336, I²C address per the BSP.
- **Mode**: polling from the LVGL input callback. The interrupt line is deliberately **not** used (`int_gpio_num = GPIO_NUM_NC`); it is unreliable on this board and polling at ~30 Hz is cheap.
- **Gesture mode**: disabled after init. The FT6336 driver enables gesture mode by default, which stops normal touch-point reporting; `esp_lcd_touch_ft6336_set_gesture_enabled(false)` fixes that.
- **Orientation**: the touch panel is mounted in the same 320×480 portrait orientation as the LCD. The raw controller range is 320×480 and requires **no swap and no mirror**:

```c
.touch_flags = {
    .swap_xy = 0,
    .mirror_x = 0,
    .mirror_y = 0
}
```

The boot log confirms the active configuration:

```text
esp32_c5_touch_lcd_3_5: Touch ready: raw 320x480 swap=0 mirror_x=0 mirror_y=0
esp_lvgl:touch: Touch input device registered successfully (IRQ mode: disabled)
```

If a different panel revision is rotated, change the flags and the `x_max`/`y_max` selection in `bsp_touch_new()`. The generic `esp_lcd_touch` layer applies `mirror_x`/`mirror_y` **before** `swap_xy`, so `x_max`/`y_max` must describe the raw (pre-swap) range. The LVGL adapter follows the display rotation. Use `touchtest` from the CLI to print the transformed coordinates; on the stock panel the FACE button centre is approximately `(44, 453)`.

## microSD

- SDSPI on SPI2, shared with the LCD.
- Mount frequency: **10 MHz** (`host.max_freq_khz = 10000`). 20 MHz was marginal on this board; multi-block writes sometimes returned `EIO`.
- FATFS with long filenames (255). A 32 GB SDHC card has been tested.
- Mount/config:
  - mount point `/sdcard`
  - captures in `/sdcard/handshakes/`
  - allocation unit 16 KB
  - no format-on-failure
- The mount probes a write and close. If the card is missing, read-only, or failing, `s_sd_ready` stays false, the UI reports `sd: false`, and captures remain in RAM. The web **SET** page shows free/total space and has a **Remount SD** button.
- PCAPs are written atomically (temp + rename); writes are limited to PMKID/complete handshakes. Large slot/AP tables live in PSRAM so the CLI and HTTP tasks keep internal RAM.
- `capture_bus_lock()` / `capture_bus_unlock()` serialize SD I/O against LVGL flush operations. The web PCAP download and capture writes use the same lock.

## Clocks and power

- CPU: 240 MHz (the stable default; no CPU overclock is applied).
- Flash: 80 MHz QIO (`CONFIG_ESPTOOLPY_FLASHFREQ_80M`), 32 MB.
- PSRAM: quad, 80 MHz (`CONFIG_SPIRAM_SPEED_80M`), required for the LVGL draw buffers and capture tables.
- The 120 MHz flash/PSRAM options are explicitly disabled for stability.
- Compiler optimization is `-O2` (`CONFIG_COMPILER_OPTIMIZATION_PERF`), size optimization off.

## Notes and failure modes

- **Touch reset**: if the IO expander is not initialized first, the FT6336 does not ACK and the display may stay dark. The bring-up order above is mandatory.
- **SPI contention**: mounting or writing SD while LVGL is flushing the panel can stall the bus and trip the task watchdog. SD is mounted before LVGL and all later access is bus-locked.
- **PSRAM**: the 320×480 UI and the sniffer/capture buffers assume PSRAM. A build without it will not have enough internal RAM.
- **USB console**: the CLI uses the native USB-Serial/JTAG driver. If the port disappears, reset the board and reopen `/dev/ttyACM0`.
- **Active deauth**: stock ESP-IDF blocks raw deauth frames on the C5. This workspace applies the one-instruction `libnet80211.a` patch; see [C5_DEAUTH.md](C5_DEAUTH.md). Deauth runs as an 8-second burst so clients cannot immediately reassociate; reapply the patch after any ESP-IDF update.
- **No mDNS**: the web UI is reachable only by IP address, printed in the boot log and shown on the `SET` screen.
