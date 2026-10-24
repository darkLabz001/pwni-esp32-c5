#include <stdio.h>

#include "bsp/esp-bsp.h"
#include "lvgl.h"
#include "nvs_flash.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "pwn_config.h"
#include "pwn_wifi.h"
#include "pwn_capture.h"
#include "pwn_hunt.h"
#include "pwn_pet.h"
#include "pwn_ui.h"
#include "pwn_cli.h"
#include "pwn_net.h"
#include "pwn_web.h"
#include "pwn_watch.h"
#include "pwn_netmeta.h"
#include "pwn_ble.h"
#include "pwn_hid.h"

static const char *TAG = "pwni";

static void nvs_bringup(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
}

void app_main(void)
{
    ESP_LOGI(TAG, "PWNI %s on ESP32-C5", PWN_VERSION);
    ESP_LOGI(TAG, "passive-first sniffer, active attacks runtime gated");

    nvs_bringup();
    watch_init();
    netmeta_init();

    /* The CH32V003 IO expander owns LCD/touch reset and backlight PWM and
     * must be initialised before the panel or the FT6336 will not ACK. */
    ESP_ERROR_CHECK(bsp_io_expander_init());

    /* Mount storage *before* LVGL starts rendering. The SD slot and the LCD
     * share one SPI bus; mounting a card while the first frame is being
     * flushed stalls the panel transaction and trips the task watchdog. */
    capture_init();
    pwn_hunt_init();
    hid_init();

    lv_display_t *disp = bsp_display_start();
    if (!disp) {
        ESP_LOGE(TAG, "display start failed");
    } else {
        bsp_display_backlight_on();
    }

    ESP_ERROR_CHECK(pwn_wifi_start());

    net_init();
    web_start();
    /* BLE is initialised last: it is opt-in, shares the 2.4 GHz radio, and
     * must not delay display/Wi-Fi bring-up. */
    ble_init();

    pet_init();
    if (disp) {
        ui_init();
    }
    cli_start();

    ESP_LOGI(TAG, "wifi pet is awake");

    for (;;) {
        pet_tick();
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}
