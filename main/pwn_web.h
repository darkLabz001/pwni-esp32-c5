#pragma once

#include <stdbool.h>
#include "esp_err.h"

/* HTTP dashboard. Starts listening on port 80; reachable once the station
 * has an IP. */
esp_err_t web_start(void);
void web_stop(void);

/* Manual GitHub OTA (same as the Settings button). Requires authorization. */
esp_err_t web_ota_github_start(void);

/* True while a GitHub OTA is running. The UI keeps the backlight on so the
 * progress/status screen stays readable until the device reboots. */
bool web_ota_busy(void);
