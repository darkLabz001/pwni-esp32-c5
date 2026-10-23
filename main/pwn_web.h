#pragma once

#include "esp_err.h"

/* HTTP dashboard. Starts listening on port 80; reachable once the station
 * has an IP. */
esp_err_t web_start(void);
void web_stop(void);
