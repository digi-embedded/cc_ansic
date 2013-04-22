/*
 * Copyright (c) 2012 Digi International Inc.,
 * All rights not expressly granted are reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Digi International Inc. 11001 Bren Road East, Minnetonka, MN 55343
 * =======================================================================
 */

#ifndef _PLATFORM_H
#define _PLATFORM_H

#include "connector_api.h"

#define APP_DEBUG   log_printf

#define UNUSED_ARGUMENT(x)     ((void)x)

/* Callbacks for this platform */
connector_callback_status_t app_os_handler(connector_request_id_os_t const request, void * const data);
connector_callback_status_t app_network_tcp_handler(connector_request_id_network_t const request_id, void * const data);
connector_callback_status_t app_config_handler(connector_request_id_config_t const request_id, void * const data);
#if defined (CONNECTOR_RCI_SERVICE)
connector_callback_status_t app_remote_config_handler(connector_request_id_remote_config_t const request_id, void * const data);
#endif
int application_run(connector_handle_t handle);
extern connector_callback_status_t app_get_vendor_id(uint8_t const ** const id, size_t * const size);
extern connector_callback_status_t app_get_device_type(char const ** const type, size_t * const size);
extern connector_callback_status_t app_custom_get_device_id(uint8_t const ** const id, size_t * const size);
connector_callback_status_t app_get_mac_addr(connector_config_pointer_data_t * const config_mac);
/* TODO: Following three prototypes doesn't belong in this file */
extern void Flash_NVRAM_get_mac_address(uint8_t * const address);
extern void Flash_NVRAM_set_mac_address(uint8_t * const address);
extern unsigned long ic_create_task(unsigned long const index_number, unsigned long const parameter);
extern unsigned long ic_destroy_task(unsigned long const task_id);

#endif /* _PLATFORM_H */
