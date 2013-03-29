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
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "connector_api.h"
#include "platform.h"

extern connector_callback_status_t app_data_service_handler(connector_request_id_data_service_t const request,
                                                  void * const data);

extern connector_callback_status_t app_firmware_handler(connector_firmware_request_t const request,
                                                  void * const data);

extern connector_status_t app_send_put_request(connector_handle_t handle);

connector_bool_t app_connector_reconnect(connector_class_id_t const class_id, connector_close_status_t const status)
{
    UNUSED_ARGUMENT(class_id);

    connector_bool_t type;

    switch (status)
    {
           /* if either the server or our application cuts the connection, don't reconnect */
        case connector_close_status_device_terminated:
        case connector_close_status_device_stopped:
        case connector_close_status_abort:
             type = connector_false;
             break;

       /* otherwise it's an error and we want to retry */
       default:
             type = connector_true;
             break;
    }

    return type;
}

connector_callback_status_t app_connector_callback(connector_class_id_t const class_id,
                                                   connector_request_id_t const request_id,
                                                   void * const data)
{
    connector_callback_status_t   status = connector_callback_continue;

    switch (class_id)
    {
    case connector_class_id_config:
        status = app_config_handler(request_id.config_request, data);
        break;

    case connector_class_id_operating_system:
        status = app_os_handler(request_id.os_request, data);
        break;

    case connector_class_id_network_tcp:
        status = app_network_tcp_handler(request_id.network_request, data);
        break;

    case connector_class_id_data_service:
        status = app_data_service_handler(request_id.firmware_request, data);
        break;

    case connector_class_firmware:
        status = app_firmware_handler(request_id.firmware_request, data);
        break;

    case connector_class_id_status:
        status = app_status_handler(request_id.status_request, data);
        break;

    default:
        /* not supported */
        break;
    }
    return status;
}

int application_run(connector_handle_t handle)
{
    unsigned int const sleep_time_in_seconds = (1 * 1000000);
    int stop_calling = 0;
    extern int start_put_request;

    while(!start_put_request)
        usleep(sleep_time_in_seconds);

    for (;;)
    {
        connector_status_t const status = app_send_put_request(handle);

        usleep(sleep_time_in_seconds);
        if (status != connector_init_error)
        {
            stop_calling = 1;
            break;
        }
    }

    return stop_calling;
}

