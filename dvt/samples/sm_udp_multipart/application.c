/*
 * Copyright (c) 2013 Digi International Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 * Digi International Inc. 11001 Bren Road East, Minnetonka, MN 55343
 * =======================================================================
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "connector_api.h"
#include "platform.h"

char * sm_dvt_random_buffer = NULL;
size_t sm_dvt_buffer_size = 0;

extern connector_callback_status_t app_data_service_handler(connector_request_id_data_service_t const request, void * const data);
extern connector_callback_status_t app_sm_handler(connector_request_id_sm_t const request, void * const data);

extern connector_status_t app_send_ping(connector_handle_t handle);
extern connector_status_t app_send_data(connector_handle_t handle);

connector_bool_t app_connector_reconnect(connector_class_id_t const class_id, connector_close_status_t const status)
{
    connector_bool_t type;

    UNUSED_ARGUMENT(class_id);

    switch (status)
    {
           /* if either Device Cloud or our application cuts the connection, don't reconnect */
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
                                                   void * const data, void * const context)
{
    connector_callback_status_t   status = connector_callback_unrecognized;

    UNUSED_ARGUMENT(context);

    switch (class_id)
    {
    case connector_class_id_config:
        status = app_config_handler(request_id.config_request, data);
        break;

    case connector_class_id_operating_system:
        status = app_os_handler(request_id.os_request, data);
        break;

#if defined CONNECTOR_TRANSPORT_TCP
    case connector_class_id_network_tcp:
        status = app_network_tcp_handler(request_id.network_request, data);
        break;
#endif

    case connector_class_id_network_udp:
        status = app_network_udp_handler(request_id.network_request, data);
        break;

    case connector_class_id_data_service:
        status = app_data_service_handler(request_id.data_service_request, data);
        break;

    case connector_class_id_status:
        status = app_status_handler(request_id.status_request, data);
        break;

    case connector_class_id_short_message:
        status = app_sm_handler(request_id.sm_request, data);
        break;

    default:
        /* not supported */
        break;
    }

    return status;
}

#define RANDOM_FILE_MAX_SIZE   (12 * 1024)
//#define SOURCE_PATH  "../../cases/test_files/random.txt"
#define SOURCE_PATH  "dvt/cases/test_files/random.txt"

int application_run(connector_handle_t handle)
{
    int return_status = 1;
    unsigned int const ping_interval_in_seconds = 4;
    typedef connector_status_t (* send_fn_t)(connector_handle_t handle);
    send_fn_t const send_fn[] = {app_send_ping, app_send_data};
    size_t const send_fn_count = ARRAY_SIZE(send_fn);
    size_t message_count = 0;
    FILE * fp = fopen(SOURCE_PATH, "r");

    if (fp == NULL)
    {
        APP_DEBUG("ERROR: Failed to open %s in sm multipart test\n", SOURCE_PATH);
        goto done;
    }

    sm_dvt_random_buffer = malloc(RANDOM_FILE_MAX_SIZE);
    if (sm_dvt_random_buffer == NULL)
    {
        APP_DEBUG("ERROR: Failed to malloc buffer to store random file in sm multipart test\n");
        goto done;
    }

    sm_dvt_buffer_size = fread(sm_dvt_random_buffer, 1, RANDOM_FILE_MAX_SIZE, fp);
    if ((feof(fp) == 0) || (ferror(fp) != 0))
    {
        APP_DEBUG("Failed to read %s\n", SOURCE_PATH);
    }
    else
    {
        APP_DEBUG("Read %" PRIsize " bytes\n", sm_dvt_buffer_size);
    }
    fclose(fp);
    fp = NULL;

    sleep(ping_interval_in_seconds);
    while (1)
    {
        connector_status_t const status = send_fn[message_count % send_fn_count](handle);

        switch (status)
        {
            case connector_init_error:
            case connector_unavailable:
                break;

            case connector_success:
                message_count++;
                break;

            case connector_service_busy:
                sleep(1);
                break;

            default:
                goto done;
        }

        sleep(ping_interval_in_seconds);
    }

done:
    if (sm_dvt_random_buffer != NULL)
    {
        free(sm_dvt_random_buffer);
        sm_dvt_random_buffer = NULL;
    }

    if (fp != NULL)
        fclose(fp);

    return return_status;
}

