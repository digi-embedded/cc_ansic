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

#include <stdlib.h>
#include "connector_api.h"
#include "platform.h"

/* supported target name */
static char const device_request_target[] = "myTarget";

static char const device_response_data[] = "My device response data";

typedef struct device_request_handle {
    void * device_handle;
    char const * response_data;
    char const * target;
    size_t length_in_bytes;
} device_request_handle_t;

static unsigned int device_request_active_count = 0;

static connector_callback_status_t app_process_device_request(connector_data_service_msg_request_t const * const request_data,
                                                      connector_data_service_msg_response_t * const response_data)
{
    connector_data_service_device_request_t * const server_device_request = request_data->service_context;
    connector_data_service_block_t * const server_data = request_data->server_data;

    device_request_handle_t * client_device_request = response_data->user_context;

    if (server_data == NULL)
    {
        APP_DEBUG("app_process_device_request: server_data is NULL\n");
        goto done;
    }

    if ((server_data->flags & CONNECTOR_MSG_FIRST_DATA) == CONNECTOR_MSG_FIRST_DATA)
    {
        /* target should not be null on 1st chunk of data */
        if (server_device_request->target == NULL)
        {
            APP_DEBUG("app_process_device_request: NULL target\n");
            goto done;
        }

        if (strcmp(server_device_request->target, device_request_target) != 0)
        {
            /* unsupported target so let's cancel it */
            response_data->message_status = connector_msg_error_cancel;
            goto done;
        }

        /* 1st chunk of device request so let's allocate memory for it
         * and setup user_context for the client_device_request.
         */
        {
            void * ptr;

            ptr = malloc(sizeof *client_device_request);
            if (ptr == NULL)
            {
                /* no memeory so cancel this request */
                APP_DEBUG("app_process_device_request: malloc fails for device request on session %p\n", server_device_request->device_handle);
                response_data->message_status = connector_msg_error_memory;
                goto done;
            }

            client_device_request = ptr;
        }
        client_device_request->length_in_bytes = 0;
        client_device_request->response_data = NULL;
        client_device_request->device_handle = server_device_request->device_handle;
        client_device_request->target = device_request_target;

         /* setup the user_context for our device request data */
         response_data->user_context = client_device_request;
         device_request_active_count++;
    }
    else
    {
        /* device request should be our user_context */
        if (client_device_request == NULL)
        {
            APP_DEBUG("app_process_device_request: NULL client_device_request\n");
            goto done;
        }
    }

    {
        /* prints device request data */
        char * device_request_data = server_data->data;
        if (client_device_request->target != NULL)
        {
            /* target is only available on 1st chunk of data */
            APP_DEBUG("Device request data: received data = \"%.*s\" for target = \"%s\"\n", (int)server_data->length_in_bytes,
                    device_request_data, client_device_request->target);
        }
        else
        {
            APP_DEBUG("Device request data: received data = \"%.*s\" for unknown target\n", (int)server_data->length_in_bytes,
                    device_request_data);

        }
    }

    if ((server_data->flags & CONNECTOR_MSG_LAST_DATA) == CONNECTOR_MSG_LAST_DATA)
    {   /* No more chunk */
        /* setup response data for this target */
        client_device_request->response_data = device_response_data;
        client_device_request->length_in_bytes = strlen(client_device_request->response_data);
    }

done:
    return connector_callback_continue;
}

static connector_callback_status_t app_process_device_response(connector_data_service_msg_request_t const * const request_data,
                                                       connector_data_service_msg_response_t * const response_data)
{
    device_request_handle_t * const client_device_request = response_data->user_context;

    UNUSED_ARGUMENT(request_data);

    if ((response_data->client_data == NULL) || (client_device_request == NULL))
    {
        APP_DEBUG("app_process_device_response: invalid input\n");
        goto error;
    }

    {
        connector_data_service_block_t * const client_data = response_data->client_data;
        /* get number of bytes written to the client data buffer */
        size_t const bytes = (client_device_request->length_in_bytes < client_data->length_in_bytes) ? client_device_request->length_in_bytes : client_data->length_in_bytes;

        APP_DEBUG("Device response data: send response data = %.*s\n", (int)bytes, client_device_request->response_data);

        /* let's copy the response data to service_response buffer */
        memcpy(client_data->data, client_device_request->response_data, bytes);
        client_device_request->response_data += bytes;
        client_device_request->length_in_bytes -= bytes;

        client_data->length_in_bytes = bytes;
        client_data->flags = (client_device_request->length_in_bytes == 0) ? CONNECTOR_MSG_LAST_DATA : 0;
        if (client_device_request->target == NULL)
        {
            client_data->flags |= CONNECTOR_MSG_DATA_NOT_PROCESSED;
        }
    }

    response_data->message_status = connector_msg_error_none;

    if (client_device_request->length_in_bytes == 0)
    {   /* done */
        device_request_active_count--;
        free(client_device_request);
    }

error:
    return connector_callback_continue;
}

static connector_callback_status_t app_process_device_error(connector_data_service_msg_request_t const * const request_data,
                                                    connector_data_service_msg_response_t * const response_data)
{
    device_request_handle_t * const client_device_request = response_data->user_context;
    connector_data_service_block_t * error_data = request_data->server_data;
    connector_msg_error_t const error_code = *((connector_msg_error_t *)error_data->data);


    APP_DEBUG("app_process_device_error: handle %p error %d from server\n",
                client_device_request->device_handle, error_code);

    device_request_active_count--;
    free(client_device_request);

    return connector_callback_continue;
}

connector_callback_status_t app_data_service_handler(connector_data_service_request_t const request,
                                                      void const * const request_data, size_t const request_length,
                                                      void * response_data, size_t * const response_length)
{
    connector_callback_status_t status = connector_callback_continue;
    connector_data_service_msg_request_t const * const service_device_request = request_data;

    UNUSED_ARGUMENT(request_length);
    UNUSED_ARGUMENT(response_length);

    if (request == connector_data_service_device_request)
    {
        switch (service_device_request->message_type)
        {
        case connector_data_service_type_have_data:
            status = app_process_device_request(request_data, response_data);
            break;
        case connector_data_service_type_need_data:
            status = app_process_device_response(request_data, response_data);
            break;
        case connector_data_service_type_error:
            status = app_process_device_error(request_data, response_data);
            break;
        default:
            APP_DEBUG("app_data_service_handler: unknown message type %d for connector_data_service_device_request\n", service_device_request->message_type);
            break;
        }
    }
    else
    {
        APP_DEBUG("Unsupported %d  (Only support connector_data_service_device_request)\n", request);
    }

    return status;
}

