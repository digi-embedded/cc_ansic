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
#include "connector_api.h"
#include "platform.h"
#include "connector_debug.h"
#include "remote_config_cb.h"

#if !defined CONNECTOR_RCI_SERVICE
#error "Must define CONNECTOR_RCI_SERVICE in connector_config.h to run this sample"
#endif

connector_callback_status_t app_remote_config_handler(connector_request_id_remote_config_t const request_id,
                                                      void * const data)
{
    connector_callback_status_t status = connector_callback_continue;

    UNUSED_ARGUMENT(data);

    switch (request_id)
    {
    case connector_request_id_remote_config_session_start:
    case connector_request_id_remote_config_session_end:
    case connector_request_id_remote_config_action_start:
    case connector_request_id_remote_config_action_end:
    case connector_request_id_remote_config_group_start:
    case connector_request_id_remote_config_group_end:
    case connector_request_id_remote_config_group_process:
    case connector_request_id_remote_config_session_cancel:
        break;
    default:
        ASSERT(0);
        break;
    }

    return status;
}

