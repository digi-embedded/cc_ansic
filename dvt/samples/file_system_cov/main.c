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

#include <pthread.h>
#include <unistd.h>
#include "connector_api.h"
#include "platform.h"

static void * connector_run_thread(void * arg)
{

    APP_DEBUG("connector_run thread starts\n");

    for (;;)
    {
        connector_status_t const status = connector_run(arg);

        APP_DEBUG("connector_run returns %d\n", status);

        if (status != connector_open_error) break;
    }


    APP_DEBUG("connector_run thread exits\n");

    pthread_exit(arg);
}

static void * application_run_thread(void * arg)
{
    int status;

    APP_DEBUG("application_run thread starts\n");

    status = application_run(arg);

    APP_DEBUG("application_run thread exits %d\n", status);

    pthread_exit(arg);
}

int main (void)
{
    while (1)
    {
        pthread_t connector_thread;

        pthread_t application_thread;

        connector_handle_t connector_handle;

        APP_DEBUG("Start Connector\n");
        connector_handle = connector_init(app_connector_callback, NULL);

        if (connector_handle != NULL)
        {
            int ccode = pthread_create(&connector_thread, NULL, connector_run_thread, connector_handle);
            if (ccode != 0)
            {
                APP_DEBUG("thread_create() error on connector_run_thread %d\n", ccode);
                goto done;
            }

            ccode = pthread_create(&application_thread, NULL, application_run_thread, connector_handle);
            if (ccode != 0)
            {
                APP_DEBUG("thread_create() error on application_run_thread %d\n", ccode);
                goto done;
            }

            pthread_join(connector_thread, NULL);
            pthread_join(application_thread, NULL);
            APP_DEBUG("Cloud Connector terminated\n");
            sleep(2);
        }
        else
        {
            APP_DEBUG("Unable to initialize the connector\n");
            goto done;
        }
    }
done:
    return 0;
}
