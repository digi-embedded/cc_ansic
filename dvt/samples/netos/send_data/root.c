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
#include <stdlib.h>
#include <tx_api.h>
#include <fservapi.h>

#include <pthread.h>
#include <connector_api.h>
#include "platform.h"


/*
 *
 *  Function: void applicationTcpDown (void)
 *
 *  Description:
 *
 *      This routine will be called by the NET+OS root thread once every 
 *      clock tick while it is waiting for the TCP/IP stack to come up.  
 *      This function can increment a counter everytime it's called to 
 *      keep track of how long we've been waiting for the stack to start.
 *      If we've been waiting too long, then this function can do something
 *      to handle the error.  
 *
 *      This function will not be called once the stack has started.
 *
 *  Parameters:
 *
 *      none
 *
 *  Return Values:
 *
 *      none
 *
 */

void applicationTcpDown (void)

{
    static int ticksPassed = 0;

    ticksPassed++;
/*
 * Code to handle error condition if the stack doesn't come up goes here.
 */
}

static void * connector_run_thread(void * arg)
{
    connector_status_t status;

    APP_DEBUG("connector_run thread starts\n");

    status = connector_run(arg);

    APP_DEBUG("connector_run thread exits %d\n", status);

    return arg;
}

static void * application_run_thread(void * arg)
{
    int status;

    APP_DEBUG("connector_run thread starts\n");

    status = application_run((connector_handle_t)arg);

    APP_DEBUG("application_run thread exits %d\n", status);

    return arg;
}

void applicationStart (void)
{
    pthread_t connector_thread;
    pthread_t application_thread;

    connector_handle_t connector_handle;

    /* start FTP server */
    //naFtpDlInit(NA_FTP_DEF_USERS);

    APP_DEBUG("Start iDigi\n");
    connector_handle = connector_init(app_connector_callback);

    if (connector_handle != NULL)
    {
        int ccode;
        ccode = pthread_create(&connector_thread, NULL, connector_run_thread, connector_handle);
        if (ccode != 0)
        {
            APP_DEBUG("pthread_create() error on connector_process_thread %d\n", ccode);
            goto done;
        }

        ccode = pthread_create(&application_thread, NULL, application_run_thread, connector_handle);
        if (ccode != 0)
        {
            APP_DEBUG("pthread_create() error on connector_process_thread %d\n", ccode);
            goto done;
        }
    }
    else
    {
        printf("unable to initialize iDigi\n");
    }
done:
    return;
}




