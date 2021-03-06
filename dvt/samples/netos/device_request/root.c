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
 
     printf("connector_run thread starts\n");
 
     /* Run the iDigi Connector, this will only return on an iDigi Connector abort */
     status = connector_run(arg);
 
     printf("connector_run thread exits %d\n", status);
    
     return (void *) status;
}

/*
 *
 *  Function: void applicationStart (void)
 *
 *  Description:
 *
 *      This routine is responsible for starting the user application.  It should 
 *      create any threads or other resources the application needs.
 *
 *      ThreadX, the NET+OS device drivers, and the TCP/IP stack will be running
 *      when this function is called.
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

void applicationStart (void)

{
    connector_handle_t connector_handle;

    /* start FTP server */
    //naFtpDlInit(NA_FTP_DEF_USERS);

    connector_handle = connector_init(app_connector_callback);

    if (connector_handle == NULL)
        printf("connector_init error\n"); 
    else
        connector_run_thread(connector_handle);

}



