/*
 * Copyright (c) 2014 Digi International Inc.
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

#include <ucos_ii.h> 
#include <lib_mem.h>
#include "os_support.h"
#include "platform.h"
#include "connector_debug.h"

#include  <stdarg.h>

unsigned long start_system_up_time = 0;

int connector_snprintf(char * const str, size_t const size, char const * const format, ...)
{
    va_list args;
    int result;

    va_start(args, format);

#if __STDC_VERSION__ >= 199901L
    result = vsnprintf(str, size, format, args);
#else
    /*************************************************************************
     * NOTE: Decided to have 64 bytes here considering following assumption  *
     * 1. In the worst case, only one format specifier will be used.         *
     * 2. Maximum of 48 bytes are used to represent a single precision value *
     *************************************************************************/
    #define SAFE_BUFFER_BYTES 64

    if (size >= SAFE_BUFFER_BYTES)
    {
        result = vsprintf(str, format, args);
    }
    else
    {
        char local_buffer[SAFE_BUFFER_BYTES];
        size_t const bytes_needed = vsprintf(local_buffer, format, args);

        result = (bytes_needed < size) ? bytes_needed : size - 1;
        memcpy(str, local_buffer, result);
        str[result] = '\0';
        result = bytes_needed;
    }
    #undef SAFE_BUFFER_BYTES
#endif
    va_end(args);

    return result;
}

static connector_callback_status_t app_os_malloc(size_t const size, void ** ptr)
{
    connector_callback_status_t status = connector_callback_abort;
    
    *ptr = ecc_malloc(size); 

    if (*ptr != NULL)
        status = connector_callback_continue;

    return status;
}

static connector_callback_status_t app_os_free(void * const ptr)
{
    connector_callback_status_t status = connector_callback_abort;

    ASSERT(ptr != NULL);
    if (ptr != NULL)
    {
        ecc_free (ptr);
        status = connector_callback_continue;
    }
    return status;
}


connector_callback_status_t app_os_get_system_time(unsigned long * const uptime)
{
#if (OS_VERSION >= 287u)
    INT32U curr_tick;
#else
    INT16U curr_tick;
#endif
      
    curr_tick = OSTimeGet();

    if (start_system_up_time == 0)
        start_system_up_time = curr_tick;
    
    /* Up time in seconds */
    *uptime = (curr_tick - start_system_up_time) / OS_TICKS_PER_SEC;

    return connector_callback_continue;
}

static connector_callback_status_t app_os_yield(connector_status_t const * const status)
{
#if (OS_VERSION >= 287u)
    INT32U timeout_in_ticks;
#else
    INT16U timeout_in_ticks;
#endif
 
    /* OSTimeDly: If the specified delay is greater than 0
       then, a context switch will result  
    */
    timeout_in_ticks = 1;   

#if 0
    if (*status == connector_idle)
    {
        /* Sleep longer in this case?  */
        timeout_in_ticks = OS_TICKS_PER_SEC * 1;  /* 1 second */
    }
#endif
    
    OSTimeDly(timeout_in_ticks);
          
    return connector_callback_continue;
}

connector_callback_status_t app_os_delay(unsigned short const timeout_in_milliseconds)
{   
#if (OS_VERSION >= 287u)
    INT32U timeout_in_ticks;
#else
    INT16U timeout_in_ticks;
#endif
    
    timeout_in_ticks = timeout_in_milliseconds * 1000 / OS_TICKS_PER_SEC;
    
    OSTimeDly(timeout_in_ticks);
          
    return connector_callback_continue;
}

static connector_callback_status_t app_os_reboot(void)
{

    APP_DEBUG("Reboot from server\n");
    
    ecc_software_reset();
    
    return connector_callback_continue;
}

connector_callback_status_t app_os_handler(connector_request_id_os_t const request, void * const data)
{
    connector_callback_status_t status;

    switch (request)
    {
    case connector_request_id_os_malloc:
        {
            connector_os_malloc_t * p = data;
            status = app_os_malloc(p->size, &p->ptr);
        }
        break;

    case connector_request_id_os_free:
        {
            connector_os_free_t * p = data;
            status = app_os_free(p->ptr);
        }
        break;

    case connector_request_id_os_system_up_time:
        {
            connector_os_system_up_time_t * p = data;
            status = app_os_get_system_time(&p->sys_uptime);
        }
        break;

    case connector_request_id_os_yield:
        {
            connector_os_yield_t * p = data;
            status = app_os_yield(&p->status);
        }
        break;

    case connector_request_id_os_reboot:
        status = app_os_reboot();
        break;

    default:
        APP_DEBUG("app_os_handler: unrecognized request [%d]\n", request);
        status = connector_callback_unrecognized;
        break;
    }

    return status;
}





