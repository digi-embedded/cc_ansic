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

#include <mqx.h>
#include <bsp.h>
#include <lwevent.h>
#include <io_gpio.h>
#include "platform.h"
#include "connector.h"

static LWGPIO_STRUCT led1;
static LWGPIO_STRUCT led2;

static void connector_status(connector_error_t const status, char const * const status_message)
{
    APP_DEBUG("idigi_status: status update %d [%s]\n", status, status_message);
}

/*
 * Turn on and off LED outputs
 */
static void set_led_state(LWGPIO_STRUCT * led, boolean state)
{
    if (state)
        lwgpio_set_value(led, LWGPIO_VALUE_LOW); /* set pin to 0 */
    else
        lwgpio_set_value(led, LWGPIO_VALUE_HIGH); /* set pin to 1 */
}

static LWGPIO_STRUCT * get_led_pin(char const * const ledString)
{
    LWGPIO_STRUCT * led = NULL;

    if (!strcmp(ledString, "LED1"))
        led = &led1;
    else if (!strcmp(ledString, "LED2"))
        led = &led2;
    else
    {
        APP_DEBUG("Unknown target [%s]\n", ledString);
    }

    return led;
}

static connector_app_error_t device_request_callback(char const * const target, connector_dataservice_data_t * const request_data)
{
    connector_app_error_t status = connector_app_invalid_parameter;
    LWGPIO_STRUCT * const led = get_led_pin(target);

    if (request_data->error != connector_success)
    {
        APP_DEBUG("devcie_request_callback: target [%s], error [%d]\n", target, request_data->error);
        goto error;
    }

    if (led != NULL)
    {
        char const * const stateStr = request_data->data_ptr;
        boolean const state = (strstr(stateStr, "ON") != NULL) ? TRUE : FALSE;

        APP_DEBUG("Turning %s %s\n", state ? "ON" : "OFF", target);
        set_led_state(led, state);
        status = connector_app_success;
    }
    else
    {
    	status = connector_app_unknown_target;
    }
    
    

error:
    return status;
}

static size_t device_response_callback(char const * const target, connector_dataservice_data_t * const response_data)
{
    LWGPIO_STRUCT * const led = get_led_pin(target);
    char const * const status = (led != NULL) ? "Success" : "Failed";
    size_t bytes_to_copy = strlen(status);

    memcpy(response_data->data_ptr, status, bytes_to_copy);
    response_data->more_data = connector_false;

    APP_DEBUG("%s action is %s\n", target, status);

error:
    return bytes_to_copy;
}


int application_start(void)
{
    connector_dataservice_data_t ic_data;
    connector_error_t ret;
    int status=-1;

    /* Initialize LED's */
    if (lwgpio_init(&led1, BSP_LED1, LWGPIO_DIR_OUTPUT, LWGPIO_VALUE_NOCHANGE) == TRUE)
        lwgpio_set_functionality(&led1, BSP_LED1_MUX_GPIO);

    if (lwgpio_init(&led2, BSP_LED2, LWGPIO_DIR_OUTPUT, LWGPIO_VALUE_NOCHANGE) == TRUE)
        lwgpio_set_functionality(&led2, BSP_LED2_MUX_GPIO);

    APP_DEBUG("application_start: calling connector_start\n");
    ret = connector_start(connector_status);
    if (ret != connector_success)
    {
        APP_DEBUG("connector_start failed [%d]\n", ret);
        goto error;
    }

    APP_DEBUG("application_start: calling connector_register_device_request_callbacks\n");
    ret = connector_register_device_request_callbacks(device_request_callback, device_response_callback, NULL, NULL);
    if (ret != connector_success)
    {
        APP_DEBUG("connector_register_device_request_callbacks failed [%d]\n", ret);
        goto error;
    }

    status = 0;

error:
    return status;

}