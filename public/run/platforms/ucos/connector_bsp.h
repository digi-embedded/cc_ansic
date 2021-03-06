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
#ifndef _CONNECTOR_BSP_H
#define _CONNECTOR_BSP_H

/* Connector BSP functions */
void connector_BSP_debug_printf(char const * const format, ...);
void Connector_BSP_software_reset(void);
void Connector_BSP_Serial_Read_Str(char *p_str, unsigned short len);
void Connector_BSP_LED_On(unsigned char led);
void Connector_BSP_LED_Off(unsigned char led);
void Connector_BSP_LED_Toggle(unsigned char led);
unsigned char Connector_BSP_Status_Read(unsigned char id);

/* Dynamic configuration of some Connector parameters */
connector_error_t connector_config(void);

/* This delay abstraction let sample application work for both uCOS-II and uCOS-III */
connector_callback_status_t app_os_delay(unsigned short const timeout_in_milliseconds); 

#endif