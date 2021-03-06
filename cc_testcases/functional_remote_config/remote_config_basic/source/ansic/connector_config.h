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
#ifndef __CONNECTOR_CONFIG_H_
#define __CONNECTOR_CONFIG_H_

#define CONNECTOR_LITTLE_ENDIAN
#define CONNECTOR_DEBUG
/* #define CONNECTOR_FIRMWARE_SERVICE */
/* #define CONNECTOR_COMPRESSION */
/* #define CONNECTOR_DATA_SERVICE */
// #define CONNECTOR_FILE_SYSTEM
#define CONNECTOR_RCI_SERVICE
#define CONNECTOR_TRANSPORT_TCP
/* #define CONNECTOR_TRANSPORT_UDP */
/* #define CONNECTOR_TRANSPORT_SMS */

#define CONNECTOR_NO_MALLOC_RCI_MAXIMUM_CONTENT_LENGTH    256
#define CONNECTOR_FILE_SYSTEM_MAX_PATH_LENGTH   256
/* #define CONNECTOR_FILE_SYSTEM_HAS_LARGE_FILES  */

/* #define CONNECTOR_NO_MALLOC */
#define CONNECTOR_NO_MALLOC_MAX_SEND_SESSIONS 1

#ifdef ENABLE_COMPILE_TIME_DATA_PASSING
#define CONNECTOR_DEVICE_TYPE                          "Linux Cloud Connector Sample"
#define CONNECTOR_CLOUD_URL                            "devicecloud.digi.com"
#define CONNECTOR_TX_KEEPALIVE_IN_SECONDS              90
#define CONNECTOR_RX_KEEPALIVE_IN_SECONDS              60
#define CONNECTOR_WAIT_COUNT                           5
#define CONNECTOR_VENDOR_ID                            0x00000000
#define CONNECTOR_MSG_MAX_TRANSACTION                  1
#define CONNECTOR_CONNECTION_TYPE                      connector_connection_type_lan
#define CONNECTOR_WAN_LINK_SPEED_IN_BITS_PER_SECOND    0
#define CONNECTOR_WAN_PHONE_NUMBER_DIALED              "012345678"
#define CONNECTOR_FIRMWARE_SUPPORT
#define CONNECTOR_DATA_SERVICE_SUPPORT
#define CONNECTOR_FILE_SYSTEM_SUPPORT
#define CONNECTOR_REMOTE_CONFIGURATION_SUPPORT

#define CONNECTOR_DEVICE_ID_METHOD                      connector_device_id_method_auto
#define CONNECTOR_NETWORK_TCP_START                     connector_connect_auto
#define CONNECTOR_NETWORK_UDP_START                     connector_connect_auto
#define CONNECTOR_NETWORK_SMS_START                     connector_connect_auto
#define CONNECTOR_WAN_TYPE                              connector_wan_type_imei
#define CONNECTOR_IDENTITY_VERIFICATION                 connector_identity_verification_simple

#endif

#endif
