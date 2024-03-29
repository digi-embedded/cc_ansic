/*
Copyright 2019, Digi International Inc.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, you can obtain one at http://mozilla.org/MPL/2.0/.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#ifndef CONNECTOR_SM_DEF_H
#define CONNECTOR_SM_DEF_H

#include <limits.h>

#if (defined CONNECTOR_COMPRESSION)
#include "zlib.h"
#endif

#include "ei_packet.h"

#define SM_UDP_VERSION 0x01

#if defined SM_PACKET_SIZE_UDP
#if  defined CONNECTOR_SM_MULTIPART
#error "SM_PACKET_SIZE_UDP cannot be override if multi-packet messaging is ON (defined CONNECTOR_SM_MULTIPART)"
#endif
#else
#define SM_PACKET_SIZE_UDP 1472
#endif

/* Max configurable value for SM_MAX_SESSIONS_LIMIT */
#define CONNECTOR_SM_MAX_SESSIONS_LIMIT 256

/* Max configurable value for SM_MAX_RX_SEGMENTS_LIMIT */
#define CONNECTOR_SM_MAX_RX_SEGMENTS_LIMIT 256

#define SM_PACKET_SIZE_SMS 128
#define SM_PACKET_SIZE_SMS_ENCODED ((SM_PACKET_SIZE_SMS/4) * 5)

/* NOTE: Some of these bits are tied to protocol, so please don't change them
         without referring to SM protocol */
#define SM_ERROR               0x0001
#define SM_LAST_DATA           0x0002
#define SM_MULTI_PART          0x0004
#define SM_RESPONSE_NEEDED     0x0008
#define SM_RESPONSE_DATA       0x0010
#define SM_NEW_KEY             0x0020
#define SM_ENCRYPTED           0x0040
#define SM_COMPRESSED          0x0080
#define SM_REBOOT              0x0100
#define SM_TARGET_IN_PAYLOAD   0x0200
#define SM_SMS_CONFIG_INIT     0x0400
#define SM_CLIENT_OWNED        0x2000
#define SM_ENCODED             0x4000
#define SM_DATA_POINT          0x8000

#define SM_COMMAND_MASK        ((uint8_t) ~(SM_COMPRESSED | SM_ENCRYPTED | SM_NEW_KEY))

#define SmIsBitSet(flag, bit) (connector_bool(((flag) & (bit)) == (bit)))
#define SmIsBitClear(flag, bit) (connector_bool(((flag) & (bit)) == 0))
#define SmBitSet(flag, bit) ((flag) |= (bit))
#define SmBitClear(flag, bit) ((flag) &= ~(bit))

#define SmIsError(flag) SmIsBitSet((flag), SM_ERROR)
#define SmIsResponse(flag) SmIsBitSet((flag), SM_RESPONSE_DATA)
#define SmIsResponseNeeded(flag) SmIsBitSet((flag), SM_RESPONSE_NEEDED)
#define SmIsLastData(flag) SmIsBitSet((flag), SM_LAST_DATA)
#define SmIsMultiPart(flag) SmIsBitSet((flag), SM_MULTI_PART)
#define SmHasNewKey(flag) SmIsBitSet((flag), SM_NEW_KEY)
#define SmIsEncrypted(flag) SmIsBitSet((flag), SM_ENCRYPTED)
#define SmIsCompressed(flag) SmIsBitSet((flag), SM_COMPRESSED)
#define SmIsClientOwned(flag) SmIsBitSet((flag), SM_CLIENT_OWNED)
#define SmIsEncoded(flag) SmIsBitSet((flag), SM_ENCODED)
#define SmIsReboot(flag) SmIsBitSet((flag), SM_REBOOT)
#define SmIsDatapoint(flag) SmIsBitSet((flag), SM_DATA_POINT)
#define SmIsTargetInPayload(flag) SmIsBitSet((flag), SM_TARGET_IN_PAYLOAD)
#define SmIsSmsConfigInit(flag) SmIsBitSet((flag), SM_SMS_CONFIG_INIT)

#define SmIsRequest(flag) SmIsBitClear((flag), SM_RESPONSE_DATA)
#define SmIsNotLastData(flag) SmIsBitClear((flag), SM_LAST_DATA)
#define SmIsNotMultiPart(flag) SmIsBitClear((flag), SM_MULTI_PART)
#define SmIsCloudOwned(flag) SmIsBitClear((flag), SM_CLIENT_OWNED)
#define SmNotEncrypted(flag) SmIsBitClear((flag), SM_ENCRYPTED)
#define SmNotCompressed(flag) SmIsBitClear((flag), SM_COMPRESSED)
#define SmIsNoResponseNeeded(flag) SmIsBitClear((flag), SM_RESPONSE_NEEDED)
#define SmIsSmsConfigNotInit(flag) SmIsBitClear((flag), SM_SMS_CONFIG_INIT)

#define SmSetError(flag) SmBitSet((flag), SM_ERROR)
#define SmSetResponse(flag) SmBitSet((flag), SM_RESPONSE_DATA)
#define SmSetResponseNeeded(flag) SmBitSet((flag), SM_RESPONSE_NEEDED)
#define SmSetLastData(flag) SmBitSet((flag), SM_LAST_DATA)
#define SmSetMultiPart(flag) SmBitSet((flag), SM_MULTI_PART)
#define SmSetEncrypted(flag) SmBitSet((flag), SM_ENCRYPTED)
#define SmSetCompressed(flag) SmBitSet((flag), SM_COMPRESSED)
#define SmSetClientOwned(flag) SmBitSet((flag), SM_CLIENT_OWNED)
#define SmSetEncoded(flag) SmBitSet((flag), SM_ENCODED)
#define SmSetReboot(flag) SmBitSet((flag), SM_REBOOT)
#define SmSetDatapoint(flag) SmBitSet((flag), SM_DATA_POINT)
#define SmSetTargetInPayload(flag) SmBitSet((flag), SM_TARGET_IN_PAYLOAD)
#define SmSetSmsConfigInit(flag) SmBitSet((flag), SM_SMS_CONFIG_INIT)

#define SmClearError(flag) SmBitClear((flag), SM_ERROR)
#define SmClearResponse(flag) SmBitClear((flag), SM_RESPONSE_DATA)
#define SmClearResponseNeeded(flag) SmBitClear((flag), SM_RESPONSE_NEEDED)
#define SmClearLastData(flag) SmBitClear((flag), SM_LAST_DATA)
#define SmClearMultiPart(flag) SmBitClear((flag), SM_MULTI_PART)
#define SmClearEncrypted(flag) SmBitClear((flag), SM_ENCRYPTED)
#define SmClearCompressed(flag) SmBitClear((flag), SM_COMPRESSED)
#define SmClearTargetInPayload(flag) SmBitClear((flag), SM_TARGET_IN_PAYLOAD)
#define SmClearSmsConfigInit(flag) SmBitClear((flag), SM_SMS_CONFIG_INIT)

#define SMS_SERVICEID_WRAPPER_TX_SIZE     1  /* 'service-id '   */
#define SMS_SERVICEID_WRAPPER_RX_SIZE     3  /* '(service-id):' */

#if (defined CONNECTOR_SM_ENCRYPTION)

#define SM_INFO_BYTE_REQUEST_ID_HIGH    0x03    /* high 2-bits of request ID */
#define SM_AAD_INFO_BYTE_MASK           ((uint8_t) ~(SM_MULTI_PART | SM_INFO_BYTE_REQUEST_ID_HIGH))

#define SM_IV_LENGTH    12
#define SM_KEY_LENGTH   16
#define SM_TAG_LENGTH   16
#define SM_AAD_LENGTH   18

#define SM_REQUEST_ID_FIRST 0
#define SM_REQUEST_ID_LAST  1023
#define SM_REQUEST_ID_COUNT (SM_REQUEST_ID_LAST - SM_REQUEST_ID_FIRST + 1)
#define SM_TRACKING_BYTES   ((SM_REQUEST_ID_COUNT + CHAR_BIT - 1) / CHAR_BIT)

#define SM_IV_TYPE_REQUEST      0x00
#define SM_IV_TYPE_RESPONSE     0x80
#define SM_IV_POOL_DEVICE       0x00
#define SM_IV_POOL_SERVER       0x40

typedef struct connector_sm_encryption_key_t
{
    connector_bool_t valid;
    uint8_t key[SM_KEY_LENGTH];
} connector_sm_encryption_key_t;

typedef struct connector_sm_encryption_data_t
{
    connector_sm_encryption_key_t current;
    connector_sm_encryption_key_t previous;
} connector_sm_encryption_data_t;
#else
#define SM_REQUEST_ID_MASK 0x3FF  /* 10 bits */
#endif

typedef enum
{
    connector_sm_cmd_ping,
    connector_sm_cmd_connect,
    connector_sm_cmd_reboot,
    connector_sm_cmd_cli,
    connector_sm_cmd_pack,
    connector_sm_cmd_pad,
    connector_sm_cmd_config,
    connector_sm_cmd_data,
    connector_sm_cmd_no_path_data,
    /* Add new commands here */
    connector_sm_cmd_opaque_response
} connector_sm_cmd_t;

typedef enum
{
    connector_sm_id_type_device_id,
    connector_sm_id_type_imei,
    connector_sm_id_type_none,
    connector_sm_id_type_service_id
} connector_sm_id_type_t;

typedef enum
{
    connector_sm_state_get_total_length,
    connector_sm_state_prepare_payload,
    connector_sm_state_more_data,
    connector_sm_state_compress,
    connector_sm_state_encrypt,
    connector_sm_state_prepare_segment,
    connector_sm_state_encoding,
    connector_sm_state_send_data,
    connector_sm_state_receive_data,
    connector_sm_state_decrypt,
    connector_sm_state_decompress,
    connector_sm_state_process_payload,
    connector_sm_state_complete,
    connector_sm_state_error
} connector_sm_state_t;

typedef enum
{
    connector_sm_error_none,
    connector_sm_error_in_request,
    connector_sm_error_unavailable,
    connector_sm_error_unknown,
    connector_sm_error_complete,
    connector_sm_error_cancel,
    connector_sm_error_timeout,
    connector_sm_error_no_resource
} connector_sm_error_id_t;

typedef struct
{
    uint8_t * data;
    size_t bytes;
} sm_data_block_t;

typedef struct connector_sm_session_t
{
    struct
    {
        void * context;
        void const * header;
    } user;

    connector_transport_t transport;
    connector_sm_state_t sm_state;
    connector_sm_cmd_t command;
    connector_sm_error_id_t error;
    unsigned long start_time;
    uint32_t request_id;
    uint8_t info;
    uint8_t cmd_status;
    uint32_t flags;

    sm_data_block_t in;
    size_t bytes_processed;

#if (defined CONNECTOR_COMPRESSION)
    struct
    {
        z_stream zlib;
        sm_data_block_t out;
    } compress;
#endif

    struct connector_sm_session_t * next;
    struct connector_sm_session_t * prev;

    struct
    {
        uint16_t * size_array;
        size_t count;
        size_t processed;
    } segments;
    unsigned long timeout_in_seconds;
} connector_sm_session_t;

typedef struct connector_sm_packet_t
{
    uint8_t * data;
    size_t total_bytes;
    size_t processed_bytes;
    connector_sm_session_t * pending_session;
} connector_sm_packet_t;

typedef struct connector_sm_data_t
{
    connector_status_t error_code;
    unsigned long rx_timeout_in_seconds;
    unsigned long last_activity;

    struct
    {
        size_t mtu;
        size_t sm_mtu_tx;
        size_t sm_mtu_rx;
        uint8_t const * id;
        size_t id_length;
        connector_sm_id_type_t id_type;
        connector_transport_state_t state;
        connector_connect_auto_type_t connect_type;
        unsigned long int connect_at;
    } transport;

    struct
    {
        connector_close_status_t status;
        connector_stop_condition_t stop_condition;
        void * user_context;
        connector_bool_t callback_needed;
    } close;

    struct
    {
        connector_sm_packet_t send_packet;
        connector_sm_packet_t recv_packet;
        connector_network_handle_t * handle;
        connector_class_id_t class_id;
        connector_transport_t transport;
    } network;

    struct
    {
        void const * data;
        connector_initiate_request_t request;
        uint16_t request_id;
        connector_bool_t pending_internal;
    } pending;

    struct
    {
        connector_sm_session_t * head;
        connector_sm_session_t * tail;
        connector_sm_session_t * current;
        size_t max_sessions;
        size_t active_client_sessions;
        size_t active_cloud_sessions;
        size_t max_segments;
    } session;

    struct
    {
        uint16_t id;
#if (defined CONNECTOR_SM_ENCRYPTION)
         uint8_t tracking[SM_TRACKING_BYTES];
#endif
    } request;

} connector_sm_data_t;

enum sm_segment_t
{
    field_define(segment, info, uint8_t),
    field_define(segment, request, uint8_t),
    field_define(segment, cmd_status, uint8_t),
    field_define(segment, crc, uint16_t),
    record_end(segment)
};

enum sm_segment0_t
{
    field_define(segment0, info, uint8_t),
    field_define(segment0, request, uint8_t),
    field_define(segment0, segment, uint8_t),
    field_define(segment0, count, uint8_t),
    field_define(segment0, cmd_status, uint8_t),
    field_define(segment0, crc, uint16_t),
    record_end(segment0)
};

enum sm_segmentn_t
{
    field_define(segmentn, info, uint8_t),
    field_define(segmentn, request, uint8_t),
    field_define(segmentn, segment, uint8_t),
    field_define(segmentn, crc, uint16_t),
    record_end(segmentn)
};

#endif
