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

#ifndef CONNECTOR_EDP_DEF_H_
#define CONNECTOR_EDP_DEF_H_

#include "ei_packet.h"

#define MSG_MAX_RECV_PACKET_SIZE 1600
#define MSG_MAX_SEND_PACKET_SIZE 512

#define EDP_MT_VERSION      2

#define DEVICE_TYPE_LENGTH  32
#define CONNECTOR_MAX_TRANSACTIONS_LIMIT    255

/* these are limits for Tx and Rx keepalive
 * interval in seconds.
 */
#define MIN_TX_KEEPALIVE_INTERVAL_IN_SECONDS     5
#define MAX_TX_KEEPALIVE_INTERVAL_IN_SECONDS     7200
#define MIN_RX_KEEPALIVE_INTERVAL_IN_SECONDS     5
#define MAX_RX_KEEPALIVE_INTERVAL_IN_SECONDS     7200

/* Limits for wait count (number of
 * keepalive packets)
 */
#define WAIT_COUNT_MIN      2
#define WAIT_COUNT_MAX      64

/*
 * MT version 2 message type defines.
 * Refer to EDP specification rev. 14.2 for a description of MT version 2.
 */
#define E_MSG_MT2_TYPE_VERSION              0x0004U /* C -> S */
#define E_MSG_MT2_TYPE_LEGACY_EDP_VERSION   0x0004U /* C -> S */
#define E_MSG_MT2_TYPE_LEGACY_EDP_VER_RESP  0x0001U /* C <- S */
#define E_MSG_MT2_TYPE_VERSION_OK           0x0010U /* C <- S */
#define E_MSG_MT2_TYPE_VERSION_BAD          0x0011U /* C <- S */
#define E_MSG_MT2_TYPE_SERVER_OVERLOAD      0x0012U /* C <- S */
#define E_MSG_MT2_TYPE_KA_RX_INTERVAL       0x0020U /* C -> S */
#define E_MSG_MT2_TYPE_KA_TX_INTERVAL       0x0021U /* C -> S */
#define E_MSG_MT2_TYPE_KA_WAIT              0x0022U /* C -> S */
#define E_MSG_MT2_TYPE_KA_KEEPALIVE         0x0030U /* bi-directional */
#define E_MSG_MT2_TYPE_PAYLOAD              0x0040U /* bi-directional */

#define URL_PREFIX  "en://"
#define GET_PACKET_DATA_POINTER(p, s)   (uint8_t *)(((uint8_t *)p) + (s))


#if (defined CONNECTOR_TX_KEEPALIVE_IN_SECONDS)
#define GET_TX_KEEPALIVE_INTERVAL(connector_ptr)    CONNECTOR_TX_KEEPALIVE_IN_SECONDS
#else
#define GET_TX_KEEPALIVE_INTERVAL(connector_ptr)    connector_ptr->edp_data.config.tx_keepalive_interval
#endif

#if (defined CONNECTOR_RX_KEEPALIVE_IN_SECONDS)
#define GET_RX_KEEPALIVE_INTERVAL(connector_ptr)    CONNECTOR_RX_KEEPALIVE_IN_SECONDS
#else
#define GET_RX_KEEPALIVE_INTERVAL(connector_ptr)    connector_ptr->edp_data.config.rx_keepalive_interval
#endif

#if (defined CONNECTOR_WAIT_COUNT)
#define GET_WAIT_COUNT(connector_ptr)    CONNECTOR_WAIT_COUNT
#else
#define GET_WAIT_COUNT(connector_ptr)    connector_ptr->edp_data.config.wait_count
#endif

#define MAX_RECEIVE_TIMEOUT_IN_SECONDS  1
#define MIN_RECEIVE_TIMEOUT_IN_SECONDS  0

/* IRL EDP States */
typedef enum {
    edp_communication_connect_server,
    edp_communication_send_version,
    edp_communication_receive_version_response,
    edp_communication_send_keepalive,
    edp_initialization_send_protocol_version,
    edp_initialization_receive_protocol_version,
    edp_security_send_identity_verification,
    edp_security_send_device_id,
    edp_security_send_server_url,
    edp_security_send_password,
    edp_discovery_send_vendor_id,
    edp_discovery_send_device_type,
    edp_discovery_facility,
    edp_discovery_send_complete,
    edp_facility_process

} connector_edp_state_t;

typedef enum {
    facility_callback_delete,
    facility_callback_cleanup
} connector_supported_facility_cb_index_t;

struct connector_data;

typedef connector_status_t (* send_complete_cb_t)(struct connector_data * const connector_ptr, uint8_t const * const packet, connector_status_t const status, void * const user_data);

typedef struct connector_buffer {
    /* this buffer must be FIRST field in the structure
     * since this is used between network interface
     * and all facilities and facilities release the buffer
     * by returning the pointer of the buffer.
     */
    uint8_t buffer[MSG_MAX_RECV_PACKET_SIZE];
    struct connector_buffer * next;
    connector_bool_t    in_use;
} connector_buffer_t;

typedef struct connector_facility {
    unsigned int service_index;
    size_t size;
    connector_buffer_t * packet_buffer;
    void * facility_data;
    struct connector_facility * next;
    struct connector_facility * prev;
    uint16_t facility_num;
} connector_facility_t;

typedef struct connector_edp_data {

    struct {
#if !(defined CONNECTOR_VENDOR_ID)
        uint32_t vendor_id;
#endif

#if !(defined CONNECTOR_DEVICE_TYPE)
        char * device_type;
        size_t device_type_length;
#endif

        uint8_t * ip_addr;
        size_t ip_addr_length;

        char server_url[SERVER_URL_LENGTH];
        size_t server_url_length;

#if !(defined CONNECTOR_IDENTITY_VERIFICATION)
        connector_identity_verification_t identity_verification;
#endif

        char * password;
        size_t password_length;

#if !(defined CONNECTOR_TX_KEEPALIVE_IN_SECONDS)
        uint16_t tx_keepalive_interval;
#endif

#if !(defined CONNECTOR_RX_KEEPALIVE_IN_SECONDS)
        uint16_t rx_keepalive_interval;
#endif

#if !(defined CONNECTOR_WAIT_COUNT)
        uint16_t wait_count;
#endif
    } config;

    struct {
        connector_transport_state_t initiate;
        connector_transport_state_t active;
        connector_edp_state_t edp;
    } state;

    struct {
        struct {
            uint8_t buffer[MSG_MAX_SEND_PACKET_SIZE];
            connector_bool_t in_use;
        } packet_buffer;
        uint8_t * ptr;
        size_t bytes_sent;
        size_t total_length;
        send_complete_cb_t complete_cb;
        void * user_data;
    } send_packet;

    struct {
        connector_buffer_t packet_buffer;
        connector_buffer_t * free_packet_buffer;
        connector_buffer_t * data_packet;
        uint8_t * ptr;
        int index;
        unsigned int timeout;
        uint16_t  packet_type;
        uint16_t  packet_length;
        size_t bytes_received;
        size_t total_length;
    } receive_packet;

    struct {
        connector_facility_t * current;
        connector_facility_t * list;
        uint16_t supported_mask;
    } facilities;

    struct {
        uint8_t send_rx_packet[PACKET_EDP_HEADER_SIZE];
        unsigned long last_rx_sent_time;
        unsigned long last_tx_received_time;
        uint16_t miss_tx_count;
    } keepalive;

    connector_close_status_t  close_status;
    connector_network_handle_t * network_handle;

    struct {
        connector_bool_t is_set;
        connector_stop_condition_t condition;
        void * user_context;
        connector_auto_connect_type_t connect_action;
    } stop;

#if !(defined CONNECTOR_NETWORK_TCP_START)
    connector_auto_connect_type_t  connect_type;
#endif

} connector_edp_data_t;

#endif /* CONNECTOR_EDP_DEF_H_ */
