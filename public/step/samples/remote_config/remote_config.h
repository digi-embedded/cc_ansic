/*
 * This is an auto-generated file - DO NOT EDIT! 
 * This is generated by RCI Generator tool 
 * This file was generated on: 2014/07/08 12:48:00 
 * The command line arguments were: "spastor1:***** "Linux Application" 1.0.0.0 config.rci"
 * The version of RCI Generator tool was: 2.0.0.0 */

#ifndef remote_config_h
#define remote_config_h



#include "connector_api.h"


#if (defined CONNECTOR_CONST_PROTECTION)
#define CONST
#undef CONNECTOR_CONST_PROTECTION
#else
#if (defined CONST)
#define CONNECTOR_CONST_STORAGE CONST
#undef CONST
#endif
#define CONST const
#endif

#define RCI_PARSER_USES_ERROR_DESCRIPTIONS
#define RCI_PARSER_USES_STRING
#define RCI_PARSER_USES_MULTILINE_STRING
#define RCI_PARSER_USES_PASSWORD
#define RCI_PARSER_USES_INT32
#define RCI_PARSER_USES_UINT32
#define RCI_PARSER_USES_0X_HEX32
#define RCI_PARSER_USES_ENUM
#define RCI_PARSER_USES_ON_OFF
#define RCI_PARSER_USES_BOOLEAN
#define RCI_PARSER_USES_IPV4
#define RCI_PARSER_USES_FQDNV4
#define RCI_PARSER_USES_DATETIME
#define RCI_PARSER_USES_UNSIGNED_INTEGER
#define RCI_PARSER_USES_STRINGS

typedef enum {
    connector_off,
    connector_on
} connector_on_off_t;


typedef enum {
    connector_element_type_string = 1,
    connector_element_type_multiline_string,
    connector_element_type_password,
    connector_element_type_int32,
    connector_element_type_uint32,
    connector_element_type_0x_hex32 = 7,
    connector_element_type_enum = 9,
    connector_element_type_on_off = 11,
    connector_element_type_boolean,
    connector_element_type_ipv4,
    connector_element_type_fqdnv4,
    connector_element_type_datetime = 22
} connector_element_value_type_t;

typedef struct {
    size_t min_length_in_bytes;
    size_t max_length_in_bytes;
} connector_element_value_string_t;

typedef struct {
   int32_t min_value;
   int32_t max_value;
} connector_element_value_signed_integer_t;

typedef struct {
   uint32_t min_value;
   uint32_t max_value;
} connector_element_value_unsigned_integer_t;

typedef struct {
    size_t count;
} connector_element_value_enum_t;


typedef union {
    char const * string_value;
    int32_t signed_integer_value;
    uint32_t unsigned_integer_value;
    unsigned int enum_value;
    connector_on_off_t  on_off_value;
    connector_bool_t  boolean_value;
} connector_element_value_t;

typedef struct rci_data {
 unsigned int group_index;
 connector_remote_action_t action;
 connector_remote_group_type_t group_type;
 char const * error_hint;
 void * user_context;
} rci_info_t;

typedef connector_callback_status_t (*rci_function_t)(rci_info_t * const info, ...);

typedef struct {
    connector_element_access_t access;
    connector_element_value_type_t type;
} connector_group_element_t;

typedef struct {
  size_t instances;
  struct {
      size_t count;
      connector_group_element_t CONST * CONST data;
  } elements;

  struct {
      size_t count;
      char CONST * CONST * description;
  } errors;

} connector_group_t;

typedef struct {
  connector_remote_group_type_t type;
  unsigned int id;
  unsigned int index;
} connector_remote_group_t;

typedef struct {
  unsigned int id;
  connector_element_value_type_t type;
  connector_element_value_t * value;
} connector_remote_element_t;

typedef struct {
  void * user_context;
  connector_remote_action_t CONST action;
  connector_remote_group_t CONST group;
  connector_remote_element_t CONST element;
  unsigned int error_id;

  union {
      char const * error_hint;
      connector_element_value_t * element_value;
  } response;
} connector_remote_config_t;

typedef struct {
  void * user_context;
} connector_remote_config_cancel_t;

typedef struct connector_remote_group_table {
  connector_group_t CONST * groups;
  size_t count;
} connector_remote_group_table_t;


typedef enum {
 connector_rci_error_not_available = -1,
 connector_rci_error_OFFSET = 1,
 connector_rci_error_bad_command =  connector_rci_error_OFFSET,
 connector_rci_error_bad_descriptor,
 connector_rci_error_COUNT
} connector_rci_error_id_t;


typedef enum {
 connector_global_error_OFFSET = connector_rci_error_COUNT,
 connector_global_error_load_fail =  connector_global_error_OFFSET,
 connector_global_error_save_fail,
 connector_global_error_memory_fail,
 connector_global_error_COUNT
} connector_global_error_id_t;

typedef enum {
 connector_setting_serial_baud_2400,
 connector_setting_serial_baud_4800,
 connector_setting_serial_baud_9600,
 connector_setting_serial_baud_19200,
 connector_setting_serial_baud_38400,
 connector_setting_serial_baud_57600,
 connector_setting_serial_baud_115200,
 connector_setting_serial_baud_230400,
 connector_setting_serial_baud_COUNT
} connector_setting_serial_baud_id_t;

typedef enum {
 connector_setting_serial_parity_none,
 connector_setting_serial_parity_odd,
 connector_setting_serial_parity_even,
 connector_setting_serial_parity_COUNT
} connector_setting_serial_parity_id_t;

typedef enum {
 connector_setting_serial_baud,
 connector_setting_serial_parity,
 connector_setting_serial_databits,
 connector_setting_serial_xbreak,
 connector_setting_serial_txbytes,
 connector_setting_serial_COUNT
} connector_setting_serial_id_t;

typedef enum {
 connector_setting_serial_error_bad_command = 1, /* Protocol defined */
 connector_setting_serial_error_bad_descriptor,
 connector_setting_serial_error_load_fail, /* User defined (global errors) */
 connector_setting_serial_error_save_fail,
 connector_setting_serial_error_memory_fail,
 connector_setting_serial_error_invalid_baud,  /* User defined (group errors)*/
 connector_setting_serial_error_invalid_databits,
 connector_setting_serial_error_invalid_parity,
 connector_setting_serial_error_invalid_xbreak,
 connector_setting_serial_error_invalid_databits_parity,
 connector_setting_serial_error_COUNT
} connector_setting_serial_error_id_t;

typedef enum {
 connector_setting_ethernet_duplex_auto,
 connector_setting_ethernet_duplex_half,
 connector_setting_ethernet_duplex_full,
 connector_setting_ethernet_duplex_COUNT
} connector_setting_ethernet_duplex_id_t;

typedef enum {
 connector_setting_ethernet_ip,
 connector_setting_ethernet_subnet,
 connector_setting_ethernet_gateway,
 connector_setting_ethernet_dhcp,
 connector_setting_ethernet_dns,
 connector_setting_ethernet_duplex,
 connector_setting_ethernet_COUNT
} connector_setting_ethernet_id_t;

typedef enum {
 connector_setting_ethernet_error_bad_command = 1, /* Protocol defined */
 connector_setting_ethernet_error_bad_descriptor,
 connector_setting_ethernet_error_load_fail, /* User defined (global errors) */
 connector_setting_ethernet_error_save_fail,
 connector_setting_ethernet_error_memory_fail,
 connector_setting_ethernet_error_invalid_duplex,  /* User defined (group errors)*/
 connector_setting_ethernet_error_invalid_ip,
 connector_setting_ethernet_error_invalid_subnet,
 connector_setting_ethernet_error_invalid_gateway,
 connector_setting_ethernet_error_invalid_dns,
 connector_setting_ethernet_error_COUNT
} connector_setting_ethernet_error_id_t;

typedef enum {
 connector_setting_device_time_curtime,
 connector_setting_device_time_COUNT
} connector_setting_device_time_id_t;

typedef enum {
 connector_setting_device_time_error_bad_command = 1, /* Protocol defined */
 connector_setting_device_time_error_bad_descriptor,
 connector_setting_device_time_error_load_fail, /* User defined (global errors) */
 connector_setting_device_time_error_save_fail,
 connector_setting_device_time_error_memory_fail,
 connector_setting_device_time_error_invalid_time,  /* User defined (group errors)*/
 connector_setting_device_time_error_COUNT
} connector_setting_device_time_error_id_t;

typedef enum {
 connector_setting_device_info_version,
 connector_setting_device_info_product,
 connector_setting_device_info_model,
 connector_setting_device_info_company,
 connector_setting_device_info_desc,
 connector_setting_device_info_COUNT
} connector_setting_device_info_id_t;

typedef enum {
 connector_setting_system_description,
 connector_setting_system_contact,
 connector_setting_system_location,
 connector_setting_system_COUNT
} connector_setting_system_id_t;

typedef enum {
 connector_setting_devicesecurity_identityVerificationForm_simple,
 connector_setting_devicesecurity_identityVerificationForm_password,
 connector_setting_devicesecurity_identityVerificationForm_COUNT
} connector_setting_devicesecurity_identityVerificationForm_id_t;

typedef enum {
 connector_setting_devicesecurity_identityVerificationForm,
 connector_setting_devicesecurity_password,
 connector_setting_devicesecurity_COUNT
} connector_setting_devicesecurity_id_t;

typedef enum {
 connector_setting_serial,
 connector_setting_ethernet,
 connector_setting_device_time,
 connector_setting_device_info,
 connector_setting_system,
 connector_setting_devicesecurity,
 connector_setting_COUNT
} connector_setting_id_t;

typedef enum {
 connector_state_device_state_system_up_time,
 connector_state_device_state_signed_integer,
 connector_state_device_state_COUNT
} connector_state_device_state_id_t;

typedef enum {
 connector_state_device_state_error_bad_command = 1, /* Protocol defined */
 connector_state_device_state_error_bad_descriptor,
 connector_state_device_state_error_load_fail, /* User defined (global errors) */
 connector_state_device_state_error_save_fail,
 connector_state_device_state_error_memory_fail,
 connector_state_device_state_error_invalid_integer,  /* User defined (group errors)*/
 connector_state_device_state_error_COUNT
} connector_state_device_state_error_id_t;

typedef enum {
 connector_state_gps_stats_latitude,
 connector_state_gps_stats_longitude,
 connector_state_gps_stats_COUNT
} connector_state_gps_stats_id_t;

typedef enum {
 connector_state_device_state,
 connector_state_gps_stats,
 connector_state_COUNT
} connector_state_id_t;


extern connector_remote_config_data_t rci_desc_data;


#undef CONST
#if (defined CONNECTOR_CONST_STORAGE)
#define CONST CONNECTOR_CONST_STORAGE
#undef CONNECTOR_CONST_STORAGE
#endif


#endif
