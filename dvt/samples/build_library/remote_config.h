/*
 * This is an auto-generated file - DO NOT EDIT! 
 * This is a public header file generated by RCI Generator tool.
 * This file was generated on: 2014/07/11 11:49:25 
 * The command line arguments were: "spastor1:***** "Linux Application" 1.0.0.1-type=global_header  config.rci"
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

#define CONNECTOR_BINARY_RCI_SERVICE
#define RCI_PARSER_USES_ERROR_DESCRIPTIONS
#define RCI_PARSER_USES_STRING
#define RCI_PARSER_USES_MULTILINE_STRING
#define RCI_PARSER_USES_PASSWORD
#define RCI_PARSER_USES_INT32
#define RCI_PARSER_USES_UINT32
#define RCI_PARSER_USES_HEX32
#define RCI_PARSER_USES_0X_HEX32
#define RCI_PARSER_USES_FLOAT
#define RCI_PARSER_USES_ENUM
#define RCI_PARSER_USES_ON_OFF
#define RCI_PARSER_USES_BOOLEAN
#define RCI_PARSER_USES_IPV4
#define RCI_PARSER_USES_FQDNV4
#define RCI_PARSER_USES_FQDNV6
#define RCI_PARSER_USES_MAC_ADDR
#define RCI_PARSER_USES_DATETIME
#define RCI_PARSER_USES_UNSIGNED_INTEGER
#define RCI_PARSER_USES_STRINGS


#include "float.h"

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
    connector_element_type_hex32,
    connector_element_type_0x_hex32,
    connector_element_type_float,
    connector_element_type_enum,
    connector_element_type_on_off = 11,
    connector_element_type_boolean,
    connector_element_type_ipv4,
    connector_element_type_fqdnv4,
    connector_element_type_fqdnv6,
    connector_element_type_mac_addr = 21,
    connector_element_type_datetime
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
    float min_value;
    float max_value;
} connector_element_value_float_t;

typedef struct {
    size_t count;
} connector_element_value_enum_t;


typedef union {
    char const * string_value;
    int32_t signed_integer_value;
    uint32_t unsigned_integer_value;
    float float_value;
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


#undef CONST
#if (defined CONNECTOR_CONST_STORAGE)
#define CONST CONNECTOR_CONST_STORAGE
#undef CONNECTOR_CONST_STORAGE
#endif


#endif
