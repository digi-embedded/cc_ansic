/*
 * Copyright (c) 2013 Digi International Inc.,
 * All rights not expressly granted are reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Digi International Inc. 11001 Bren Road East, Minnetonka, MN 55343
 * =======================================================================
 */
#include  "remote_config.h"

#include "connector_api.h"



#define CONST const 
#define FIRMWARE_TARGET_ZERO_VERSION  0x1000000

#define CONNECTOR_RCI_ERROR_BAD_COMMAND (connector_remote_all_strings+0)
#define CONNECTOR_RCI_ERROR_BAD_DESCRIPTOR (connector_remote_all_strings+12)
#define SETTING_SERIAL_ERROR_INVALID_BAUD (connector_remote_all_strings+30)
#define SETTING_SERIAL_ERROR_INVALID_DATABITS (connector_remote_all_strings+49)
#define SETTING_SERIAL_ERROR_INVALID_PARITY (connector_remote_all_strings+67)
#define SETTING_SERIAL_ERROR_INVALID_XBREAK (connector_remote_all_strings+83)
#define SETTING_SERIAL_ERROR_INVALID_DATABITS_PARITY (connector_remote_all_strings+106)
#define SETTING_ETHERNET_ERROR_INVALID_DUPLEX (connector_remote_all_strings+150)
#define SETTING_ETHERNET_ERROR_INVALID_IP (connector_remote_all_strings+182)
#define SETTING_ETHERNET_ERROR_INVALID_SUBNET (connector_remote_all_strings+201)
#define SETTING_ETHERNET_ERROR_INVALID_GATEWAY (connector_remote_all_strings+221)
#define SETTING_ETHERNET_ERROR_INVALID_DNS (connector_remote_all_strings+245)
#define SETTING_DEVICE_TIME_ERROR_INVALID_TIME (connector_remote_all_strings+265)
#define STATE_DEVICE_STATE_ERROR_INVALID_INTEGER (connector_remote_all_strings+278)
#define CONNECTOR_GLOBAL_ERROR_LOAD_FAIL (connector_remote_all_strings+300)
#define CONNECTOR_GLOBAL_ERROR_SAVE_FAIL (connector_remote_all_strings+310)
#define CONNECTOR_GLOBAL_ERROR_MEMORY_FAIL (connector_remote_all_strings+320)

char CONST connector_remote_all_strings[] = {
 11,'B','a','d',' ','c','o','m','m','a','n','d',
 17,'B','a','d',' ','c','o','n','f','i','g','u','r','a','t','i','o','n',
 18,'I','n','v','a','l','i','d',' ','b','a','u','d',' ','r','a','t','e',' ',
 17,'I','n','v','a','l','i','d',' ','d','a','t','a',' ','b','i','t','s',
 15,' ','I','n','v','a','l','i','d',' ','p','a','r','i','t','y',
 22,'I','n','v','a','l','i','d',' ','x','b','r','e','a','k',' ','s','e','t','t','i','n','g',
 43,'I','n','v','a','l','i','d',' ','c','o','m','b','i','n','a','t','i','o','n',' ','o','f',' ','d','a','t','a',' ','b','i','t','s',' ','a','n','d',' ','p','a','r','i','t','y',
 31,'I','n','v','a','l','i','d',' ','e','t','h','e','r','n','e','t',' ','d','u','p','l','e','x',' ','s','e','t','t','i','n','g',
 18,'I','n','v','a','l','i','d',' ','I','P',' ','a','d','d','r','e','s','s',
 19,'I','n','v','a','l','i','d',' ','s','u','b','n','e','t',' ','m','a','s','k',
 23,'I','n','v','a','l','i','d',' ','g','a','t','e','w','a','y',' ','a','d','d','r','e','s','s',
 19,'I','n','v','a','l','i','d',' ','D','N','S',' ','a','d','d','r','e','s','s',
 12,'I','n','v','a','l','i','d',' ','t','i','m','e',
 21,'I','n','v','a','l','i','d',' ','i','n','t','e','g','e','r',' ','v','a','l','u','e',
 9,'L','o','a','d',' ','f','a','i','l',
 9,'S','a','v','e',' ','f','a','i','l',
 19,'I','n','s','u','f','f','i','c','i','e','n','t',' ','m','e','m','o','r','y'
};

static char const * const connector_rci_errors[] = {
 CONNECTOR_RCI_ERROR_BAD_COMMAND, /*bad_command*/
 CONNECTOR_RCI_ERROR_BAD_DESCRIPTOR, /*bad_descriptor*/
 CONNECTOR_GLOBAL_ERROR_LOAD_FAIL, /*load_fail*/
 CONNECTOR_GLOBAL_ERROR_SAVE_FAIL, /*save_fail*/
 CONNECTOR_GLOBAL_ERROR_MEMORY_FAIL /*memory_fail*/
};

static connector_group_element_t CONST setting_serial_elements[] = {
 {  /*baud*/
   connector_element_access_read_write,
   connector_element_type_enum
 },
 {  /*parity*/
   connector_element_access_read_write,
   connector_element_type_enum
 },
 {  /*databits*/
   connector_element_access_read_write,
   connector_element_type_uint32
 },
 {  /*xbreak*/
   connector_element_access_read_write,
   connector_element_type_on_off
 },
 {  /*txbytes*/
   connector_element_access_read_only,
   connector_element_type_uint32
 }
};

static char CONST * CONST setting_serial_errors[] = {
 SETTING_SERIAL_ERROR_INVALID_BAUD, /*invalid_baud*/
 SETTING_SERIAL_ERROR_INVALID_DATABITS, /*invalid_databits*/
 SETTING_SERIAL_ERROR_INVALID_PARITY, /*invalid_parity*/
 SETTING_SERIAL_ERROR_INVALID_XBREAK, /*invalid_xbreak*/
 SETTING_SERIAL_ERROR_INVALID_DATABITS_PARITY /*invalid_databits_parity*/
};

static connector_group_element_t CONST setting_ethernet_elements[] = {
 {  /*ip*/
   connector_element_access_read_write,
   connector_element_type_ipv4
 },
 {  /*subnet*/
   connector_element_access_read_write,
   connector_element_type_ipv4
 },
 {  /*gateway*/
   connector_element_access_read_write,
   connector_element_type_ipv4
 },
 {  /*dhcp*/
   connector_element_access_read_write,
   connector_element_type_boolean
 },
 {  /*dns*/
   connector_element_access_read_write,
   connector_element_type_fqdnv4
 },
 {  /*duplex*/
   connector_element_access_read_write,
   connector_element_type_enum
 }
};

static char CONST * CONST setting_ethernet_errors[] = {
 SETTING_ETHERNET_ERROR_INVALID_DUPLEX, /*invalid_duplex*/
 SETTING_ETHERNET_ERROR_INVALID_IP, /*invalid_ip*/
 SETTING_ETHERNET_ERROR_INVALID_SUBNET, /*invalid_subnet*/
 SETTING_ETHERNET_ERROR_INVALID_GATEWAY, /*invalid_gateway*/
 SETTING_ETHERNET_ERROR_INVALID_DNS /*invalid_dns*/
};

static connector_group_element_t CONST setting_device_time_elements[] = {
 {  /*curtime*/
   connector_element_access_read_write,
   connector_element_type_datetime
 }
};

static char CONST * CONST setting_device_time_errors[] = {
 SETTING_DEVICE_TIME_ERROR_INVALID_TIME /*invalid_time*/
};

static connector_group_element_t CONST setting_device_info_elements[] = {
 {  /*version*/
   connector_element_access_read_only,
   connector_element_type_0x_hex32
 },
 {  /*product*/
   connector_element_access_read_write,
   connector_element_type_string
 },
 {  /*model*/
   connector_element_access_read_write,
   connector_element_type_string
 },
 {  /*company*/
   connector_element_access_read_write,
   connector_element_type_string
 },
 {  /*desc*/
   connector_element_access_read_write,
   connector_element_type_multiline_string
 }
};

static connector_group_element_t CONST setting_system_elements[] = {
 {  /*description*/
   connector_element_access_read_write,
   connector_element_type_string
 },
 {  /*contact*/
   connector_element_access_read_write,
   connector_element_type_string
 },
 {  /*location*/
   connector_element_access_read_write,
   connector_element_type_string
 }
};

static connector_group_element_t CONST setting_devicesecurity_elements[] = {
 {  /*identityVerificationForm*/
   connector_element_access_read_write,
   connector_element_type_enum
 },
 {  /*password*/
   connector_element_access_write_only,
   connector_element_type_password
 }
};

static connector_group_t CONST connector_setting_groups[] = {
 {  /*serial*/
   2 , /* instances */
   { asizeof(setting_serial_elements),
     setting_serial_elements
   },
   { asizeof(setting_serial_errors),
     setting_serial_errors
   }  /* errors*/
}
,
 {  /*ethernet*/
   1 , /* instances */
   { asizeof(setting_ethernet_elements),
     setting_ethernet_elements
   },
   { asizeof(setting_ethernet_errors),
     setting_ethernet_errors
   }  /* errors*/
}
,
 {  /*device_time*/
   1 , /* instances */
   { asizeof(setting_device_time_elements),
     setting_device_time_elements
   },
   { asizeof(setting_device_time_errors),
     setting_device_time_errors
   }  /* errors*/
}
,
 {  /*device_info*/
   1 , /* instances */
   { asizeof(setting_device_info_elements),
     setting_device_info_elements
   },
   { 0,
     NULL
   }  /* errors*/
}
,
 {  /*system*/
   1 , /* instances */
   { asizeof(setting_system_elements),
     setting_system_elements
   },
   { 0,
     NULL
   }  /* errors*/
}
,
 {  /*devicesecurity*/
   1 , /* instances */
   { asizeof(setting_devicesecurity_elements),
     setting_devicesecurity_elements
   },
   { 0,
     NULL
   }  /* errors*/
}

};

static connector_group_element_t CONST state_device_state_elements[] = {
 {  /*system_up_time*/
   connector_element_access_read_only,
   connector_element_type_uint32
 },
 {  /*signed_integer*/
   connector_element_access_read_write,
   connector_element_type_int32
 }
};

static char CONST * CONST state_device_state_errors[] = {
 STATE_DEVICE_STATE_ERROR_INVALID_INTEGER /*invalid_integer*/
};

static connector_group_element_t CONST state_gps_stats_elements[] = {
 {  /*latitude*/
   connector_element_access_read_only,
   connector_element_type_string
 },
 {  /*longitude*/
   connector_element_access_read_only,
   connector_element_type_string
 }
};

static connector_group_t CONST connector_state_groups[] = {
 {  /*device_state*/
   1 , /* instances */
   { asizeof(state_device_state_elements),
     state_device_state_elements
   },
   { asizeof(state_device_state_errors),
     state_device_state_errors
   }  /* errors*/
}
,
 {  /*gps_stats*/
   1 , /* instances */
   { asizeof(state_gps_stats_elements),
     state_gps_stats_elements
   },
   { 0,
     NULL
   }  /* errors*/
}

};

static connector_remote_group_table_t CONST connector_group_table[] = {
 { connector_setting_groups,
   asizeof(connector_setting_groups)
 },
 { connector_state_groups,
   asizeof(connector_state_groups)
 }
};


connector_remote_config_data_t rci_desc_data = {
    connector_group_table,
    connector_rci_errors,
    connector_rci_error_COUNT,
    FIRMWARE_TARGET_ZERO_VERSION,
    0x30000DB,
    "Linux Application"
};