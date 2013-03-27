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

#if (defined CONNECTOR_DEBUG)

#define enum_to_case(name)  case name:  result = #name;             break

void connector_debug_hexvalue(char * label, uint8_t * buff, size_t length)
{
    size_t i;

    connector_debug_printf("%s = ", label);
    for (i=0; i<length; i++)
    {
        connector_debug_printf(" %02X", buff[i]);
        if (i > 0 && (i % 16) == 0)
        {
            connector_debug_printf("\n%.*s", (strlen(label)+3), " ");
        }
    }
    connector_debug_printf("\n");
}

#else
#define connector_debug_hexvalue(label, start, length)

static void connector_debug_printf(char const * const format, ...)
{
    (void) format;
}

#endif

#if (defined CONNECTOR_DEBUG)

static char const * transport_status_to_string(connector_transport_t const value)
{
    char const * result = NULL;
    switch (value)
    {
        enum_to_case(connector_transport_tcp);
        enum_to_case(connector_transport_udp);
        enum_to_case(connector_transport_sms);
        enum_to_case(connector_transport_all);
    }
    return result;
}
#else

#define transport_status_to_string(value)       NULL
#endif

