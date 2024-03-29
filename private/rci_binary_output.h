/*
 * Copyright (c) 2018 Digi International Inc.
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

#if (defined RCI_PARSER_USES_LIST)
#define SHOULD_OUTPUT(rci)  (get_list_depth(rci) < (rci)->output.skip_depth && !(rci)->output.element_skip)
#else
#define SHOULD_OUTPUT(rci)  ((rci)->output.skip_depth != 0 && !(rci)->output.element_skip)
#endif

#if (defined RCI_PARSER_USES_DICT)
STATIC connector_bool_t should_output_name(rci_t * const rci)
{
    connector_collection_type_t type = get_current_collection_type(rci);

    if (is_dictionary(type) == connector_true)
    {
        char const * const name = get_current_collection_name(rci);
        return connector_bool(name != NULL && name[0] != '\0');
    }
    else
    {
        return connector_false;
    }
}
#endif

STATIC void end_collection(rci_t * const rci)
{
    connector_remote_config_t const * const remote_config = &rci->shared.callback_data;

    if (remote_config->error_id != connector_success)
        state_call(rci, rci_parser_state_error);
    else if (!have_element_id(rci))
        set_rci_output_state(rci, rci_output_state_field_terminator);
    else
        state_call(rci, rci_parser_state_traverse);
}

STATIC void rci_set_output_error(rci_t * const rci, unsigned int const id, char const * const hint, rci_output_state_t state)
{
    rci_global_error(rci, id, hint);
    set_rci_output_state(rci, state);
    state_call(rci, rci_parser_state_output);
}

STATIC connector_bool_t rci_output_data(rci_t * const rci, rci_buffer_t * const output, uint8_t const * const data, size_t const bytes)
{
    connector_bool_t const overflow = connector_bool(rci_buffer_remaining(output) < bytes);

    if (overflow)
    {
        rci->status = rci_status_flush_output;
    }
    else
    {
        memcpy(rci_buffer_position(output), data, bytes);
        rci_buffer_advance(output, bytes);
    }

    return overflow;
}

STATIC size_t get_bytes_followed(uint32_t value)
{
    /* Bytes needed for the value:
     * 1 byte is 0 to 0x7F
     * 2 bytes is 0 to 0x1FFF
     * 3 bytes is 0 to 0xFFFF
     * 5 bytes is 0 to 0xFFFFFFFF
     *
     * Get additional bytes needed according to the value.
     */
    size_t bytes = 0;
    if (value <= UINT32_C(0x7F))
    {
        bytes = 0;
    }
    else if (value < UINT32_C(0x2000))
    {
        bytes = 1;
    }
    else if (value < UINT32_C(0x10000))
    {
        bytes = 2;
    }
    else
    {
        bytes = 4;
    }

    return bytes;
}

STATIC connector_bool_t rci_output_uint32(rci_t * const rci, uint32_t const value)
{
    connector_bool_t overflow;
    size_t const bytes_follow = get_bytes_followed(value);

    rci_buffer_t * const output = &rci->buffer.output;
    size_t const total_bytes = bytes_follow + 1;

    overflow = connector_bool(rci_buffer_remaining(output) < total_bytes);
    if (overflow)
    {
        rci->status = rci_status_flush_output;
    }
    else
    {
        uint8_t * const rci_ber = rci_buffer_position(output);

        /*
         *        opcode
         *    7 6 5 4 3 2 1 0 bit
         *    ---------------
         *    0 X X X X X X X   (0 : 0x7F)
         *    1 0 0 X X X X X   + 1 byte followed (0: 0x1FFF)
         *    1 0 1 - - - 0 0   + 2 bytes followed (0: 0xFFFF)
         *    1 0 1 - - - 0 1   + 4 bytes followed (0: 0xFFFFFFFF)
         *    1 0 1 - - - 1 0   + 8 bytes followed (0: 0xFFFFFFFFFFFFFFFF)
         *    1 1 0 - - - - -   Reserved
         *    1 1 1 0 0 0 0 0   NONUM (No Value)
         *    1 1 1 0 0 0 0 1   TRM (Terminator)
         */
        switch (total_bytes)
        {
            case record_bytes(rci_ber):
            {
                /* one byte with range [0, 0x7F] */
                uint8_t const data = (uint8_t)value;
                message_store_u8(rci_ber, value, data);
                break;
            }
            case record_bytes(rci_ber_u8):
            {
                #define MAX_ONE_BYTE_FOLLOW_VALUE   UINT32_C(0x1FFF)

                /* two bytes with range [0, 0x1FFF] */
                uint8_t * const rci_ber_u8 = rci_ber;
                uint8_t data;
                uint16_t data_value = (uint16_t)value;

                ASSERT(value <= MAX_ONE_BYTE_FOLLOW_VALUE);

                data = BINARY_RCI_SIZE_ALTERNATE_FLAG;
                data |= HIGH8(data_value);
                message_store_u8(rci_ber_u8, opcode, data);

                data =  LOW8(data_value);
                message_store_u8(rci_ber_u8, value, data);

                #undef MAX_ONE_BYTE_FOLLOW_VALUE
                break;
            }
            case record_bytes(rci_ber_u16):
            {
                /* 3 bytes with range [0, 0xFFFF] */
                uint8_t * const rci_ber_u16 = rci_ber;
                uint8_t const opcode = BINARY_RCI_SET_MULTI_FOLLOW_BYTES(binary_rci_two_follow_byte);
                uint16_t const data = (uint16_t)value;

                message_store_u8(rci_ber_u16, opcode, opcode);
                message_store_be16(rci_ber_u16, value, data);
                break;
            }
            case record_bytes(rci_ber_u32):
            {
                /* 5 bytes with range [0, 0xFFFFFFFF */
                uint8_t * const rci_ber_u32 = rci_ber;
                uint8_t const opcode = BINARY_RCI_SET_MULTI_FOLLOW_BYTES(binary_rci_four_follow_byte);

                message_store_u8(rci_ber_u32, opcode, opcode);
                message_store_be32(rci_ber_u32, value, value);

                break;

            }
        }
        rci_buffer_advance(output, total_bytes);
    }
    return overflow;
}

STATIC connector_bool_t rci_output_string(rci_t * const rci, char const * const string, size_t const length)
{

    rci_buffer_t * const output = &rci->buffer.output;
    connector_bool_t overflow = connector_true;

    /* output:  | length | string | */
    if (!rcistr_valid(&rci->output.content))
    {
        /* set up the data and its length */
        overflow = rci_output_uint32(rci, length);
        if (overflow) goto done;
        rci->output.content.data = (uint8_t *)string;
        rci->output.content.length = length;
    }

    if (rci->output.content.length > 0)
    {
        size_t const bytes_available = rci_buffer_remaining(output);
        size_t const write_bytes = (rci->output.content.length < bytes_available) ? rci->output.content.length : bytes_available;

        overflow = rci_output_data(rci, output, (uint8_t  *)rci->output.content.data, write_bytes);
        if (overflow) goto done;

        rci->output.content.data += write_bytes;
        rci->output.content.length -= write_bytes;

    }

    if (rci->output.content.length > 0)
    {
        overflow = connector_true;
        rci->status = rci_status_flush_output;
    }
    else
    {
        clear_rcistr(&rci->output.content);
    }

done:
    return overflow;
}

STATIC connector_bool_t rci_output_uint8(rci_t * const rci, uint8_t const value)
{
    uint8_t const data = value;
    rci_buffer_t * const output = &rci->buffer.output;

    return rci_output_data(rci, output, &data, sizeof data);
}

#define STRING_LENGTH_LEN 1

#if defined RCI_PARSER_USES_IPV4
STATIC connector_bool_t rci_output_ipv4(rci_t * const rci, char const * const string)
{
    rci_buffer_t * const output = &rci->buffer.output;
    connector_bool_t overflow = connector_true;

    {
        uint32_t ipv4 = 0;
        uint8_t * const rci_ber_u32 = rci_buffer_position(output);
        int dot_count = 0;
        size_t i;
        size_t const length = strlen(string);
        char aux_string[4] = {'\0', '\0', '\0', '\0'}; /* Three chars plus terminator. */

        size_t index = 0;

        for (i = 0; i < length; i++)
        {
            if (index > sizeof(aux_string) - 1)
                break;

            if (string[i] != '.')
            {
                aux_string[index++] = string[i];
            }

            if (string[i] == '.' || i == length - 1)
            {
                long int val;
                char * endptr;

                val = strtol(aux_string, &endptr, 10);
                if (endptr == NULL || *endptr != '\0' || val < 0 || val > 255)
                {
                    break;
                }

                ipv4 = (ipv4 << 8) | val;
                dot_count++;
                index = 0;
                memset(aux_string, '\0', sizeof aux_string);
            }
        }
        if (dot_count != 4)
        {
            connector_request_id_t request_id;
            request_id.remote_config_request = connector_request_id_remote_config_element_process;
            notify_error_status(rci->service_data->connector_ptr->callback, connector_class_id_remote_config, request_id, connector_invalid_data_range, rci->service_data->connector_ptr->context);

            {
                uint8_t * const element_id = rci->buffer.output.current - 1;

                *element_id |= BINARY_RCI_FIELD_TYPE_INDICATOR_BIT;
                rci_global_error(rci, connector_fatal_protocol_error_bad_value, NULL);
                state_call(rci, rci_parser_state_error);
            }

            connector_debug_line("Invalid IPv4 \"%s\"", string);
            goto done;
        }

        message_store_u8(rci_ber_u32, opcode, sizeof ipv4);
        message_store_be32(rci_ber_u32, value, ipv4);

        rci_buffer_advance(output, record_bytes(rci_ber_u32));

        overflow = connector_false;
    }

done:
    return overflow;
}
#define IPV4_ADDR_LEN (sizeof(uint32_t) + STRING_LENGTH_LEN)
#else
#define IPV4_ADDR_LEN 0
#endif

#if defined RCI_PARSER_USES_MAC_ADDR
#define SIZEOF_MAC_ADDR 6
STATIC connector_bool_t rci_output_mac_addr(rci_t * const rci, char const * const string)
{
    rci_buffer_t * const output = &rci->buffer.output;
    connector_bool_t overflow = connector_true;

    {
        char mac_addr[SIZEOF_MAC_ADDR] =  {0};
        char * p_mac_addr = mac_addr;
        int colon_count = 0;
        size_t i;
        size_t const length = strlen(string);
        char aux_string[3] = {'\0', '\0', '\0'}; /* Two chars plus terminator. */

        size_t index = 0;

        for (i = 0; i < length; i++)
        {
            if (index > sizeof(aux_string) - 1)
                break;

            if (string[i] != ':')
            {
                aux_string[index++] = string[i];
            }

            if (string[i] == ':' || i == length - 1)
            {
                long int val;
                char * endptr;

                val = strtol(aux_string, &endptr, 16);
                if (endptr == NULL || *endptr != '\0' || val < 0 || val > 255)
                {
                    break;
                }

                *p_mac_addr++ = (char)(val & 0xFF);
                colon_count++;
                index = 0;
                memset(aux_string, '\0', sizeof aux_string);
            }
        }
        if (colon_count != SIZEOF_MAC_ADDR)
        {
            connector_request_id_t request_id;
            request_id.remote_config_request = connector_request_id_remote_config_group_process;
            notify_error_status(rci->service_data->connector_ptr->callback, connector_class_id_remote_config, request_id, connector_invalid_data_range, rci->service_data->connector_ptr->context);

            {
                uint8_t * const element_id = rci->buffer.output.current - 1;

                *element_id |= BINARY_RCI_FIELD_TYPE_INDICATOR_BIT;
                rci_global_error(rci, connector_fatal_protocol_error_bad_value, NULL);
                state_call(rci, rci_parser_state_error);
            }

            connector_debug_line("Invalid mac_addr \"%s\"", string);
            goto done;
        }

        {
            uint8_t * rci_ber = rci_buffer_position(output);
            size_t j;

            *rci_ber++ = (uint8_t)SIZEOF_MAC_ADDR;
            rci_buffer_advance(output, 1);

            for (j = 0; j < SIZEOF_MAC_ADDR; j++)
            {
                *rci_ber++ = mac_addr[j];
                rci_buffer_advance(output, 1);
            }
        }

        overflow = connector_false;
    }

done:
    return overflow;
}
#define MAC_ADDR_LEN (SIZEOF_MAC_ADDR + STRING_LENGTH_LEN)
#else
#define MAC_ADDR_LEN 0
#endif

#if defined RCI_PARSER_USES_FLOAT
STATIC connector_bool_t rci_output_float(rci_t * const rci, float const value)
{
    float const float_value = value;
    uint32_t float_integer;

    ASSERT(sizeof value == sizeof float_integer);

    memcpy(&float_integer, &float_value, sizeof float_integer);

    return rci_output_uint32(rci, float_integer);
}
#endif

#define rci_output_no_value(rci)    rci_output_uint8((rci), BINARY_RCI_NO_VALUE)
#define rci_output_terminator(rci)  rci_output_uint8((rci), BINARY_RCI_TERMINATOR)

STATIC void rci_output_command_id(rci_t * const rci)
{
    connector_remote_config_t const * const remote_config = &rci->shared.callback_data;
    connector_bool_t overflow = connector_false;


    switch (rci->command.command_id)
    {
        case rci_command_set_state:
        case rci_command_query_state:
#if (defined RCI_LEGACY_COMMANDS)
        case rci_command_reboot:
        case rci_command_set_factory_default:
#endif
            overflow = rci_output_uint32(rci, rci->command.command_id);
            break;

        case rci_command_query_setting:
        case rci_command_set_setting:
#if (defined RCI_LEGACY_COMMANDS)
        case rci_command_do_command:
#endif
            if (rci->shared.attribute_count == 0)
            {
                overflow = rci_output_uint32(rci, rci->command.command_id);
            }
            else
            {
                overflow = rci_output_uint32(rci, rci->command.command_id | BINARY_RCI_ATTRIBUTE_BIT);
            }
            break;
         case rci_command_query_descriptor:
            ASSERT_GOTO(connector_false, done);
    }

    if (overflow)
    {
        goto done;
    }

    if (remote_config->error_id != connector_success)
    {
        state_call(rci, rci_parser_state_error);
        goto done;
    }

    if (rci->shared.attribute_count > 0)
    {
        set_rci_output_state(rci, rci_output_state_command_normal_attribute_count);
    }
    else
    {
        switch (rci->command.command_id)
        {
            case rci_command_set_setting:
            case rci_command_query_setting:
            case rci_command_set_state:
            case rci_command_query_state:
                state_call(rci, rci_parser_state_traverse);
                break;

#if (defined RCI_LEGACY_COMMANDS)
            case rci_command_do_command:
                set_rci_output_state(rci, rci_output_state_do_command_payload);

                set_rci_traverse_state(rci, rci_traverse_state_command_do_command);

                state_call(rci, rci_parser_state_traverse);
                break;

            case rci_command_reboot:
                set_rci_output_state(rci, rci_output_state_group_terminator);

                set_rci_traverse_state(rci, rci_traverse_state_command_reboot);

                state_call(rci, rci_parser_state_traverse);
                break;

            case rci_command_set_factory_default:
                set_rci_output_state(rci, rci_output_state_group_terminator);

                set_rci_traverse_state(rci, rci_traverse_state_command_set_factory_default);

                state_call(rci, rci_parser_state_traverse);
                break;
#endif

            case rci_command_query_descriptor:
                ASSERT_GOTO(connector_false, done);
        }
    }

done:
    return;
}

STATIC void rci_output_command_normal_attribute_count(rci_t * const rci)
{
    connector_remote_config_t const * const remote_config = &rci->shared.callback_data;
    connector_bool_t overflow = connector_false;


    switch (rci->command.command_id)
    {
        case rci_command_query_state:
        case rci_command_set_state:
        case rci_command_query_descriptor:
#if (defined RCI_LEGACY_COMMANDS)
        case rci_command_reboot:
        case rci_command_set_factory_default:
#endif
            ASSERT_GOTO(connector_false, done);
            break;

        case rci_command_query_setting:
        case rci_command_set_setting:
#if (defined RCI_LEGACY_COMMANDS)
        case rci_command_do_command:
#endif
            overflow = rci_output_uint8(rci, BINARY_RCI_ATTRIBUTE_TYPE_NORMAL | rci->shared.attribute_count);
            if (overflow)
            {
                goto done;
            }
            break;
    }

    if (remote_config->error_id != connector_success)
    {
        state_call(rci, rci_parser_state_error);
        goto done;
    }

    rci->shared.attributes_processed = 0;

    ASSERT_GOTO(rci->shared.attribute_count > 0, done);

    set_rci_output_state(rci, rci_output_state_command_normal_attribute_id);

done:
    return;
}

STATIC void rci_output_command_normal_attribute_id(rci_t * const rci)
{
    connector_remote_config_t const * const remote_config = &rci->shared.callback_data;
    connector_bool_t overflow = connector_false;


    switch (rci->command.command_id)
    {
        case rci_command_query_state:
        case rci_command_set_state:
        case rci_command_query_descriptor:
#if (defined RCI_LEGACY_COMMANDS)
        case rci_command_reboot:
        case rci_command_set_factory_default:
#endif
            ASSERT_GOTO(connector_false, done);
            break;

        case rci_command_query_setting:
        case rci_command_set_setting:
#if (defined RCI_LEGACY_COMMANDS)
        case rci_command_do_command:
#endif
            overflow = rci_output_uint8(rci, rci->command.attribute[rci->shared.attributes_processed].id.val);
            if (overflow)
            {
                goto done;
            }
            break;
    }

    if (remote_config->error_id != connector_success)
    {
        state_call(rci, rci_parser_state_error);
        goto done;
    }

    set_rci_output_state(rci, rci_output_state_command_normal_attribute_value);

done:
    return;
}

STATIC void rci_output_command_normal_attribute_value(rci_t * const rci)
{
    connector_remote_config_t const * const remote_config = &rci->shared.callback_data;
    connector_bool_t overflow = connector_false;

    switch (rci->command.command_id)
    {
        case rci_command_query_state:
        case rci_command_set_state:
        case rci_command_query_descriptor:

#if (defined RCI_LEGACY_COMMANDS)
        case rci_command_reboot:
        case rci_command_set_factory_default:
#endif
            ASSERT_GOTO(connector_false, done);
            break;

        case rci_command_query_setting:
        case rci_command_set_setting:
#if (defined RCI_LEGACY_COMMANDS)
        case rci_command_do_command:
#endif
            switch (rci->command.attribute[rci->shared.attributes_processed].type)
            {
                case attribute_type_enum:
                    overflow = rci_output_uint8(rci, rci->command.attribute[rci->shared.attributes_processed].value.enum_val);
                    break;
#if (defined RCI_LEGACY_COMMANDS)
                case attribute_type_string:
                    overflow = rci_output_string(rci, rci->command.attribute[rci->shared.attributes_processed].value.string_val, strlen(rci->command.attribute[rci->shared.attributes_processed].value.string_val));
                    break;
#endif
            }
            if (overflow)
            {
                goto done;
            }
            break;
    }

    if (remote_config->error_id != connector_success)
    {
        state_call(rci, rci_parser_state_error);
        goto done;
    }

    rci->shared.attributes_processed++;

    if (rci->shared.attributes_processed < rci->shared.attribute_count)
    {
        set_rci_output_state(rci, rci_output_state_command_normal_attribute_id);
    }
    else
    {
        switch (rci->command.command_id)
        {
            case rci_command_query_state:
            case rci_command_set_state:
            case rci_command_query_descriptor:
#if (defined RCI_LEGACY_COMMANDS)
            case rci_command_reboot:
            case rci_command_set_factory_default:
#endif
                ASSERT_GOTO(connector_false, done);
                break;
            case rci_command_query_setting:
            case rci_command_set_setting:
                state_call(rci, rci_parser_state_traverse);
                break;
#if (defined RCI_LEGACY_COMMANDS)
            case rci_command_do_command:
                set_rci_output_state(rci, rci_output_state_do_command_payload);

                set_rci_traverse_state(rci, rci_traverse_state_command_do_command);

                state_call(rci, rci_parser_state_traverse);
                break;
#endif
        }
    }

done:
    return;
}

STATIC void rci_output_group_id(rci_t * const rci)
{
    uint32_t encoding_data;

    if (!have_group_id(rci))
    {
        state_call(rci, rci_parser_state_error);
        goto done;
    }

    if (!SHOULD_OUTPUT(rci))
    {
#if (defined RCI_PARSER_USES_VARIABLE_GROUP)
#if (defined RCI_PARSER_USES_VARIABLE_DICT)
        SET_RCI_SHARED_FLAG(rci, RCI_SHARED_FLAG_REMOVE, connector_false);
#endif
#if (defined RCI_PARSER_USES_VARIABLE_ARRAY)
        SET_RCI_SHARED_FLAG(rci, RCI_SHARED_FLAG_OUTPUT_COUNT, connector_false);
#endif
#endif
        state_call(rci, rci_parser_state_traverse);
        goto done;
    }

    encoding_data = encode_group_id(get_group_id(rci));

    if ((get_group_instance(rci) != INVALID_INDEX && get_group_instance(rci) > 1) 
#if (defined RCI_PARSER_USES_DICT)
        || group_is_dictionary(rci)
#endif
#if (defined RCI_PARSER_USES_VARIABLE_GROUP)
        || should_output_count(rci)
#if (defined RCI_PARSER_USES_VARIABLE_DICT)
        || should_remove_instance(rci)
#endif
#endif
    )
    {
        encoding_data |= BINARY_RCI_ATTRIBUTE_BIT;

        if (rci_output_uint32(rci, encoding_data) == connector_false)
            set_rci_output_state(rci, rci_output_state_collection_attribute);
    }
    else if (rci_output_uint32(rci, encoding_data) == connector_false)
    {
        end_collection(rci);
    }

done:
    return;
}

STATIC connector_bool_t encode_attribute(rci_t * const rci, unsigned int const type, unsigned int const num)
{
    uint32_t encoding_data = type;
    connector_bool_t overflow = connector_false;

    #define BINARY_RCI_MAX_ATTRIBUTE_INDEX_FOR_ONE_BYTE     31
    #define BINARY_RCI_MAX_ATTRIBUTE_INDEX_FOR_TWO_BYTES    0x1FFF

    if (num < BINARY_RCI_MAX_ATTRIBUTE_INDEX_FOR_ONE_BYTE)
    {
        /* attribute output
         * bit |7 | 6 5 | 4 3 2 1 0|
         *     |x | 0 1 | - index -|
         */
        encoding_data |= num;
    }
    else
    {
        /* attribute must be wrapped around the "attribute type" bits (bits 5 and 6)
         *
         * bit |15 14 13 12 11 10 9 8 7 | 6 5 | 4 3 2 1 0|
         *     |       - index -        | 0 1 | - index -|
         */
        uint16_t encoding_data_high, encoding_data_low;

        ASSERT(num < BINARY_RCI_MAX_ATTRIBUTE_INDEX_FOR_TWO_BYTES);
        encoding_data_low = num & 0x1F;
        encoding_data_high = num & (~(0x1F));
        encoding_data |= (encoding_data_high << 2) | encoding_data_low;
    }
    if (SHOULD_OUTPUT(rci))
        overflow = rci_output_uint32(rci, encoding_data);

    return overflow;
}

STATIC void rci_output_collection_attribute(rci_t * const rci)
{
    unsigned int instance;
    rci_output_state_t next_output_state;
    unsigned int normal_attribute_count = 0;

#if (defined RCI_PARSER_USES_LIST)
    if (get_list_depth(rci) > 0)
    {
        instance = get_current_list_instance(rci);
    }
    else
#endif
    {
        instance = get_group_instance(rci);
    }

#if (defined RCI_PARSER_USES_VARIABLE_ARRAY) || (defined RCI_PARSER_USES_VARIABLE_DICT)
    if (should_output_count(rci))
    {
#if (defined RCI_PARSER_USES_DICT)
        connector_collection_type_t collection_type = get_current_collection_type(rci);
#endif
        normal_attribute_count++;
        if (should_remove_instance(rci))
        {
            normal_attribute_count++;
        }
#if (defined RCI_PARSER_USES_DICT)
        if (is_dictionary(collection_type) == connector_true)
            next_output_state = rci_output_state_complete_attribute_id;
#if (defined RCI_PARSER_USES_VARIABLE_ARRAY)
        else
#endif
#endif
#if (defined RCI_PARSER_USES_VARIABLE_ARRAY)
            next_output_state = rci_output_state_collection_count_id;
#endif
    }
#if (defined RCI_PARSER_USES_VARIABLE_DICT)
    else if (should_remove_instance(rci))
    {
        normal_attribute_count++;
        next_output_state = rci_output_state_remove_attribute_id;
    }
#endif
#endif

    if (normal_attribute_count > 0)
    {
        if (instance != INVALID_INDEX && (instance > 1
#if (defined RCI_PARSER_USES_DICT)
            || should_output_name(rci)
#endif
        ))
        {
            next_output_state = rci_output_state_collection_specifier_id;
            normal_attribute_count++;
        }
        if (!encode_attribute(rci, BINARY_RCI_ATTRIBUTE_TYPE_NORMAL, normal_attribute_count))
        {
            set_rci_output_state(rci, next_output_state);
        }
    }
#if (defined RCI_PARSER_USES_DICT)
    else if (should_output_name(rci))
    {
        char const * const name = get_current_collection_name(rci);
        connector_bool_t overflow = encode_attribute(rci, BINARY_RCI_ATTRIBUTE_TYPE_NAME, strlen(name));
        if (!overflow)
            set_rci_output_state(rci, rci_output_state_collection_name_string);
    }
#endif
    else if (instance > 1)
    {
        connector_bool_t overflow = encode_attribute(rci, BINARY_RCI_ATTRIBUTE_TYPE_INDEX, instance);
        if (!overflow)
        {
            end_collection(rci);
        }
    }
    else
    {
        end_collection(rci);
    }
}

#if (defined RCI_PARSER_USES_VARIABLE_ARRAY)
STATIC void rci_output_collection_count_id(rci_t * const rci)
{
    SET_RCI_SHARED_FLAG(rci, RCI_SHARED_FLAG_OUTPUT_COUNT, connector_false);
    connector_bool_t overflow = rci_output_uint8(rci, rci_array_attribute_count);

    if (!overflow)
    {
        set_rci_output_state(rci, rci_output_state_collection_count_value);
    }
}

STATIC void rci_output_collection_count_value(rci_t * const rci)
{
#if (defined RCI_PARSER_USES_LIST)
    unsigned int count = get_list_depth(rci) > 0 ? get_current_list_count(rci) : get_group_count(rci);
#else
    unsigned int count = get_group_count(rci);
#endif
    connector_bool_t overflow = rci_output_uint32(rci, count);

    if (!overflow)
    {
        end_collection(rci);
    }
}
#endif

#if (defined RCI_PARSER_USES_VARIABLE_DICT)
STATIC void rci_output_remove_attribute_id(rci_t * const rci)
{
    SET_RCI_SHARED_FLAG(rci, RCI_SHARED_FLAG_REMOVE, connector_false);
    connector_bool_t overflow = rci_output_uint8(rci, rci_dictionary_attribute_remove);

    if (!overflow)
    {
        set_rci_output_state(rci, rci_output_state_remove_attribute_value);
    }
}

STATIC void rci_output_remove_attribute_value(rci_t * const rci)
{
    connector_bool_t overflow = rci_output_uint8(rci, 1);
    connector_remote_config_t const * const remote_config = &rci->shared.callback_data;

    if (!overflow)
    {
        if (remote_config->error_id != connector_success)
            state_call(rci, rci_parser_state_error);
        else
            set_rci_output_state(rci, rci_output_state_field_terminator);
    }
}
#endif

#if (defined RCI_PARSER_USES_VARIABLE_DICT)
STATIC void rci_output_complete_attribute_id(rci_t * const rci)
{
    SET_RCI_SHARED_FLAG(rci, RCI_SHARED_FLAG_OUTPUT_COUNT, connector_false);
    connector_bool_t overflow = rci_output_uint8(rci, rci_dictionary_attribute_complete);

    if (!overflow)
    {
        set_rci_output_state(rci, rci_output_state_complete_attribute_value);
    }
}

STATIC void rci_output_complete_attribute_value(rci_t * const rci)
{
    connector_bool_t overflow = rci_output_uint8(rci, 1);

    if (!overflow)
    {
        if (should_remove_instance(rci))
            set_rci_output_state(rci, rci_output_state_remove_attribute_id);
        else
            end_collection(rci);
    }
}
#endif

STATIC void rci_output_collection_specifier_id(rci_t * const rci)
{
    connector_bool_t overflow;

#if (defined RCI_PARSER_USES_DICT)
    connector_collection_type_t collection_type = get_current_collection_type(rci);
    if (is_dictionary(collection_type) == connector_true)
    {
        overflow = rci_output_uint8(rci, rci_dictionary_attribute_name);
    }
    else
#endif
    {
        overflow = rci_output_uint8(rci, rci_array_attribute_index);
    }

    if (!overflow)
        set_rci_output_state(rci, rci_output_state_collection_specifier_value);
}

STATIC void rci_output_collection_specifier_value(rci_t * const rci)
{
    connector_bool_t overflow;
    unsigned int instance;
#if (defined RCI_PARSER_USES_DICT)
    connector_collection_type_t collection_type = get_current_collection_type(rci);;
#endif

#if (defined RCI_PARSER_USES_LIST)
    if (get_list_depth(rci) > 0)
    {
        instance = get_current_list_instance(rci);
    }
    else
#endif
    {
        instance = get_group_instance(rci);
    }

#if (defined RCI_PARSER_USES_DICT)
    if (is_dictionary(collection_type) == connector_true)
    {
        char const * const name = get_current_collection_name(rci);
        overflow = rci_output_string(rci, name, strlen(name));
    }
    else
#endif
    {
        overflow = rci_output_uint32(rci, instance);
    }

    if (!overflow)
    {
#if (defined RCI_PARSER_USES_VARIABLE_ARRAY) || (defined RCI_PARSER_USES_VARIABLE_DICT)
        if (should_output_count(rci))
        {
#if (defined RCI_PARSER_USES_DICT)
            if (is_dictionary(collection_type) == connector_true)
                set_rci_output_state(rci, rci_output_state_complete_attribute_id);
#if (defined RCI_PARSER_USES_VARIABLE_ARRAY)
            else
#endif
#endif
#if (defined RCI_PARSER_USES_VARIABLE_ARRAY)
                set_rci_output_state(rci, rci_output_state_collection_count_id);
#endif
        }
#if (defined RCI_PARSER_USES_VARIABLE_DICT)
        else if (should_remove_instance(rci))
        {
            set_rci_output_state(rci, rci_output_state_remove_attribute_id);
        }
#endif
        else
#endif
        {
            end_collection(rci);
        }
    }
}

#if (defined RCI_PARSER_USES_DICT)
STATIC void rci_output_collection_name_string(rci_t * const rci)
{
    connector_bool_t overflow;
    char const * const name = get_current_collection_name(rci);

    if (!rcistr_valid(&rci->output.content)) /* bypass output of leading length */
    {
        rci->output.content.data = (uint8_t *) name;
        rci->output.content.length = strlen(name);
    }
    overflow = rci_output_string(rci, (char *) rci->output.content.data, rci->output.content.length);

    if (!overflow)
    {
        end_collection(rci);
    }
}
#endif

#define BYTES_REQUIRED_FOR_ERROR_PRONE_FIELD_VALUES MAX_VALUE(MAC_ADDR_LEN, IPV4_ADDR_LEN)

STATIC void rci_output_field_id(rci_t * const rci)
{
    connector_remote_config_t const * const remote_config = &rci->shared.callback_data;
    rci_buffer_t * const output = &rci->buffer.output;
    size_t const bytes_available = rci_buffer_remaining(output);
    uint32_t field_id =  encode_element_id(get_element_id(rci));
    size_t const bytes_required_for_field_id = 1 + get_bytes_followed(field_id);
    size_t const total_bytes_required = bytes_required_for_field_id + BYTES_REQUIRED_FOR_ERROR_PRONE_FIELD_VALUES;

    if (bytes_available < total_bytes_required)
    {
        rci->status = rci_status_flush_output;
        goto done;
    }

    if (!have_element_id(rci))
    {
        state_call(rci, rci_parser_state_error);
        goto done;
    }

    {
        /* output field id */
        if (remote_config->error_id != connector_success) field_id |= BINARY_RCI_FIELD_TYPE_INDICATOR_BIT;

        {
            connector_bool_t overflow = connector_false;

            if (SHOULD_OUTPUT(rci))
                overflow = rci_output_uint32(rci, field_id);

            if (overflow) goto done;

            if (remote_config->error_id != connector_success)
                state_call(rci, rci_parser_state_error);
            else
                set_rci_output_state(rci, rci_output_state_field_value);
        }

    }

done:
    return;
}

#if (defined RCI_PARSER_USES_LIST)
STATIC void rci_output_list_id(rci_t * const rci)
{
    connector_remote_config_t const * const remote_config = &rci->shared.callback_data;
    uint32_t field_id = encode_element_id(get_current_list_id(rci));

    if (!have_current_list_id(rci))
    {
        state_call(rci, rci_parser_state_error);
        goto done;
    }

    if (!SHOULD_OUTPUT(rci))
    {
        SET_RCI_SHARED_FLAG(rci, RCI_SHARED_FLAG_REMOVE, connector_false);
        SET_RCI_SHARED_FLAG(rci, RCI_SHARED_FLAG_OUTPUT_COUNT, connector_false);
        state_call(rci, rci_parser_state_traverse);
        goto done;
    }

    /* output field id */
    if (remote_config->error_id != connector_success)
    {
        field_id |= BINARY_RCI_FIELD_TYPE_INDICATOR_BIT;
    }

    if (get_current_list_instance(rci) > 1
#if (defined RCI_PARSER_USES_DICT)
        || should_output_name(rci)
#endif
#if (defined RCI_PARSER_USES_VARIABLE_LIST)
        || should_output_count(rci)
#if (defined RCI_PARSER_USES_VARIABLE_DICT)
        || should_remove_instance(rci)
#endif
#endif
    )
    {
        field_id |= BINARY_RCI_FIELD_ATTRIBUTE_BIT;

        if (rci_output_uint32(rci, field_id) == connector_false)
            set_rci_output_state(rci, rci_output_state_collection_attribute);
    }
    else if (rci_output_uint32(rci, field_id) == connector_false)
    {
        end_collection(rci);
    }

done:
    return;
}
#endif


STATIC void rci_output_field_value(rci_t * const rci)
{
    connector_item_t const * const element = get_current_element(rci);
    connector_element_value_type_t const type = element->type;
    connector_element_value_t value = rci->shared.value;

    connector_bool_t overflow = connector_false;

    if (!SHOULD_OUTPUT(rci))
    {
        goto done;
    }

    if (rci->shared.callback_data.action == connector_remote_action_set) {
        if (rci->shared.callback_data.attribute.embed_transformed_values != connector_true ||
            rci->shared.transformed_value.string_value == NULL) {
            overflow = rci_output_no_value(rci);
            goto done;
        }
        value = rci->shared.transformed_value;
    }

    switch (type)
    {
#if defined RCI_PARSER_USES_STRINGS

#if defined RCI_PARSER_USES_STRING
    case connector_element_type_string:
#endif

#if defined RCI_PARSER_USES_MULTILINE_STRING
    case connector_element_type_multiline_string:
#endif

#if defined RCI_PARSER_USES_PASSWORD
    case connector_element_type_password:
#endif

#if defined RCI_PARSER_USES_FQDNV4
    case connector_element_type_fqdnv4:
#endif

#if defined RCI_PARSER_USES_FQDNV6
    case connector_element_type_fqdnv6:
#endif

#if defined RCI_PARSER_USES_DATETIME
    case connector_element_type_datetime:
#endif

#if defined RCI_PARSER_USES_REF_ENUM
    case connector_element_type_ref_enum:
#endif
        ASSERT(value.string_value != NULL);
        overflow = rci_output_string(rci, value.string_value, strlen(value.string_value));
        break;
#endif

#if defined RCI_PARSER_USES_IPV4
    case connector_element_type_ipv4:
        ASSERT(value.string_value != NULL);
        overflow = rci_output_ipv4(rci, value.string_value);
        break;
#endif

#if defined RCI_PARSER_USES_INT32
    case connector_element_type_int32:
        overflow = rci_output_uint32(rci, value.signed_integer_value);
        break;
#endif

#if (defined RCI_PARSER_USES_UNSIGNED_INTEGER)
#if defined RCI_PARSER_USES_UINT32
    case connector_element_type_uint32:
#endif

#if defined RCI_PARSER_USES_HEX32
    case connector_element_type_hex32:
#endif

#if defined RCI_PARSER_USES_0X_HEX32
    case connector_element_type_0x_hex32:
#endif

        overflow = rci_output_uint32(rci, value.unsigned_integer_value);
        break;
#endif

#if defined RCI_PARSER_USES_FLOAT
    case connector_element_type_float:
        overflow = rci_output_float(rci, value.float_value);
        break;
#endif

#if defined RCI_PARSER_USES_ENUM
    case connector_element_type_enum:
        overflow = rci_output_uint32(rci, value.enum_value);
        break;
#endif

#if defined RCI_PARSER_USES_ON_OFF
    case connector_element_type_on_off:
        overflow = rci_output_uint32(rci, value.on_off_value);
        break;
#endif

#if defined RCI_PARSER_USES_BOOLEAN
    case connector_element_type_boolean:
        overflow = rci_output_uint32(rci, value.boolean_value);
        break;
#endif

#if defined RCI_PARSER_USES_MAC_ADDR
    case connector_element_type_mac_addr:
        ASSERT(value.string_value != NULL);
        overflow = rci_output_mac_addr(rci, value.string_value);
        break;
#endif

#if (defined RCI_PARSER_USES_LIST)
    case connector_element_type_list:
        ASSERT(connector_false);
        break;
#endif
    }

done:
    if (!overflow)
        state_call(rci, rci_parser_state_traverse);

}

#if (defined RCI_LEGACY_COMMANDS)
STATIC void rci_output_do_command_payload(rci_t * const rci)
{
    connector_bool_t overflow = connector_false;
    char const * const response_payload = rci->command.do_command.response_value.string_value;

    if (response_payload != NULL)
    {
        overflow = rci_output_string(rci, response_payload, strlen(response_payload));
    }
    else
    {
        overflow = rci_output_uint8(rci, 0x00);
    }

    if (!overflow)
    {
        set_rci_output_state(rci, rci_output_state_group_terminator);

        set_rci_traverse_state(rci, rci_traverse_state_none);

        state_call(rci, rci_parser_state_input);
    }

}
#endif

STATIC void rci_output_field_terminator(rci_t * const rci)
{
    connector_bool_t overflow = connector_false;

    if (SHOULD_OUTPUT(rci))
        overflow = rci_output_terminator(rci);

    if (!overflow)
    {
        state_call(rci, rci_parser_state_traverse);
    }

    return;
}

STATIC void rci_output_group_terminator(rci_t * const rci)
{
    connector_remote_config_t const * const remote_config = &rci->shared.callback_data;

    if (remote_config->error_id != connector_success)
    {
        state_call(rci, rci_parser_state_error);
    }
    else
    {
        connector_bool_t const overflow = rci_output_terminator(rci);
        if (!overflow)
        {
            set_rci_output_state(rci, rci_output_state_response_done);
        }
    }

    return;
}

STATIC void rci_generate_output(rci_t * const rci)
{
    rci_buffer_t * const output = &rci->buffer.output;

    if ((rci_buffer_remaining(output) != 0))
    {
#if (defined RCI_DEBUG)
        connector_debug_line("output: %s", rci_output_state_t_as_string(rci->output.state));
#endif

        switch (rci->output.state)
        {
            case rci_output_state_command_id:
                rci_output_command_id(rci);
                break;

            case rci_output_state_command_normal_attribute_count:
                rci_output_command_normal_attribute_count(rci);
                break;

            case rci_output_state_command_normal_attribute_id:
                rci_output_command_normal_attribute_id(rci);
                break;

            case rci_output_state_command_normal_attribute_value:
                rci_output_command_normal_attribute_value(rci);
                break;

            case rci_output_state_group_id:
                rci_output_group_id(rci);
                break;

            case rci_output_state_collection_attribute:
                rci_output_collection_attribute(rci);
                break;

#if (defined RCI_PARSER_USES_VARIABLE_ARRAY)
            case rci_output_state_collection_count_id:
                rci_output_collection_count_id(rci);
                break;

            case rci_output_state_collection_count_value:
                rci_output_collection_count_value(rci);
                break;
#endif

            case rci_output_state_collection_specifier_id:
                rci_output_collection_specifier_id(rci);
                break;

            case rci_output_state_collection_specifier_value:
                rci_output_collection_specifier_value(rci);
                break;

#if (defined RCI_PARSER_USES_DICT)
            case rci_output_state_collection_name_string:
                rci_output_collection_name_string(rci);
                break;

#if (defined RCI_PARSER_USES_VARIABLE_DICT)
            case rci_output_state_complete_attribute_id:
                rci_output_complete_attribute_id(rci);
                break;

            case rci_output_state_complete_attribute_value:
                rci_output_complete_attribute_value(rci);
                break;

            case rci_output_state_remove_attribute_id:
                rci_output_remove_attribute_id(rci);
                break;

            case rci_output_state_remove_attribute_value:
                rci_output_remove_attribute_value(rci);
                break;
#endif
#endif

#if (defined RCI_PARSER_USES_LIST)
            case rci_output_state_list_id:
                rci_output_list_id(rci);
                break;
#endif

            case rci_output_state_field_id:
                rci_output_field_id(rci);
                break;

            case rci_output_state_field_value:
                rci_output_field_value(rci);
                break;

#if (defined RCI_LEGACY_COMMANDS)
            case rci_output_state_do_command_payload:
                rci_output_do_command_payload(rci);
                break;
#endif

            case rci_output_state_field_terminator:
                rci_output_field_terminator(rci);
                break;

            case rci_output_state_group_terminator:
                rci_output_group_terminator(rci);
                break;

            case rci_output_state_response_done:

                if (get_rci_input_state(rci) == rci_input_state_done)
                {
                    trigger_rci_callback(rci, connector_request_id_remote_config_session_end);
                    set_rci_output_state(rci, rci_output_state_done);
                }
                else
                {
                    state_call(rci, rci_parser_state_input);
                    set_rci_input_state(rci, rci_input_state_command_id);
                }
                break;

            case rci_output_state_done:
            {
                connector_remote_config_t const * const remote_config = &rci->shared.callback_data;
                if (remote_config->error_id != connector_success)
                    state_call(rci, rci_parser_state_error);
                else
                    rci->status = rci_status_complete;
                break;
            }
        }
    }
    else if ((rci_buffer_used(&rci->buffer.output) > 0) && (rci->status == rci_status_busy))
    {
        /* We are here since we have no space left for more output data and we have output data waiting to be sent.
           So set up the state to send out the output data and come back to rci */

        rci->status = rci_status_flush_output;
    }


#if defined RCI_DEBUG
    {
        size_t const bytes = rci_buffer_used(&rci->buffer.output);
        if (bytes > 0)
        {
            connector_debug_print_buffer("Response", rci->buffer.output.start, bytes);
        }
    }
#endif

    return;
}
