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

#define BINARY_RCI_FIELD_LOWER_ID_MASK UINT32_C(0x3F)
#define BINARY_RCI_FIELD_MIDDLE_ID_MASK UINT32_C(0x380)
#define BINARY_RCI_FIELD_MIDDLE_BIT_ID_MASK UINT32_C(0x800)
#define BINARY_RCI_FIELD_UPPER_ID_MASK (~UINT32_C(0x1FFF))


static unsigned int decode_element_id(uint32_t const value)
{
    unsigned int id;

    id = (value & BINARY_RCI_FIELD_LOWER_ID_MASK);
    id |= ((value & BINARY_RCI_FIELD_MIDDLE_ID_MASK) >> 1);
    id |= ((value & BINARY_RCI_FIELD_MIDDLE_BIT_ID_MASK) >> 2);
    id |= ((value & BINARY_RCI_FIELD_UPPER_ID_MASK) >> 3);

    return id;
}

STATIC uint32_t encode_element_id(unsigned int const id)
{

    uint32_t value;

    value = (id & BINARY_RCI_FIELD_LOWER_ID_MASK);
    value |= ((id  << 1) & BINARY_RCI_FIELD_MIDDLE_ID_MASK);
    value |= ((id  << 2) & BINARY_RCI_FIELD_MIDDLE_BIT_ID_MASK);
    value |= ((id  << 3) & BINARY_RCI_FIELD_UPPER_ID_MASK);

    return value;
}


#define BINARY_RCI_GROUP_ID_LOWER_BIT_MASK  UINT32_C(0x03F)   /* [5:0] */
#define BINARY_RCI_GROUP_ID_MIDDLE_BIT_MASK UINT32_C(0xF80)   /* [11:7] */
#define BINARY_RCI_GROUP_ID_UPPER_BIT_MASK  ~(UINT32_C(0x1FF))    /* [:13] */

static unsigned int decode_group_id(uint32_t const group_id)
{

    unsigned int id = 0;

    id = (group_id & BINARY_RCI_GROUP_ID_LOWER_BIT_MASK);
    id |= ((group_id & BINARY_RCI_GROUP_ID_MIDDLE_BIT_MASK) >> 1);
    id |= ((group_id & BINARY_RCI_GROUP_ID_UPPER_BIT_MASK) >> 2);

    return id;
}

STATIC uint32_t encode_group_id(unsigned int const group_id)
{
    uint32_t id;

    id = (group_id & BINARY_RCI_GROUP_ID_LOWER_BIT_MASK);
    id |= ((group_id << 1) & BINARY_RCI_GROUP_ID_MIDDLE_BIT_MASK);
    id |= ((group_id << 2) & BINARY_RCI_GROUP_ID_UPPER_BIT_MASK);

    return id;
}

#if (defined RCI_PARSER_USES_VARIABLE_ARRAY) || (defined RCI_PARSER_USES_VARIABLE_DICT)
STATIC connector_bool_t is_variable(connector_collection_type_t collection_type)
{
#if (defined RCI_PARSER_USES_VARIABLE_ARRAY) && (defined RCI_PARSER_USES_VARIABLE_DICT)
return collection_type == connector_collection_type_variable_array || collection_type == connector_collection_type_variable_dictionary;
#elif (defined RCI_PARSER_USES_VARIABLE_ARRAY)
return collection_type == connector_collection_type_variable_array;
#else
return collection_type == connector_collection_type_variable_dictionary;
#endif
}
#endif

#if (defined RCI_PARSER_USES_DICT)
STATIC connector_bool_t is_dictionary(connector_collection_type_t collection_type)
{
#if (defined RCI_PARSER_USES_VARIABLE_DICT)
    return connector_bool(collection_type == connector_collection_type_fixed_dictionary || collection_type == connector_collection_type_variable_dictionary);
#else
    return connector_bool(collection_type == connector_collection_type_fixed_dictionary);
#endif
}
#endif

