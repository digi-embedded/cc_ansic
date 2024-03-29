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
#ifndef _EI_PACKET_H
#define _EI_PACKET_H

#define field_glue(left, right)                 left ## _ ## right
#define field_name(record, field)               field_glue(record,field)
#define field_data(name, data)                  field_glue(name, data)

#define field_named_data(record, field, data)   field_data(field_name(record, field), data)

#define field_allocate(name, type)              field_data(name, offset), \
                                                field_data(name, size) = (sizeof(type)), \
                                                field_data(name, next) = (field_data(name, offset) + field_data(name, size) - 1)

#define field_define(record, field, type)       field_allocate(field_name(record, field), type)

#define field_allocate_array(name, bytes)       field_data(name, offset), \
                                                field_data(name, size) = (bytes), \
                                                field_data(name, next) = (field_data(name, offset) + field_data(name, size) - 1)

#define field_define_array(record, field, count) field_allocate_array(field_name(record, field), count)

#define record_end(name)                        field_data(name, bytes)

#define record_bytes(name)                      field_data(name, bytes)

#if (defined CONNECTOR_SUPPORTS_64_BIT_INTEGERS)
#define message_store_be64(record, field, value) \
do { \
    ASSERT(field_named_data(record, field, size) == sizeof (uint64_t)); \
    StoreBE64(record + field_named_data(record, field, offset), (value)); \
} while (0)
#endif

#define message_store_be32(record, field, value) \
    do { \
        ASSERT(field_named_data(record, field, size) == sizeof (uint32_t)); \
        StoreBE32(record + field_named_data(record, field, offset), (value)); \
    } while (0)

#define message_store_be16(record, field, value) \
    do { \
        ASSERT(field_named_data(record, field, size) == sizeof (uint16_t)); \
        StoreBE16(record + field_named_data(record, field, offset), (value)); \
    } while (0)

#define message_store_u8(record, field, value) \
    do { \
        ASSERT(field_named_data(record, field, size) == sizeof (uint8_t)); \
        *(record + field_named_data(record, field, offset)) = (value); \
    } while (0)

#define message_store_array(record, field, value, asize) \
    do { \
        ASSERT(field_named_data(record, field, size) == (asize)); \
        memcpy((record + field_named_data(record, field, offset)), (value), (asize)); \
    } while (0)

#if (defined CONNECTOR_DEBUG)
#define message_load_be32(record, field) (ASSERT(field_named_data(record, field, size) == sizeof (uint32_t)), LoadBE32(record + field_named_data(record, field, offset)))
#define message_load_be16(record, field) (ASSERT(field_named_data(record, field, size) == sizeof (uint16_t)), LoadBE16(record + field_named_data(record, field, offset)))
#define message_load_u8(record, field) (ASSERT(field_named_data(record, field, size) == sizeof (uint8_t)), *(record + field_named_data(record, field, offset)))
#else
#define message_load_be32(record, field) LoadBE32(record + field_named_data(record, field, offset))
#define message_load_be16(record, field) LoadBE16(record + field_named_data(record, field, offset))
#define message_load_u8(record, field) *(record + field_named_data(record, field, offset))
#endif

#define message_load_array(value, asize, record, field) \
    do { \
        ASSERT(field_named_data(record, field, size) == (asize)); \
        memcpy((value), (record + field_named_data(record, field, offset)), (asize)); \
    } while (0)

#define field_offsets_match(field, record1, record2) ((long) field_named_data(record1, field, offset) == (long) field_named_data(record2, field, offset))
#define field_sizes_match(field, record1, record2) ((long) field_named_data(record1, field, size) == (long) field_named_data(record2, field, size))
#define fields_equivalent(field, record1, record2) (field_offsets_match(field, record1, record2) && field_sizes_match(field, record1, record2))

#define PACKET_EDP_PROTOCOL_SIZE        ((size_t)record_bytes(edp_protocol))
#define PACKET_EDP_HEADER_SIZE          ((size_t)record_bytes(edp_header))
#define PACKET_EDP_FACILITY_SIZE        (PACKET_EDP_PROTOCOL_SIZE + PACKET_EDP_HEADER_SIZE)

/* private definitions */
enum edp_header {
    field_define(edp_header, type, uint16_t),
    field_define(edp_header, length, uint16_t),
    record_end(edp_header)
};

enum edp_protocol {
    field_define(edp_protocol, sec_coding, uint8_t),
    field_define(edp_protocol, payload, uint8_t),
    field_define(edp_protocol, facility, uint16_t),
    record_end(edp_protocol)
};

#endif
