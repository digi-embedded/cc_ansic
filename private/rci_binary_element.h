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

#define ELEMENT_ID_VARIABLE(rci)        ((rci)->shared.element.id)
#define set_element_id(rci, value)      (ELEMENT_ID_VARIABLE(rci) = (value))
#define get_element_id(rci)             (ELEMENT_ID_VARIABLE(rci))
#define invalidate_element_id(rci)      set_element_id(rci, INVALID_ID)
#define have_element_id(rci)            (get_element_id(rci) != INVALID_ID)

static connector_collection_t const * get_current_collection_info(rci_t const * const rci)
{
	ASSERT(have_group_id(rci));
	{
		connector_group_t const * const group = get_current_group(rci);
		connector_collection_t const * info =  &group->collection;

#if (defined RCI_PARSER_USES_LIST)
		{
			int i;
			for (i = 0; i < get_list_depth(rci); i++)
			{
				connector_item_t const * list = info->item.data + rci->shared.list.level[i].id;
				ASSERT(list->type == connector_element_type_list);
				info = list->data.collection;
			}
		}
#endif

		return info;
	}
}

static connector_item_t const * get_current_element(rci_t const * const rci)
{
    ASSERT(have_element_id(rci));
	{
        unsigned int const id = get_element_id(rci);
		connector_collection_t const * const info = get_current_collection_info(rci);

		ASSERT(id < info->item.count);

		return info->item.data + id;
	}
}
