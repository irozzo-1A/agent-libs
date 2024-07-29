// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#pragma once

#include "list_operations.h"

// This is a copy of the `refill_read_buffers` method + the active list population.
// We copied this method to reduce conflicts in the fork.
static __always_inline int32_t refill_active_list(struct scap_device_set* devset) {
	uint32_t j;
	uint32_t ndevs = devset->m_ndevs;

	if(are_buffers_empty(devset)) {
		sleep_ms(devset->m_buffer_empty_wait_time_us / 1000);
		devset->m_buffer_empty_wait_time_us =
		        MIN(devset->m_buffer_empty_wait_time_us * 2, BUFFER_EMPTY_WAIT_TIME_US_MAX);
	} else {
		devset->m_buffer_empty_wait_time_us = BUFFER_EMPTY_WAIT_TIME_US_START;
	}

	/* In any case (potentially also after a `sleep`) we refill our buffers */
	for(j = 0; j < ndevs; j++) {
		struct scap_device* dev = &(devset->m_devs[j]);
		if(dev->m_state != DEV_OPEN) {
			continue;
		}

		int32_t res = READBUF(dev, &dev->m_sn_next_event, &dev->m_sn_len);

		if(res != SCAP_SUCCESS) {
			return res;
		}

		DEBUG_MSG("Refill buffer %d with %d bytes\n", j, dev->m_sn_len);
		// If this buffer doesn't have new data, we won't add it to the list.
		// We will try again to add it at the next refill.
		if(dev->m_sn_len > 0) {
			// We populate the event pointer here
			dev->m_evt_p = NEXT_EVENT(dev);
			add_to_active_list(devset, j, dev->m_evt_p->ts);
			dev->m_alive_events++;
		}
	}

	/* Return `SCAP_TIMEOUT` after a refill so we can start consuming the new events. */
	return SCAP_TIMEOUT;
}

// todo!: why do we need the `pflags` param? it seems specific to the savefile engine!
// todo!: no udig implementation. it requires a dynamic mechanism to add and remove new buffers from
// the list.
static __always_inline int32_t __OPTIMIZE_O3
ringbuffer_next_sorted_linked_list(struct scap_device_set* devset,
                                   scap_evt** event_ptr,
                                   uint16_t* buffer_id,
                                   uint32_t* pflags) {
FILL_CACHE_PHASE:
	if(devset->e_cache.len == 0) {
		uint16_t head = INVALID_BUFFER_ID;
		scap_device* dev = NULL;
		DEBUG_MSG("\n[FILL CACHE]\n");
		for(uint8_t c = 0; c < EVENT_CACHE_LIMIT; c++) {
			head = devset->al.h;
			// The active list is empty
			if(head == INVALID_BUFFER_ID) {
				DEBUG_MSG("Active list is empty\n");
				break;
			}

			// We don't need to call `NEXT_EVENT` here because we already have the event pointer.
			// But we need to call `ADVANCE_TO_EVT` because at the following `NEXT_EVENT` we want to
			// read the next event on this buffer.
			dev = &(devset->m_devs[head]);
			ADVANCE_TO_EVT(dev, dev->m_evt_p);

			DEBUG_MSG("Add event in the cache (len: %d) -> ", devset->e_cache.len);
			DEBUG_EVENT(dev->m_evt_p, head);

			devset->e_cache.map[devset->e_cache.len].b_id = head;
			devset->e_cache.map[devset->e_cache.len].e_p = dev->m_evt_p;
			devset->e_cache.len++;

			// We remove the buffer from the active list:
			// 1. If this buffer has no more events we don't add the removed buffer to the wait
			// list. we will reinsert this buffer only at the next refill, since until that moment
			// it won't have new events. And so we continue the loop.
			// 2. If this buffer has other events:
			// - If the active list is not empty and the timestamp of the new event is less than the
			// timestamp of the active list tail we insert the buffer in the active list.
			// - Otherwise we insert the buffer in the wait list.
			remove_head_from_active_list(devset);

			if(dev->m_sn_len > 0) {
				// We immediately take another event from the same buffer if possible.
				dev->m_evt_p = NEXT_EVENT(dev);
				dev->m_alive_events++;
				DEBUG_MSG("Read another event from the same buffer -> ");
				DEBUG_EVENT(dev->m_evt_p, head);
				if(devset->al.t != INVALID_BUFFER_ID &&
				   dev->m_evt_p->ts < devset->m_devs[devset->al.t].m_evt_p->ts) {
					DEBUG_MSG("-- Insert event in the active list\n");
					add_to_active_list(devset, head, dev->m_evt_p->ts);
				} else {
					DEBUG_MSG("-- Insert event in the wait list\n");
					add_to_wait_list(devset, head);
				}
			}
		}
	}
	DEBUG_MSG("-----------------------------\n\n");

	if(devset->e_cache.len > 0) {
		DEBUG_MSG("[SEND PHASE]\nCache len: %d, pos:%d\n",
		          devset->e_cache.len,
		          devset->e_cache.pos);

		*event_ptr = devset->e_cache.map[devset->e_cache.pos].e_p;
		*buffer_id = devset->e_cache.map[devset->e_cache.pos].b_id;

		// Only when we don't have any more events in the cache and in the list we can advance the
		// buffer tail. In this way the producer can start again to fill the buffer.
		if(--(devset->m_devs[*buffer_id].m_alive_events) == 0) {
			DEBUG_MSG("[ADVANCE TAIL] For buf: %d, len:%d\n",
			          *buffer_id,
			          devset->m_devs[*buffer_id].m_sn_len);
			ASSERT(devset->m_devs[*buffer_id].m_sn_len == 0);
			ADVANCE_TAIL(&(devset->m_devs[*buffer_id]));
		}

		// We prepare the cache pos for the next iteration and we clean the cache if we reach the
		// limit.
		if(++devset->e_cache.pos == devset->e_cache.len) {
			devset->e_cache.len = 0;
			devset->e_cache.pos = 0;
			DEBUG_MSG("Cache cleaned.\n");
		}

		DEBUG_MSG("Send event -> ");
		DEBUG_EVENT((*event_ptr), (*buffer_id));
		DEBUG_MSG("Buffer usage %d\n", devset->m_devs[*buffer_id].m_alive_events);
		DEBUG_MSG("-----------------------------\n\n");
		return SCAP_SUCCESS;
	}

	// We populate active_list with the wait_list
	uint16_t curr = devset->wl_head;
	DEBUG_MSG("[SCRAPE WAIT LIST]\n%s\n",
	          curr != INVALID_BUFFER_ID ? "Try to iterate the wait list" : "Wait list is empty");
	while(curr != INVALID_BUFFER_ID) {
		// We need to remove the buffer ID from the wait list
		remove_head_wait_list(devset, curr);

		// We need to insert and sort the new buffer ID in the active list.
		add_to_active_list(devset, curr, devset->m_devs[curr].m_evt_p->ts);

		// Set the next element of the wait list that we need to scrape.
		curr = devset->wl_head;
	}
	DEBUG_MSG("-----------------------------\n\n");

	// If we have elements in the active list we fill again our cache.
	if(devset->al.h != INVALID_BUFFER_ID) {
		DEBUG_MSG("Active list is not empty -> go to Fill cache phase\n");
		goto FILL_CACHE_PHASE;
	}

	DEBUG_MSG("[REFILL PHASE]\n");
	return refill_active_list(devset);
}
