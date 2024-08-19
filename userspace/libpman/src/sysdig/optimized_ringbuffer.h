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

#include <state.h>
#include <driver/ppm_events_public.h>
#include <ringbuffer_definitions.h>
#include "list_operations.h"

static __always_inline void __OPTIMIZE_O3 get_first_ring_event(int pos) {
	struct ring *r = g_state.rb_manager->rings[pos];
	int *len_ptr = NULL;
	int len = 0;

	/* If the consumer reaches the producer update the producer position to
	 * get the newly collected events.
	 */
	if((g_state.cons_pos[pos] + g_state.b_state[pos].off) == g_state.prod_pos[pos]) {
		// We increment the producer position.
		g_state.prod_pos[pos] = smp_load_acquire(r->producer_pos);
		// If the consumer is still == producer it means we don't have new events.
		if((g_state.cons_pos[pos] + g_state.b_state[pos].off) == g_state.prod_pos[pos]) {
			g_state.b_state[pos].e_size = 0;
			g_state.b_state[pos].e_p = NULL;
			return;
		}
		// We have new event so we can continue.
	}

	len_ptr = r->data + ((g_state.cons_pos[pos] + g_state.b_state[pos].off) & r->mask);
	len = smp_load_acquire(len_ptr);

	/* The actual event is not yet committed */
	if(len & BPF_RINGBUF_BUSY_BIT) {
		g_state.b_state[pos].e_size = 0;
		g_state.b_state[pos].e_p = NULL;
		return;
	}

	/* the sample is not discarded kernel side. */
	if((len & BPF_RINGBUF_DISCARD_BIT) == 0) {
		/* We don't increment the offset of the buffer here because sometimes we
		 * want to read the same event multiple times.
		 */
		g_state.b_state[pos].e_size = roundup_len(len);
		g_state.b_state[pos].e_p = (void *)len_ptr + BPF_RINGBUF_HDR_SZ;
		return;
	} else {
		/* Today this should never happen, we don't discard event kernel side.
		 * If we start to do it we need to double-check our logic here.
		 * It is a problem for our algorithm because we are blocked on this event.
		 */
		assert(false);
		if(g_state.b_state[pos].off != 0) {
			// Do nothing, we need to wait until we reach this position with the consumer.
			g_state.b_state[pos].e_size = 0;
			g_state.b_state[pos].e_p = NULL;
			return;
		} else {
			/* Discard the event kernel side and update the consumer position */
			g_state.cons_pos[pos] += roundup_len(len);
			g_state.b_state[pos].e_size = 0;
			g_state.b_state[pos].e_p = NULL;
			smp_store_release(r->consumer_pos, g_state.cons_pos[pos]);
			return;
		}
	}
}

static __always_inline void __OPTIMIZE_O3
ring_buffer__sorted_linked_list(struct ring_buffer *rb,
                                struct ppm_evt_hdr **event_ptr,
                                int16_t *buffer_id) {
FILL_CACHE_PHASE:
	if(g_state.e_cache.len == 0) {
		uint16_t head = INVALID_BUFFER_ID;
		DEBUG_MSG("\n[FILL CACHE]\n");
		for(uint8_t c = 0; c < EVENT_CACHE_LIMIT; c++) {
			head = g_state.al.h;
			if(head == INVALID_BUFFER_ID) {
				DEBUG_MSG("Active list is empty\n");
				break;
			}

			DEBUG_MSG("Add event in the cache (len: %d) -> ", g_state.e_cache.len);
			DEBUG_EVENT(g_state.b_state[head].e_p, head);

			g_state.e_cache.map[g_state.e_cache.len].e_p = g_state.b_state[head].e_p;
			g_state.e_cache.map[g_state.e_cache.len].e_size = g_state.b_state[head].e_size;
			g_state.e_cache.map[g_state.e_cache.len].b_id = head;
			g_state.e_cache.len++;

			// We remove the buffer from the active list:
			// 1. If this buffer has other events and the active list is not empty and the timestamp
			// of the new event is less than the timestamp of the active list tail we insert the
			// buffer in the active list.
			// 2. Otherwise we insert the buffer in the wait list.
			remove_head_from_active_list();

			get_first_ring_event(head);
			DEBUG_MSG("Try to get a new event from buffer %d -> ", head);
			DEBUG_EVENT(g_state.b_state[head].e_p, head);
			if(g_state.b_state[head].e_p != NULL && g_state.al.t != INVALID_BUFFER_ID &&
			   g_state.b_state[head].e_p->ts < g_state.b_state[g_state.al.t].e_p->ts) {
				DEBUG_MSG("-- Insert event in the active list\n");
				// We increase the offset, because we have read the event.
				g_state.b_state[head].off += g_state.b_state[head].e_size;
				add_to_active_list(head, g_state.b_state[head].e_p->ts);
			} else {
				DEBUG_MSG("-- Insert event in the wait list\n");
				// We don't increase the offset here because we will read the event again when
				// iterating over the empty list.
				add_to_wait_list(head);
			}
		}
	}
	DEBUG_MSG("-----------------------------\n\n");

	if(g_state.e_cache.len > 0) {
		DEBUG_MSG("[SEND PHASE]\nCache len: %d, pos:%d\n",
		          g_state.e_cache.len,
		          g_state.e_cache.pos);

		// We skip `g_state.e_cache.pos = 0` since it means we still need to send the first event of
		// the cache.
		if(g_state.e_cache.pos > 0) {
			// We release the memory of the event of the previous iteration.
			uint16_t prev_buf_id = g_state.e_cache.map[g_state.e_cache.pos - 1].b_id;
			uint32_t prev_e_size = g_state.e_cache.map[g_state.e_cache.pos - 1].e_size;

			struct ring *r = rb->rings[prev_buf_id];
			g_state.cons_pos[prev_buf_id] += prev_e_size;
			g_state.b_state[prev_buf_id].off -= prev_e_size;
			DEBUG_MSG("Release memory for event %ld on buf %d. New offset on the buf: %ld\n",
			          g_state.e_cache.map[g_state.e_cache.pos - 1].e_p->ts,
			          prev_buf_id,
			          g_state.b_state[prev_buf_id].off);
			smp_store_release(r->consumer_pos, g_state.cons_pos[prev_buf_id]);
		}

		// We have no more events in the cache to send.
		if(g_state.e_cache.pos == g_state.e_cache.len) {
			g_state.e_cache.len = 0;
			g_state.e_cache.pos = 0;
			DEBUG_MSG("Cache cleaned. Go to fill cache phase.\n-----------------------------\n\n");
			goto FILL_CACHE_PHASE;
		}

		*event_ptr = g_state.e_cache.map[g_state.e_cache.pos].e_p;
		*buffer_id = g_state.e_cache.map[g_state.e_cache.pos].b_id;
		g_state.e_cache.pos++;
		DEBUG_MSG("Send event -> ");
		DEBUG_EVENT((*event_ptr), (*buffer_id));
		DEBUG_MSG("-----------------------------\n\n");
		return;
	}

	// We loop over the buffer without previous events and we search for possible new events.
	// - If we find a new event we remove the buffer from the wait list and we add it to the active
	// list. We sort the new event inside the list.
	// - If we don't find a new event we keep the buffer in the wait list.
	uint16_t curr = g_state.wl_head;
	uint16_t prev = INVALID_BUFFER_ID;
	uint16_t next = INVALID_BUFFER_ID;
	DEBUG_MSG("[SCRAPE WAIT LIST]\n%s\n",
	          curr != INVALID_BUFFER_ID ? "Try to iterate the wait list" : "Wait list is empty");
	while(curr != INVALID_BUFFER_ID) {
		get_first_ring_event(curr);
		if(g_state.b_state[curr].e_p == NULL) {
			DEBUG_MSG("buffer %d without events\n", curr);
			prev = curr;
			curr = g_state.buf_array[curr];
			continue;
		} else {
			DEBUG_EVENT(g_state.b_state[curr].e_p, curr);

			// We increase the offset, because we have read the event.
			g_state.b_state[curr].off += g_state.b_state[curr].e_size;

			// We need to remove the curr id from the wait list
			// We need to do this before moving the id to the active list otherwise we will lose the
			// next pointer. We need the prev to readapt the wait list. We don't touch `prev` in
			// this case since it will remain the same.
			next = remove_from_wait_list(prev, curr);

			// We need to insert and sort the id in the active list.
			add_to_active_list(curr, g_state.b_state[curr].e_p->ts);

			// Set the next element of the wait list that we need to scrape.
			curr = next;
		}
	}

	if(g_state.al.h != INVALID_BUFFER_ID) {
		// It means we have at least one event in our buffers.
		DEBUG_MSG("Active list is not empty -> go to Fill cache phase\n");
		goto FILL_CACHE_PHASE;
	}

	*event_ptr = NULL;
	*buffer_id = -1;
	DEBUG_MSG(
	        "No events to send. Send a NULL pointer with id -1\n-----------------------------\n\n");
}

static __always_inline int __OPTIMIZE_O3 ring_buffer__populate_state() {
	g_state.buf_array = (uint16_t *)calloc(g_state.n_required_buffers, sizeof(uint16_t));
	g_state.b_state = (buffer_state *)calloc(g_state.n_required_buffers, sizeof(buffer_state));
	if(g_state.buf_array == NULL || g_state.b_state == NULL) {
		return errno;
	}

	DEBUG_MSG("[INIT PHASE]: Fill no-event buffers list\n");
	for(int i = 0; i < g_state.n_required_buffers; i++) {
		add_to_wait_list(i);
	}
	DEBUG_MSG("-----------------------------\n\n");
	return 0;
}
