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

#include "debug_macro.h"
#include <assert.h>

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#if defined(__clang__)
#define __OPTIMIZE_O3
#else
#define __OPTIMIZE_O3 __attribute__((optimize("O3")))
#endif

static __always_inline void __OPTIMIZE_O3 add_to_wait_list(uint16_t id) {
	// We always add to the head
	DEBUG_MSG("Change head for wait list. Old head: %d, new head: %d\n", g_state.wl_head, id);
	g_state.buf_array[id] = g_state.wl_head;
	g_state.wl_head = id;
	DEBUG_WAIT_LIST();
}

// We want to remove `id` from the wait list. Returns the new next element of the new list layout.
static __always_inline uint16_t __OPTIMIZE_O3 remove_from_wait_list(uint16_t prev, uint16_t id) {
	if(prev == INVALID_BUFFER_ID) {
		DEBUG_MSG("Remove head from wait list. Old head: %d, new head: %d\n",
		          g_state.wl_head,
		          g_state.buf_array[id]);
		g_state.wl_head = g_state.buf_array[id];
	} else {
		DEBUG_MSG("Remove buf %d from wait list.\n", id);
		g_state.buf_array[prev] = g_state.buf_array[id];
	}
	DEBUG_WAIT_LIST();
	return g_state.buf_array[id];
}

// We remove only from the head in active list.
static __always_inline void __OPTIMIZE_O3 remove_head_from_active_list() {
	DEBUG_MSG("Remove head from active list. Old head: %d, new head: %d\n",
	          g_state.al.h,
	          g_state.buf_array[g_state.al.h]);
	g_state.al.h = g_state.buf_array[g_state.al.h];
	// if the head is invalid we invalidate also the tail
	if(g_state.al.h == INVALID_BUFFER_ID) {
		g_state.al.t = INVALID_BUFFER_ID;
	}
	DEBUG_ACTIVE_LIST();
}

static __always_inline void __OPTIMIZE_O3 add_to_active_list(uint16_t id, uint64_t ts) {
	// If the list is empty
	if(g_state.al.h == INVALID_BUFFER_ID) {
		g_state.al.h = id;
		g_state.al.t = id;
		g_state.buf_array[g_state.al.t] = INVALID_BUFFER_ID;
		DEBUG_MSG("Active list is empty. Populate it.\n");
		DEBUG_ACTIVE_LIST();
		return;
	}

	// If the new timestamp is the lowest in the list, we add it to the head
	// We use `<=` because events produced by different threads can have the same timestamp.
	// It's convenient to add the new event before the one with the same timestamp so we save some
	// time and we possibly continue on the same buffer.
	if(ts <= g_state.b_state[g_state.al.h].e_p->ts) {
		DEBUG_MSG("Add %d to head. actual ts: %ld <= head ts: %ld\n",
		          id,
		          ts,
		          g_state.b_state[g_state.al.h].e_p->ts);
		g_state.buf_array[id] = g_state.al.h;
		g_state.al.h = id;
		DEBUG_ACTIVE_LIST();
		return;
	}

	// If the new timestamp is the greatest in the list, we add it to the tail
	// We use `>=` because events produced by different threads can have the same timestamp.
	// In that case is not important in which order we process them because the 2 threads are not
	// correlated
	if(ts >= g_state.b_state[g_state.al.t].e_p->ts) {
		DEBUG_MSG("Add %d to tail. actual ts: %ld >= tail ts: %ld\n",
		          id,
		          ts,
		          g_state.b_state[g_state.al.t].e_p->ts);
		g_state.buf_array[g_state.al.t] = id;
		g_state.al.t = id;
		g_state.buf_array[g_state.al.t] = INVALID_BUFFER_ID;
		DEBUG_ACTIVE_LIST();
		return;
	}

	// We need to insert in the middle, head and tail cases are already excluded.
	// We start from the element after the head, we already know that the list is not empty
	// and that we don't need to insert a new head.
	uint16_t curr = g_state.buf_array[g_state.al.h];
	uint16_t prev = g_state.al.h;
	while(curr != INVALID_BUFFER_ID) {
		if(ts <= g_state.b_state[curr].e_p->ts) {
			DEBUG_MSG("Add %d before %d. actual ts: %ld, ts of %d: %ld\n",
			          id,
			          curr,
			          ts,
			          curr,
			          g_state.b_state[curr].e_p->ts);
			g_state.buf_array[id] = curr;
			g_state.buf_array[prev] = id;
			DEBUG_ACTIVE_LIST();
			return;
		}
		prev = curr;
		curr = g_state.buf_array[curr];
	}

	// We should never reach this point. It means that we are not able to sort by timestamp!
	assert(false);
}
