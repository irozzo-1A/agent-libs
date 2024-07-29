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

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#if defined(__clang__)
#define __OPTIMIZE_O3
#else
#define __OPTIMIZE_O3 __attribute__((optimize("O3")))
#endif

static __always_inline void __OPTIMIZE_O3 add_to_active_list(struct scap_device_set* devset,
                                                             uint16_t id,
                                                             uint64_t ts) {
	// If the list is empty
	if(devset->al.h == INVALID_BUFFER_ID) {
		devset->al.h = id;
		devset->al.t = id;
		devset->buf_array[devset->al.t] = INVALID_BUFFER_ID;
		DEBUG_MSG("Active list is empty. Populate it.\n");
		DEBUG_ACTIVE_LIST();
		return;
	}

	// If the new timestamp is the lowest in the list, we add it to the head
	// We use `<=` because events produced by different threads can have the same timestamp.
	// It's convenient to add the new event before the one with the same timestamp so we save some
	// time and we possibly continue on the same buffer.
	if(ts <= devset->m_devs[devset->al.h].m_evt_p->ts) {
		DEBUG_MSG("Add %d to head. actual ts: %ld <= head ts: %ld\n",
		          id,
		          ts,
		          devset->m_devs[devset->al.h].m_evt_p->ts);
		devset->buf_array[id] = devset->al.h;
		devset->al.h = id;
		DEBUG_ACTIVE_LIST();
		return;
	}

	// If the new timestamp is the greatest in the list, we add it to the tail
	if(ts >= devset->m_devs[devset->al.t].m_evt_p->ts) {
		DEBUG_MSG("Add %d to tail. actual ts: %ld >= tail ts: %ld\n",
		          id,
		          ts,
		          devset->m_devs[devset->al.t].m_evt_p->ts);
		devset->buf_array[devset->al.t] = id;
		devset->al.t = id;
		devset->buf_array[devset->al.t] = INVALID_BUFFER_ID;
		DEBUG_ACTIVE_LIST();
		return;
	}

	// We need to insert in the middle, head and tail cases are already excluded.
	// We start from the element after the head, we already know that the list is not empty
	// and that we don't need to insert a new head.
	uint16_t curr = devset->buf_array[devset->al.h];
	uint16_t prev = devset->al.h;
	while(curr != INVALID_BUFFER_ID) {
		if(ts <= devset->m_devs[curr].m_evt_p->ts) {
			DEBUG_MSG("Add %d before %d. actual ts: %ld, ts of %d: %ld\n",
			          id,
			          curr,
			          ts,
			          curr,
			          devset->m_devs[curr].m_evt_p->ts);
			devset->buf_array[id] = curr;
			devset->buf_array[prev] = id;
			DEBUG_ACTIVE_LIST();
			return;
		}
		prev = curr;
		curr = devset->buf_array[curr];
	}

	// We should never reach this point. It means that we are not able to sort by timestamp!
	assert(false);
}

// We remove only from the head in the active list.
static __always_inline void __OPTIMIZE_O3
remove_head_from_active_list(struct scap_device_set* devset) {
	DEBUG_MSG("Remove head from 'active list'. Old head: %d, new head: %d\n",
	          devset->al.h,
	          devset->buf_array[devset->al.h]);
	devset->al.h = devset->buf_array[devset->al.h];
	// if the head is invalid we invalidate also the tail
	if(devset->al.h == INVALID_BUFFER_ID) {
		devset->al.t = INVALID_BUFFER_ID;
	}
	DEBUG_ACTIVE_LIST();
}

static __always_inline void __OPTIMIZE_O3 add_to_wait_list(struct scap_device_set* devset,
                                                           uint16_t id) {
	// We always add to the head
	DEBUG_MSG("-- Change head for wait list. Old head: %d, new head: %d\n", devset->wl_head, id);
	devset->buf_array[id] = devset->wl_head;
	devset->wl_head = id;
	DEBUG_WAIT_LIST();
}

static __always_inline void __OPTIMIZE_O3 remove_head_wait_list(struct scap_device_set* devset,
                                                                uint16_t id) {
	DEBUG_MSG("-- Remove head from wait list. Old head: %d, new head: %d\n",
	          devset->wl_head,
	          devset->buf_array[id]);
	devset->wl_head = devset->buf_array[id];
	DEBUG_WAIT_LIST();
}
