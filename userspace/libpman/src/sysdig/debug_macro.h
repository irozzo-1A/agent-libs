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

#include <stdio.h>
#include <stdint.h>

// Debugging Macros
#define DEBUGGING 0

#if DEBUGGING
#define DEBUG_MSG(...) printf(__VA_ARGS__)

#define DEBUG_EVENT(event, ring_id)                                    \
	if(event == NULL) {                                                \
		DEBUG_MSG("[NULL Event] buf: %d\n", ring_id);                  \
	} else {                                                           \
		DEBUG_MSG("[Event] ts: %ld, buf: %d\n", (event)->ts, ring_id); \
	}

#define DEBUG_ACTIVE_LIST()                                                            \
	DEBUG_MSG("Active list: ");                                                        \
	for(uint16_t i = g_state.al.h; i != INVALID_BUFFER_ID; i = g_state.buf_array[i]) { \
		if(g_state.buf_array[i] == INVALID_BUFFER_ID) {                                \
			DEBUG_MSG("%d", i);                                                        \
		} else {                                                                       \
			DEBUG_MSG("%d->", i);                                                      \
		}                                                                              \
	}                                                                                  \
	DEBUG_MSG(" (head: %d,tail: %d)\n", g_state.al.h, g_state.al.t);

#define DEBUG_WAIT_LIST()                                                                 \
	DEBUG_MSG("Wait list: ");                                                             \
	for(uint16_t i = g_state.wl_head; i != INVALID_BUFFER_ID; i = g_state.buf_array[i]) { \
		if(g_state.buf_array[i] == INVALID_BUFFER_ID) {                                   \
			DEBUG_MSG("%d", i);                                                           \
		} else {                                                                          \
			DEBUG_MSG("%d->", i);                                                         \
		}                                                                                 \
	}                                                                                     \
	DEBUG_MSG("\n");

#define DEBUG_LISTS(list_type) \
	DEBUG_WAIT_LIST();         \
	DEBUG_ACTIVE_LIST();       \
	DEBUG_MSG("\n");

#else
#define DEBUG_MSG(...)
#define DEBUG_EVENT(event, ring_id)
#define DEBUG_ACTIVE_LIST()
#define DEBUG_WAIT_LIST()
#define DEBUG_LISTS(list_type)
#endif
