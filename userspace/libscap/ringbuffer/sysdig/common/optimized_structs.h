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

#include <stdint.h>

// The actual cache has 16 elements.
#define EVENT_CACHE_LIMIT 16

// We use `2^16 - 1` as invalid buf id
#define INVALID_BUFFER_ID (1 << 16) - 1

// These are the head and tail of an array list used to keep track of not empty buffers while we are
// scraping
typedef struct active_list {
	uint16_t h;  // head
	uint16_t t;  // tail
} active_list;

// NOTE: Used only in the modern ebpf.
// This reflects the actual state of the buffer.
typedef struct buffer_state {
	struct ppm_evt_hdr *e_p;  // pointer to the event we have at the head of the buffer
	uint32_t e_size;  // size of the above event. The max event size is 2^16 but since we could have
	                  // also the external ringbuf header it's better to use 32 bits.
	unsigned long off;  // offset computed from the current consumer position. We read the next
	                    // event in the buffer at 'cons_pos + off')
} buffer_state;

typedef struct cache_entry {
	struct ppm_evt_hdr *e_p;  // pointer to the event we will send.
	uint32_t e_size;          // size of the above event. Used only in the modern ebpf.
	uint16_t b_id;            // buffer where we found the event.
} cache_entry;

typedef struct event_cache {
	cache_entry map[EVENT_CACHE_LIMIT];
	uint8_t len;
	uint8_t pos;
} event_cache;
