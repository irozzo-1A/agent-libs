// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#include <libscap/scap_log.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <driver/modern_bpf/shared_definitions/struct_definitions.h>
#include <bpf_probe.skel.h>
#include <unistd.h>
#include <errno.h>
#include <libpman.h>

#define MAX_ERROR_MESSAGE_LEN 200

/* Pay attention this need to be bumped every time we add a new bpf program that is directly
 * attached into the kernel */
#define MODERN_BPF_PROG_ATTACHED_MAX 9

#define BPF_LOG_BIG_BUF_SIZE \
	(UINT32_MAX >> 8) /* Recommended log buffer size, taken from libbpf. Used for verifier logs */
#define BPF_LOG_SMALL_BUF_SIZE 8192 /* Used for libbpf non-verifier logs */

struct metrics_v2;

struct __attribute__((aligned(64))) ringbuffer_pos {
	unsigned long consumer;
	unsigned long producer;
};

struct internal_state {
	struct bpf_probe* skel;          /* bpf skeleton with all programs and maps. */
	struct ring_buffer* rb_manager;  /* ring_buffer manager with all ring buffers. */
	pman_ringbuf_t* ringbuf_handles; /* Ring buffer handles. Each managed ring buffer is associated
	                                    with a handle. */
	uint16_t n_reserved_ringbuf_handles; /* Number of reserved ring buffer handles. Always <= the
	                                        total number of ring buffer handles.  */
	int16_t n_possible_cpus;             /* number of possible system CPUs (online and not). */
	int16_t n_interesting_cpus;  /* according to userspace configuration we can consider only online
	                    CPUs or all  available CPUs. */
	bool allocate_online_only;   /* If true we allocate ring buffers only for online CPUs */
	uint32_t n_required_buffers; /* number of ring buffers we need to allocate */
	uint16_t cpus_for_each_buffer; /* Users want a ring buffer every `cpus_for_each_buffer` CPUs.
	                                  Here 0 means that the user specified an absolute number for
	                                  the ring buffers. */
	struct ringbuffer_pos* ringbuf_positions; /* every ring buffer has a producer and a consumer
	                                   position. */
	int32_t inner_ringbuf_map_fd;   /* inner map used to configure the ring buffer array before
	                                   loading phase. */
	unsigned long buffer_bytes_dim; /* dimension of a single ring buffer in bytes. */
	int last_ring_read; /* Last ring from which we have correctly read an event. Could be `-1` if
	               there were no successful reads. */
	unsigned long last_event_size; /* Last event correctly read. Could be `0` if there were no
	                                  successful reads. */

	/* Stats v2 utilities */
	int32_t attached_progs_fds[MODERN_BPF_PROG_ATTACHED_MAX]; /* file descriptors of attached
	                                 programs, used to collect stats */
	struct metrics_v2* stats; /* array of stats collected by libpman */
	uint32_t nstats;          /* number of stats */
	char* log_buf;            /* buffer used to store logs before sending them to the log_fn */
	size_t log_buf_size;      /* size of the log buffer */
	falcosecurity_log_fn log_fn;
};

extern struct internal_state g_state;

extern void pman_print_error(const char* error_message);
extern void pman_print_msg(enum falcosecurity_log_severity level, const char* error_message);
extern bool pman_is_cpus_to_ringbufs_mapping_disabled(void);
