#ifndef UDIG_OPEN_H
#define UDIG_OPEN_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>

#include <driver/ppm_ringbuffer.h>
#include <libscap/ringbuffer/devset.h>

#define UDIG_RING_SIZE (1024 * 1024)

struct udig_consumer_t {
	uint32_t seq;
	uint32_t snaplen;
	uint32_t sampling_ratio;
	bool do_dynamic_snaplen;
	uint32_t sampling_interval;
	int is_dropping;
	int dropping_mode;
	volatile int need_to_insert_drop_e;
	volatile int need_to_insert_drop_x;
	uint16_t fullcapture_port_range_start;
	uint16_t fullcapture_port_range_end;
	uint16_t statsd_port;
};

enum ring_state {
	RING_CAPTURING = 0,
	RING_STARTING = 1,
	RING_STOPPED = 2,
};

struct udig_syscall_bitmap {
	size_t m_size;
	uint8_t m_bitmap[0];
} __attribute__((aligned(256)));

struct udig_ring_buffer_status {
	volatile uint64_t m_writer_tid;
	volatile uint32_t m_buffer_size;
	volatile enum ring_state m_state;
	struct udig_consumer_t m_consumer;
	// this shouldn't really be mapped into the producer,
	// but we don't have a good place that's udig2 specific
	// (we'd have to put it in scap_device)
	volatile struct timespec m_last_event_time;

	// in an ideal world, this would be a reference counter,
	// but we cannot track all exits properly (e.g. when
	// a process exits, all its threads exit, but we don't know
	// how many; same for execve).
	//
	// We should also update the refcount on fatal signals
	// but that's not possible either. So we have this soft
	// counter that at least tries to keep track of when
	// the refcount would go down and check the ringbuffer
	// lock then.
	volatile uint32_t m_new_exits;

	volatile struct udig_syscall_bitmap m_syscall_bitmap;
};

struct scap_ringbuffer_info {
	struct ppm_ring_buffer_info m_bufinfo;
	struct udig_ring_buffer_status m_ring_buffer_status;
};

// The syscall bitmap has variable size, so it should be the last member of scap_ringbuffer_info
// so let's align it to 256 bytes, leaving plenty of room for expansion of the previous fields.
// At the time of this writing, all the previous fields sum up to 340 bytes.
//
// If we do exceed another 256 bytes, we can just change the assert below, but that breaks binary
// compatibility and needs to be coordinated with libscap-hayabusa.
//
// The size of the bitmap is negotiated between the producer and consumer (set by the consumer,
// really) and the upper limit is PAGE_SIZE - the offset. That works out to 3584 bytes (28672
// bits), which should be plenty.
_Static_assert(offsetof(struct scap_ringbuffer_info, m_ring_buffer_status.m_syscall_bitmap) == 512,
               "syscall bitmap must be at offset 512");

int32_t udig_map_ring(struct scap_device *dev,
                      uint32_t ring_size,
                      char *error,
                      int ring_access_flags);

struct scap_stats;

void scap_udig_close_dev(struct scap_device *dev, struct scap_stats *stats);

#endif  // UDIG_OPEN_H
