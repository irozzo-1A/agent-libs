#include <libscap/engine/udig2/udig-int.h>

#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libscap/scap.h>
#include <libscap/ringbuffer/devset.h>
#include <libscap/strerror.h>

void scap_udig_init(struct scap_udig *handle) {
	handle->settings.dropping_mode = 0;
	handle->settings.snaplen = RW_SNAPLEN;
	handle->settings.sampling_ratio = 1;
	handle->settings.sampling_interval = 1000000;
	handle->settings.is_dropping = 0;
	handle->settings.do_dynamic_snaplen = false;
	handle->settings.need_to_insert_drop_e = 0;
	handle->settings.need_to_insert_drop_x = 0;
	handle->settings.fullcapture_port_range_start = 0;
	handle->settings.fullcapture_port_range_end = 0;
	handle->settings.statsd_port = PPM_PORT_STATSD;
}

///////////////////////////////////////////////////////////////////////////////
// Capture control helpers.
///////////////////////////////////////////////////////////////////////////////
void udig_begin_capture_dev(struct scap_device *dev,
                            struct udig_consumer_t *settings,
                            char *error) {
	static volatile uint32_t seq_counter = 0x55550000;

	struct udig_ring_buffer_status *rbs = dev->m_bufstatus;
	struct ppm_ring_buffer_info *rbi = dev->m_bufinfo;

	if(!__sync_bool_compare_and_swap(&rbs->m_state, RING_STOPPED, RING_STARTING)) {
		// either the ring is already capturing, or another thread is inside
		// this function already
		return;
	}

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	dev->m_lastreadsize = 0;
	dev->m_sn_len = 0;
	rbi->tail = rbi->head;
	rbi->n_evts = 0;
	rbi->n_drops_buffer = 0;

	//
	// Initialize the consumer
	//
	struct udig_consumer_t *consumer = &(rbs->m_consumer);
	memcpy(consumer, settings, sizeof(*settings));

	consumer->seq = __atomic_fetch_add(&seq_counter, 1, __ATOMIC_RELAXED);
	consumer->is_dropping = 0;
	consumer->need_to_insert_drop_e = 0;
	consumer->need_to_insert_drop_x = 0;

	//
	// Initialize the ring
	//
	rbs->m_last_event_time = now;

	__sync_synchronize();
	rbs->m_state = RING_CAPTURING;
}

int32_t scap_udig_start_capture(struct scap_engine_handle engine) {
	struct scap_udig *handle = engine.m_handle;
	handle->m_udig_capturing = true;
	__sync_synchronize();

	for(int i = 0; i < handle->m_dev_set.m_ndevs; ++i) {
		struct scap_device *dev = &handle->m_dev_set.m_devs[i];
		if(dev->m_state != DEV_OPEN) {
			continue;
		}

		udig_begin_capture_dev(dev, &handle->settings, handle->m_lasterr);
	}

	return SCAP_SUCCESS;
}

int32_t scap_udig_stop_capture(struct scap_engine_handle engine) {
	struct scap_udig *handle = engine.m_handle;
	handle->m_udig_capturing = false;
	__sync_synchronize();

	for(int i = 0; i < handle->m_dev_set.m_ndevs; ++i) {
		struct scap_device *dev = &handle->m_dev_set.m_devs[i];
		if(dev->m_state != DEV_OPEN) {
			continue;
		}

		struct udig_ring_buffer_status *rbs = dev->m_bufstatus;
		while(1) {
			enum ring_state state =
			        __sync_val_compare_and_swap(&rbs->m_state, RING_CAPTURING, RING_STOPPED);
			if(state == RING_STOPPED || state == RING_CAPTURING) {
				break;
			}
			usleep(1000);
		}
	}
	return SCAP_SUCCESS;
}

static uint32_t scap_udig_set_snaplen(struct scap_udig *handle, uint32_t snaplen) {
	handle->settings.snaplen = snaplen;
	for(int i = 0; i < handle->m_dev_set.m_ndevs; ++i) {
		struct scap_device *dev = &handle->m_dev_set.m_devs[i];
		if(dev->m_state != DEV_OPEN) {
			continue;
		}
		dev->m_bufstatus->m_consumer.snaplen = snaplen;
	}
	return SCAP_SUCCESS;
}

static int32_t scap_udig_set_dropping_mode(struct scap_udig *handle,
                                           uint32_t sampling_ratio,
                                           bool dropping_mode) {
	if(!dropping_mode) {
		sampling_ratio = 1;
	}

	if(sampling_ratio != 1 && sampling_ratio != 2 && sampling_ratio != 4 && sampling_ratio != 8 &&
	   sampling_ratio != 16 && sampling_ratio != 32 && sampling_ratio != 64 &&
	   sampling_ratio != 128) {
		return scap_errprintf(handle->m_lasterr, 0, "invalid sampling ratio %u", sampling_ratio);
	}

	handle->settings.dropping_mode = dropping_mode;
	handle->settings.sampling_interval = 1000000000 / sampling_ratio;
	handle->settings.sampling_ratio = sampling_ratio;
	for(int i = 0; i < handle->m_dev_set.m_ndevs; ++i) {
		struct scap_device *dev = &handle->m_dev_set.m_devs[i];
		if(dev->m_state != DEV_OPEN) {
			continue;
		}

		struct udig_consumer_t *consumer = &dev->m_bufstatus->m_consumer;
		consumer->dropping_mode = dropping_mode;

		consumer->sampling_interval = 1000000000 / sampling_ratio;
		consumer->sampling_ratio = sampling_ratio;
	}

	return SCAP_SUCCESS;
}

static int32_t scap_udig_set_dynamic_snaplen(struct scap_udig *handle, bool enable) {
	handle->settings.do_dynamic_snaplen = enable;
	for(int i = 0; i < handle->m_dev_set.m_ndevs; ++i) {
		struct scap_device *dev = &handle->m_dev_set.m_devs[i];
		if(dev->m_state != DEV_OPEN) {
			continue;
		}

		struct udig_consumer_t *consumer = &dev->m_bufstatus->m_consumer;
		consumer->do_dynamic_snaplen = enable;
	}
	return SCAP_SUCCESS;
}

static int32_t scap_udig_set_fullcapture_port_range(struct scap_udig *handle,
                                                    uint16_t range_start,
                                                    uint16_t range_end) {
	handle->settings.fullcapture_port_range_start = range_start;
	handle->settings.fullcapture_port_range_end = range_end;
	for(int i = 0; i < handle->m_dev_set.m_ndevs; ++i) {
		struct scap_device *dev = &handle->m_dev_set.m_devs[i];
		if(dev->m_state != DEV_OPEN) {
			continue;
		}

		struct udig_consumer_t *consumer = &dev->m_bufstatus->m_consumer;
		consumer->fullcapture_port_range_start = range_start;
		consumer->fullcapture_port_range_end = range_end;
	}
	return SCAP_SUCCESS;
}

static int32_t scap_udig_set_statsd_port(struct scap_udig *handle, const uint16_t port) {
	handle->settings.statsd_port = port;
	for(int i = 0; i < handle->m_dev_set.m_ndevs; ++i) {
		struct scap_device *dev = &handle->m_dev_set.m_devs[i];
		if(dev->m_state != DEV_OPEN) {
			continue;
		}

		struct udig_consumer_t *consumer = &dev->m_bufstatus->m_consumer;
		consumer->statsd_port = port;
	}
	return SCAP_SUCCESS;
}

static int32_t scap_udig_set_syscall_mask(struct scap_udig *handle, uint32_t op, uint32_t sc) {
	uint32_t native_sc = scap_ppm_sc_to_native_id(sc);
	if(native_sc == (uint32_t)-1) {
		// not a syscall
		return SCAP_SUCCESS;
	}

	size_t byte = native_sc / 8;
	size_t bit = native_sc % 8;

	if(byte >= sizeof(handle->m_bitmap)) {
		return scap_errprintf(handle->m_lasterr,
		                      0,
		                      "syscall number %d (sc %d) too large",
		                      native_sc,
		                      sc);
	}

	if(op == SCAP_PPM_SC_MASK_SET) {
		handle->m_bitmap[byte] |= (1 << bit);
		if(handle->m_bitmap_size < byte) {
			handle->m_bitmap_size = byte;
		}
	} else if(op == SCAP_PPM_SC_MASK_UNSET) {
		handle->m_bitmap[byte] &= ~(1 << bit);
	} else {
		return scap_errprintf(handle->m_lasterr, 0, "invalid syscall mask operation %d", op);
	}

	for(int i = 0; i < handle->m_dev_set.m_ndevs; ++i) {
		struct scap_device *dev = &handle->m_dev_set.m_devs[i];
		if(dev->m_state != DEV_OPEN) {
			continue;
		}

		// We do not need the ops to be atomic (since we should be the only writer)
		// but we do the memory writes to happen.
		//
		// Also, while there is an atomic or, there's no atomic and :( (nand doesn't quite fit)
		volatile struct udig_syscall_bitmap *bitmap = &dev->m_bufstatus->m_syscall_bitmap;
		if(bitmap->m_size < byte) {
			bitmap->m_size = byte;
		}

		if(op == SCAP_PPM_SC_MASK_SET) {
			bitmap->m_bitmap[byte] |= (1 << bit);
		} else {
			bitmap->m_bitmap[byte] &= ~(1 << bit);
		}
	}

	return SCAP_SUCCESS;
}

int32_t scap_udig_configure(struct scap_engine_handle engine,
                            enum scap_setting setting,
                            unsigned long arg1,
                            unsigned long arg2) {
	struct scap_udig *handle = engine.m_handle;
	switch(setting) {
	case SCAP_SAMPLING_RATIO:
		return scap_udig_set_dropping_mode(handle, arg1, arg2);
	case SCAP_SNAPLEN:
		return scap_udig_set_snaplen(handle, arg1);
	case SCAP_DYNAMIC_SNAPLEN:
		return scap_udig_set_dynamic_snaplen(handle, arg1);
	case SCAP_FULLCAPTURE_PORT_RANGE:
		return scap_udig_set_fullcapture_port_range(handle, arg1, arg2);
	case SCAP_STATSD_PORT:
		return scap_udig_set_statsd_port(handle, arg1);
	case SCAP_PPM_SC_MASK:
		return scap_udig_set_syscall_mask(handle, arg1, arg2);

	default:
		return scap_errprintf(handle->m_lasterr, 0, "not supported on udig");
	}
}
