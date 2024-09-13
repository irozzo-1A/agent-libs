#include <libscap/engine/udig2/udig-int.h>
#include <libscap/scap.h>
#include <libscap/ringbuffer/devset.h>
#include <libscap/ringbuffer/ringbuffer.h>

#include <fcntl.h>

static inline bool should_close_device(struct scap_device *dev, struct timespec *now) {
	if(dev->m_bufinfo->head != dev->m_bufinfo->tail) {
		// still has unconsumed events
		return false;
	}

	uint32_t zero = 0;
	uint32_t new_exits = 0;
	__atomic_exchange(&dev->m_bufstatus->m_new_exits, &zero, &new_exits, __ATOMIC_RELAXED);

	// Not entering this `if` block means that a producer for this ring buffer has exited recently.
	// In that case, do not wait for 5 seconds but check the ring buffer lock immediately.
	if(new_exits == 0) {
		// no new exits
		struct timespec last_event = dev->m_bufstatus->m_last_event_time;

		if(now->tv_sec - last_event.tv_sec <= 5)  // under 5 seconds since last event?
		{
			return false;
		}
	}

	struct flock lock = {
	        .l_type = F_WRLCK,
	        .l_start = 1,
	        .l_len = 1,
	        .l_whence = 0,
	};

	int res = fcntl(dev->m_fd, F_GETLK, &lock);
	if(res == 0 && lock.l_type == F_UNLCK) {
		return true;
	}
	dev->m_bufstatus->m_last_event_time = *now;

	return false;
}

__attribute__((flatten)) int32_t scap_udig_next(struct scap_engine_handle engine,
                                                scap_evt **pevent,
                                                uint16_t *pdevid,
                                                uint32_t *pflags) {
	struct scap_udig *handle = engine.m_handle;
	int32_t res = ringbuffer_next(&handle->m_dev_set, pevent, pdevid, pflags);

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	if(*pdevid != 65535) {
		struct scap_device *dev = &handle->m_dev_set.m_devs[*pdevid];
		dev->m_bufstatus->m_last_event_time = now;
	}

	for(int i = 0; i < handle->m_dev_set.m_ndevs; ++i) {
		struct scap_device *dev = &handle->m_dev_set.m_devs[i];
		if(dev->m_state != DEV_OPEN) {
			continue;
		}

		if(should_close_device(dev, &now)) {
			scap_udig_close_dev(dev, &handle->m_dev_set.old_stats);
			ASSERT(handle->m_dev_set.m_used_devs > 0);
			handle->m_dev_set.m_used_devs--;
		}
	}

	if(handle->m_dev_set.m_used_devs == handle->m_dev_set.m_alloc_devs) {
		devset_grow(&handle->m_dev_set, handle->m_dev_set.m_alloc_devs * 2, handle->m_lasterr);
	}

	return res;
}
