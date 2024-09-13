#include <libscap/engine/udig2/udig-int.h>
#include <libscap/engine/udig2/udig-open.h>
#include <libscap/scap.h>
#include <libscap/ringbuffer/ringbuffer.h>
#include <libscap/strerror.h>

#include <sys/mman.h>
#include <sys/un.h>
#include <sys/user.h>
#include <time.h>

///////////////////////////////////////////////////////////////////////////////
// The following function maps the ring buffer and the ring buffer
// descriptors into the address space of this process.
// This is the buffer that will be consumed by scap.
///////////////////////////////////////////////////////////////////////////////
int32_t udig_map_ring(struct scap_device *dev,
                      uint32_t ring_size,
                      char *error,
                      int ring_access_flags) {
	struct scap_ringbuffer_info *info;
	uint32_t mem_size = sizeof(*info);

	//
	// Map the ring. This is a multi-step process because we want to map two
	// consecutive copies of the same memory to reuse the driver fillers, which
	// expect to be able to go past the end of the ring.
	// First of all, allocate enough space for the 2 copies. This allows us
	// to find an area of consecutive memory that is big enough.
	//
	char *buf1 = (char *)mmap(NULL, ring_size * 2, PROT_NONE, MAP_SHARED, dev->m_fd, 0);
	if((long)buf1 < 0) {
		close(dev->m_fd);
		return scap_errprintf(error, -(long)buf1, "udig_map_ring double mmap failed");
	}

	// Map the first ring copy at exactly the beginning of the previously
	// allocated area, forcing it with MAP_FIXED.
	dev->m_buffer =
	        (char *)mmap(buf1, ring_size, ring_access_flags, MAP_SHARED | MAP_FIXED, dev->m_fd, 0);
	if(dev->m_buffer != buf1) {
		if((long)dev->m_buffer > 0) {
			munmap(dev->m_buffer, ring_size);
		}
		munmap(buf1, ring_size * 2);
		close(dev->m_fd);
		return scap_errprintf(error, -(long)dev->m_buffer, "udig_map_ring first half mmap failed");
	}

	// Map the second ring copy just after the end of the first one.
	char *buf2 = buf1 + ring_size;
	char *ring2 =
	        (char *)mmap(buf2, ring_size, ring_access_flags, MAP_SHARED | MAP_FIXED, dev->m_fd, 0);
	if(ring2 != buf2) {
		close(dev->m_fd);
		munmap(dev->m_buffer, ring_size * 2);
		if((long)ring2 > 0) {
			munmap(ring2, ring_size);
		}
		return scap_errprintf(
		        error,
		        -(long)ring2,
		        "udig_map_ring second half mmap failed, needed %p, obtained %p, base=%p",
		        buf2,
		        ring2,
		        buf1);
	}

	//
	// Map the descriptor memory
	//
	uint8_t *descs = (uint8_t *)
	        mmap(NULL, mem_size, PROT_READ | PROT_WRITE, MAP_SHARED, dev->m_fd, ring_size);
	if((long)descs < 0) {
		munmap(dev->m_buffer, ring_size * 2);
		close(dev->m_fd);
		return scap_errprintf(error,
		                      -(long)descs,
		                      "udig_map_ring_descriptors mmap ring_descs failed");
	}

	info = (struct scap_ringbuffer_info *)descs;
	dev->m_bufinfo = &info->m_bufinfo;
	dev->m_bufinfo_size = mem_size;
	dev->m_mmap_size = 2 * ring_size;
	dev->m_buffer_size = ring_size;

	//
	// Locate the ring buffer status object
	//
	dev->m_bufstatus = &info->m_ring_buffer_status;

	//
	// Note that, according to the man page of shm_open, we are guaranteed that
	// the content of the buffer will initially be initialized to 0.
	//

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	dev->m_bufstatus->m_writer_tid = 0;
	dev->m_bufstatus->m_buffer_size = ring_size;
	dev->m_bufstatus->m_last_event_time = now;
	return SCAP_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// free the ring buffer and the ring buffer descriptor.
///////////////////////////////////////////////////////////////////////////////
void scap_udig_close_dev(struct scap_device *dev, struct scap_stats *stats) {
	if(dev->m_state != DEV_OPEN) {
		return;
	}

	dev->m_state = DEV_CLOSING;
	__sync_synchronize();

	if(stats) {
		struct ppm_ring_buffer_info *bufinfo = dev->m_bufinfo;
		stats->n_evts += bufinfo->n_evts;
		stats->n_drops_buffer += bufinfo->n_drops_buffer;
		stats->n_drops_pf += bufinfo->n_drops_pf;
		stats->n_drops += bufinfo->n_drops_buffer + bufinfo->n_drops_pf;
		stats->n_preemptions += bufinfo->n_preemptions;
	}

	devset_close_device(dev);

	dev->m_buffer = MAP_FAILED;
	dev->m_bufinfo = NULL;
	dev->m_fd = -1;
	__sync_synchronize();
	dev->m_state = DEV_CLOSED;
}
