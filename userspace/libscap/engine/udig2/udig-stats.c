#include <libscap/engine/udig2/udig-int.h>
#include <libscap/scap.h>
#include <libscap/ringbuffer/ringbuffer.h>

int32_t scap_udig_get_stats(struct scap_engine_handle engine, struct scap_stats *stats) {
	struct scap_device_set *devset = &HANDLE(engine)->m_dev_set;
	uint32_t j;

	for(j = 0; j < devset->m_ndevs; j++) {
		scap_device *dev = &devset->m_devs[j];
		if(dev->m_state != DEV_OPEN) {
			continue;
		}
		stats->n_evts += dev->m_bufinfo->n_evts;
		stats->n_drops_buffer += dev->m_bufinfo->n_drops_buffer;
		stats->n_drops_pf += dev->m_bufinfo->n_drops_pf;
		stats->n_drops += dev->m_bufinfo->n_drops_buffer + dev->m_bufinfo->n_drops_pf;
		stats->n_preemptions += dev->m_bufinfo->n_preemptions;
	}

	return SCAP_SUCCESS;
}

int32_t scap_udig_get_n_tracepoint_hit(struct scap_engine_handle engine, long *_ret) {
	return SCAP_SUCCESS;
}

uint32_t scap_udig_get_n_devs(struct scap_engine_handle engine) {
	struct scap_device_set *devset = &HANDLE(engine)->m_dev_set;
	uint64_t i;
	uint32_t num_devs = 0;

	for(i = 0; i < devset->m_ndevs; i++) {
		scap_device *dev = &devset->m_devs[i];
		if(dev->m_state != DEV_OPEN) {
			continue;
		}

		num_devs += 1;
	}

	return num_devs;
}

uint64_t scap_udig_get_max_buf_used(struct scap_engine_handle engine) {
	uint64_t i;
	uint64_t max = 0;
	struct scap_device_set *devset = &HANDLE(engine)->m_dev_set;

	for(i = 0; i < devset->m_ndevs; i++) {
		scap_device *dev = &devset->m_devs[i];
		if(dev->m_state != DEV_OPEN) {
			continue;
		}
		uint64_t size = buf_size_used(dev);
		max = size > max ? size : max;
	}

	return max;
}
