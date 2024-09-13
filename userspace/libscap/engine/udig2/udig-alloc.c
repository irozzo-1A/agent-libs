#include <memory.h>
#include <stdlib.h>
#include <libscap/engine/udig2/udig-int.h>

void *scap_udig_alloc(scap_t *main_handle, char *lasterr_ptr) {
	struct scap_udig *handle = calloc(1, sizeof(*handle));
	if(handle) {
		handle->m_lasterr = lasterr_ptr;
		scap_udig_init(handle);
	}
	return handle;
}

void scap_udig_free(struct scap_engine_handle engine) {
	free(engine.m_handle);
}
