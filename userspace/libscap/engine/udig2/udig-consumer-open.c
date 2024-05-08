#include <libscap/engine/udig2/udig-int.h>
#include <libscap/ringbuffer/ringbuffer.h>
#include <libscap/scap-int.h>
#include <libscap/strerror.h>

#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef __NR_memfd_create
#define __NR_memfd_create 319
#endif

static int32_t scap_udig_open_dev(struct scap_udig *handle, struct scap_device *dev) {
	uint32_t buffer_size = UDIG_RING_SIZE;
	int res;
	int mem_size = sizeof(struct scap_ringbuffer_info);

	dev->m_state = DEV_OPENING;
	__sync_synchronize();

	// TODO fcntl grow/shrink seals
	dev->m_fd = syscall(__NR_memfd_create, "udig_ringbuf", PPM_MFD_CLOEXEC);
	if(dev->m_fd < 0) {
		dev->m_state = DEV_CLOSED;
		return scap_errprintf(handle->m_lasterr, -dev->m_fd, "Failed to create memfd");
	}

	res = ftruncate(dev->m_fd, buffer_size + mem_size);
	if(res < 0) {
		close(dev->m_fd);
		dev->m_state = DEV_CLOSED;
		return scap_errprintf(handle->m_lasterr, errno, "Failed to resize ring buffer");
	}

	if(udig_map_ring(dev, buffer_size, handle->m_lasterr, PROT_READ) != SCAP_SUCCESS) {
		// udig_map_ring closes the ring_fd on error
		dev->m_state = DEV_CLOSED;
		return SCAP_FAILURE;
	}
	dev->m_bufinfo->head = 0;
	dev->m_bufinfo->tail = 0;
	dev->m_bufstatus->m_state = RING_STOPPED;

	//
	// Additional initializations
	//
	dev->m_lastreadsize = 0;
	dev->m_sn_len = 0;
	dev->m_sn_next_event = dev->m_buffer;

	dev->m_bufstatus->m_syscall_bitmap.m_size = handle->m_bitmap_size;
	memcpy((char *)dev->m_bufstatus->m_syscall_bitmap.m_bitmap,
	       handle->m_bitmap,
	       handle->m_bitmap_size);

	dev->m_state = DEV_OPEN;
	__sync_synchronize();
	if(handle->m_udig_capturing) {
		udig_begin_capture_dev(dev, &handle->settings, handle->m_lasterr);
	}

	return SCAP_SUCCESS;
}

static struct scap_device *scap_udig_find_free_dev(struct scap_udig *handle) {
	struct scap_device_set *devset = &handle->m_dev_set;
	for(int i = 0; i < devset->m_alloc_devs; ++i) {
		if(!devset->m_devs) {
			// scap_udig_next is reallocating, let it finish
			return NULL;
		}

		struct scap_device *dev = &devset->m_devs[i];
		if(dev->m_state != DEV_CLOSED) {
			// buffer already used
			continue;
		}

		int res = scap_udig_open_dev(handle, dev);
		if(res != SCAP_SUCCESS) {
			// TODO cleanup
			scap_udig_close_dev(dev, NULL);
			return NULL;
		}

		devset->m_used_devs++;
		if(i >= devset->m_ndevs) {
			devset->m_ndevs = i + 1;
		}
		return dev;
	}

	// no free buffers
	return NULL;
}

static void scap_udig_send_fd(int conn_fd, int sent_fd) {
	struct msghdr msg = {0};
	char buf[CMSG_SPACE(sizeof(sent_fd))] = {0};
	struct iovec io = {.iov_base = "ABC", .iov_len = 3};

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;

	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(sent_fd));
	msg.msg_controllen = CMSG_SPACE(sizeof(sent_fd));

	*((int *)CMSG_DATA(cmsg)) = sent_fd;
	sendmsg(conn_fd, &msg, 0);
}

void *accept_thread(void *arg) {
	struct scap_udig *handle = (struct scap_udig *)arg;
	struct scap_device *dev = NULL;

	// pdig can exit at any time, leading to sigpipe. therefore we need to ignore it
	// in the accept_thread thread where we attempt to write to the pipe
	sigset_t sigs;
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &sigs, NULL);

	while(1) {
		int fd = accept(handle->m_listen_fd, NULL, NULL);
		if(fd < 0) {
			// ...?
			continue;
		}

		while(1) {
			dev = scap_udig_find_free_dev(handle);
			if(dev != NULL) {
				break;
			}
			usleep(1000);
		}

		scap_udig_send_fd(fd, dev->m_fd);
		close(fd);
	}
}

static int32_t scap_udig_listen(struct scap_udig *handle, const char *socket_path) {
	int sock, ret;
	struct sockaddr_un address;
	unsigned long old_umask;

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if(sock == -1) {
		scap_errprintf(handle->m_lasterr, errno, "udig_fd_server: error registering unix socket");
		return -1;
	}

	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, PPM_UNIX_PATH_MAX, "%s", socket_path);

	ret = unlink(socket_path);
	if(ret != 0 && ret != -ENOENT && ret != -EPERM) {
		scap_errprintf(handle->m_lasterr, errno, "udig_fd_server: error unlinking unix socket");
		return -1;
	}

	old_umask = umask(0);
	ret = bind(sock, (struct sockaddr *)&address, sizeof(address));
	if(ret != 0) {
		scap_errprintf(handle->m_lasterr, errno, "udig_fd_server: error binding unix socket");
		umask(old_umask);
		return -1;
	}
	umask(old_umask);

	ret = listen(sock, 128);
	if(ret != 0) {
		scap_errprintf(handle->m_lasterr, errno, "udig_fd_server: error on listen");
		return -1;
	}

	return sock;
}

static inline void set_syscall_bitmap_entry(struct scap_udig *handle, int sc_code) {
	int sc = scap_ppm_sc_to_native_id(sc_code);

	if(sc == -1) {
		return;
	}

	size_t byte = sc / 8;
	size_t bit = sc % 8;

	handle->m_bitmap[byte] |= (1 << bit);
	if(handle->m_bitmap_size < byte) {
		handle->m_bitmap_size = byte;
	}
}

int32_t scap_udig_open(scap_t *main_handle, struct scap_open_args *oargs) {
	struct scap_udig2_engine_params *params = oargs->engine_params;
	struct scap_udig *handle = main_handle->m_engine.m_handle;
	pthread_attr_t attr;

	handle->m_listen_fd = scap_udig_listen(handle, params->udig_socket_path);
	if(handle->m_listen_fd < 0) {
		return SCAP_FAILURE;
	}

	if(devset_init(&handle->m_dev_set, 16, handle->m_lasterr) != SCAP_SUCCESS) {
		close(handle->m_listen_fd);
		return SCAP_FAILURE;
	}
	handle->m_dev_set.m_ndevs = 0;

	for(int i = 0; i < sizeof(oargs->ppm_sc_of_interest.ppm_sc); i++) {
		if(oargs->ppm_sc_of_interest.ppm_sc[i]) {
			set_syscall_bitmap_entry(handle, i);
		}
	}

	// TODO handle errors here
	pthread_attr_init(&attr);
	pthread_create(&handle->m_thread, &attr, accept_thread, (void *)handle);
	pthread_attr_destroy(&attr);

	return SCAP_SUCCESS;
}

int32_t scap_udig_close(struct scap_engine_handle engine) {
	struct scap_udig *handle = engine.m_handle;

	for(int i = 0; i < handle->m_dev_set.m_ndevs; ++i) {
		scap_udig_close_dev(&handle->m_dev_set.m_devs[i], &handle->m_dev_set.old_stats);
	}
	handle->m_dev_set.m_used_devs = 0;
	return SCAP_SUCCESS;
}
