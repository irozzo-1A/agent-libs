#include <gtest/gtest.h>
#include <syscall.h>
#include <libscap/scap.h>
#include <errno.h>

#if defined(__NR_open_by_handle_at) && defined(__NR_wait4)

#define MOCK_MOUNT_FD 10000000
#define GENERATOR_ITERATIONS 10000000
#define DROP_THRESHOLD            \
	(GENERATOR_ITERATIONS / 10) * \
	        9  // Some events could be drop but we want to see at least 90% of them
// if we hit 100 consecutive timeouts it means that all buffers are empty (approximation)
#define CONSECUTIVE_TIMEOUTS 100
#define OPEN_BY_HANDLE_AT_PARAMS 6

static int spawn_generator() {
	int pid = fork();
	if(pid == 0) {
		// we would like to wait the capture to be started
		sleep(1);
		// the mountfd is on 32 bit so the max here is (2^32)-1
		for(int i = 0; i <= GENERATOR_ITERATIONS; i++) {
			syscall(__NR_open_by_handle_at, i, NULL, 0);
			// we try to force a switch to change the CPU
			if(i % 1000 == 0) {
				usleep(1);
			}
		}
		printf("STOP producing\n");
		exit(0);
	}
	return pid;
}

static int64_t get_mount_fd(scap_evt* evt) {
	int64_t mount_fd = 0;
	// we want to reach the mount_fd parameter
	memcpy(&mount_fd,
	       ((char*)evt + sizeof(struct ppm_evt_hdr) + 6 * sizeof(uint16_t) + sizeof(int64_t)),
	       sizeof(int64_t));
	return mount_fd;
}

#define STOP_CAPTURE_AND_COLLECT_STATS                                              \
	ASSERT_EQ(scap_stop_capture(h), SCAP_SUCCESS)                                   \
	        << "unable to stop the capture: " << scap_getlasterr(h) << std::endl;   \
                                                                                    \
	int status = 0;                                                                 \
	int options = 0;                                                                \
	if(syscall(__NR_wait4, pid, &status, options, NULL) == -1) {                    \
		FAIL() << "unable to wait the generator: " << strerror(errno) << std::endl; \
	}                                                                               \
                                                                                    \
	scap_stats stats;                                                               \
	scap_get_stats(h, &stats);                                                      \
	std::cout << "n_evts: " << stats.n_evts << std::endl;                           \
	std::cout << "n_drops: " << stats.n_drops << std::endl;                         \
	std::cout << "n_open_calls: " << open_by_handle_at_calls << std::endl;

void check_live_same_thread_event_order(scap_t* h) {
	ASSERT_EQ(scap_get_event_info_table()[PPME_SYSCALL_OPEN_BY_HANDLE_AT_X].params[1].type, PT_FD)
	        << "unexpected type for the mount_fd parameter in open_by_handle_at";

	// detach a thread that throws open_by_handle_at with increasing fd
	int pid = spawn_generator();
	if(pid == -1) {
		FAIL() << "unable to fork the generator";
	}

	ASSERT_EQ(scap_start_capture(h), SCAP_SUCCESS)
	        << "unable to start the capture: " << scap_getlasterr(h) << std::endl;

	scap_evt* evt = NULL;
	uint16_t buffer_id = 0;
	uint32_t flags = 0;
	int64_t order = 0;
	int ret = 0;
	uint64_t open_by_handle_at_calls = 0;
	uint16_t timeouts = 0;
	bool failure = false;
	uint16_t last_buffer = 0;
	uint64_t last_timestamp = 0;
	while(true) {
		ret = scap_next(h, &evt, &buffer_id, &flags);
		if(ret == SCAP_SUCCESS) {
			timeouts = 0;
			if(evt->tid == (uint64_t)pid && evt->type == PPME_SYSCALL_OPEN_BY_HANDLE_AT_X) {
				open_by_handle_at_calls++;
				int64_t mount_fd = get_mount_fd(evt);

				// we don't know what will be the first fd that we catch, so the first time we
				// accept everything
				if(order == 0) {
					order = mount_fd;
				} else {
					if(order + 1 != mount_fd) {
						failure = true;
						// This should never happen that's why we print the log.
						printf("[NOT RESPECTED] order+1: %ld + 1 != mount_fd: %ld. Last "
						       "ordered event BUFID(%d), ts(%lu). New event BUFID(%d), "
						       "ts(%lu)\n",
						       order,
						       mount_fd,
						       last_buffer,
						       last_timestamp,
						       buffer_id,
						       evt->ts);
						break;
					}

					order = mount_fd;
				}
				if(order >= DROP_THRESHOLD) {
					break;
				}
				last_timestamp = evt->ts;
				last_buffer = buffer_id;
			}
		} else if(ret == SCAP_TIMEOUT) {
			timeouts++;
			if(timeouts == CONSECUTIVE_TIMEOUTS) {
				failure = true;
				printf("[TIMEOUT]\n");
				break;
			}
		}
	}

	STOP_CAPTURE_AND_COLLECT_STATS

	if(failure) {
		// We skip it because this test could also fail because some event could come out-of-order
		GTEST_SKIP();
	}
}

// We want to check that our algorithms work well even when the buffers are almost empty
void check_refill(scap_t* h) {
	int pid = fork();
	if(pid == 0) {
		// we would like to wait the capture to be started
		sleep(1);

		for(int i = 0; i <= 5; i++) {
			for(int j = 0; j <= 10; j++) {
				syscall(__NR_open_by_handle_at, j, NULL, 0, 0);
			}
			sleep(1);
		}
		printf("STOP producing\n");
		exit(0);
	}

	if(pid == -1) {
		FAIL() << "unable to fork the generator";
	}

	ASSERT_EQ(scap_start_capture(h), SCAP_SUCCESS)
	        << "unable to start the capture: " << scap_getlasterr(h) << std::endl;

	scap_evt* evt = NULL;
	uint16_t buffer_id = 0;
	uint32_t flags = 0;
	int ret = 0;
	uint64_t open_by_handle_at_calls = 0;

	while(true) {
		ret = scap_next(h, &evt, &buffer_id, &flags);
		if(ret == SCAP_SUCCESS) {
			if(evt->tid == (uint64_t)pid && evt->type == PPME_SYSCALL_OPEN_BY_HANDLE_AT_X) {
				open_by_handle_at_calls++;

				// We stop when we reach the last fd generated by the child
				if(open_by_handle_at_calls >= 50) {
					break;
				}
			}
		} else if(ret == SCAP_TIMEOUT) {
			sleep(1);
			continue;
		}
	}

	STOP_CAPTURE_AND_COLLECT_STATS
}
#else
void check_live_same_thread_event_order(scap_t* h) {
	GTEST_SKIP() << "Some syscalls required by the test are not defined" << std::endl;
}

void check_refill(scap_t* h) {
	GTEST_SKIP() << "Some syscalls required by the test are not defined" << std::endl;
}
#endif

#if defined(__NR_close) && defined(__NR_openat) && defined(__NR_listen) &&           \
        defined(__NR_accept4) && defined(__NR_getegid) && defined(__NR_getgid) &&    \
        defined(__NR_geteuid) && defined(__NR_getuid) && defined(__NR_bind) &&       \
        defined(__NR_connect) && defined(__NR_sendto) && defined(__NR_getsockopt) && \
        defined(__NR_recvmsg) && defined(__NR_recvfrom) && defined(__NR_socket) &&   \
        defined(__NR_socketpair)

/* We are supposing that if we overcome this threshold, all buffers are full.
 * Probably this threshold is too low, but it depends on the machine's workload.
 * We are running in CI so it is better to be conservative even if tests becomes
 * not so reliable...
 */
#define PRE_FETCHED_MAX_ITERATIONS 300

/* Number of events we want to assert */
#define PRE_FETCHED_EVENTS_TO_ASSERT 32

void check_pre_fetched_event_order(scap_t* h) {
	uint32_t events_to_assert[PRE_FETCHED_EVENTS_TO_ASSERT] = {
	        PPME_SYSCALL_CLOSE_E,     PPME_SYSCALL_CLOSE_X,     PPME_SYSCALL_OPENAT_2_E,
	        PPME_SYSCALL_OPENAT_2_X,  PPME_SOCKET_LISTEN_E,     PPME_SOCKET_LISTEN_X,
	        PPME_SOCKET_ACCEPT4_6_E,  PPME_SOCKET_ACCEPT4_6_X,  PPME_SYSCALL_GETEGID_E,
	        PPME_SYSCALL_GETEGID_X,   PPME_SYSCALL_GETGID_E,    PPME_SYSCALL_GETGID_X,
	        PPME_SYSCALL_GETEUID_E,   PPME_SYSCALL_GETEUID_X,   PPME_SYSCALL_GETUID_E,
	        PPME_SYSCALL_GETUID_X,    PPME_SOCKET_BIND_E,       PPME_SOCKET_BIND_X,
	        PPME_SOCKET_CONNECT_E,    PPME_SOCKET_CONNECT_X,    PPME_SOCKET_SENDTO_E,
	        PPME_SOCKET_SENDTO_X,     PPME_SOCKET_GETSOCKOPT_E, PPME_SOCKET_GETSOCKOPT_X,
	        PPME_SOCKET_RECVMSG_E,    PPME_SOCKET_RECVMSG_X,    PPME_SOCKET_RECVFROM_E,
	        PPME_SOCKET_RECVFROM_X,   PPME_SOCKET_SOCKET_E,     PPME_SOCKET_SOCKET_X,
	        PPME_SOCKET_SOCKETPAIR_E, PPME_SOCKET_SOCKETPAIR_X};

	/* Start the capture */
	ASSERT_EQ(scap_start_capture(h), SCAP_SUCCESS)
	        << "unable to start the capture: " << scap_getlasterr(h) << std::endl;

	/* 1. Generate a `close` event pair */
	syscall(__NR_close, -1);

	/* 2. Generate an `openat` event pair */
	syscall(__NR_openat, 0, "/**mock_path**/", 0, 0);

	/* 3. Generate a `listen` event pair */
	syscall(__NR_listen, -1, -1);

	/* 4. Generate an `accept4` event pair */
	syscall(__NR_accept4, -1, NULL, NULL, 0);

	/* 5. Generate a `getegid` event pair */
	syscall(__NR_getegid);

	/* 6. Generate a `getgid` event pair */
	syscall(__NR_getgid);

	/* 7. Generate a `geteuid` event pair */
	syscall(__NR_geteuid);

	/* 8. Generate a `getuid` event pair */
	syscall(__NR_getuid);

	/* 9. Generate a `bind` event pair */
	syscall(__NR_bind, -1, NULL, 0);

	/* 10. Generate a `connect` event pair */
	syscall(__NR_connect, -1, NULL, 0);

	/* 11. Generate a `sendto` event pair */
	syscall(__NR_sendto, -1, NULL, 0, 0, NULL, 0);

	/* 12. Generate a `getsockopt` event pair */
	syscall(__NR_getsockopt, -1, 0, 0, NULL, NULL);

	/* 13. Generate a `recvmsg` event pair */
	syscall(__NR_recvmsg, -1, NULL, 0);

	/* 14. Generate a `recvmsg` event pair */
	syscall(__NR_recvfrom, -1, NULL, 0, 0, NULL, 0);

	/* 15. Generate a `socket` event pair */
	syscall(__NR_socket, 0, 0, 0);

	/* 16. Generate a `socketpair` event pair */
	syscall(__NR_socketpair, 0, 0, 0, 0);

	/* Stop the capture */
	ASSERT_EQ(scap_stop_capture(h), SCAP_SUCCESS)
	        << "unable to stop the capture: " << scap_getlasterr(h) << std::endl;

	scap_stats stats;
	scap_get_stats(h, &stats);
	std::cout << "n_evts: " << stats.n_evts << std::endl;
	std::cout << "n_drops: " << stats.n_drops << std::endl;

	scap_evt* evt = NULL;
	uint16_t buffer_id = 0;
	uint32_t flags = 0;
	int ret = 0;
	uint64_t actual_pid = getpid();
	/* if we hit 5 consecutive timeouts it means that all buffers are empty (approximation) */
	uint16_t timeouts = 0;

	// Used for debug
	// for(int i = 0; i < PRE_FETCHED_EVENTS_TO_ASSERT; i++)
	// {
	// 	printf("%d) Event %d: (%s)\n", i, events_to_assert[i],
	// 	       scap_get_event_info_table()[events_to_assert[i]].name);
	// }
	// printf("\n\n");

	for(int i = 0; i < PRE_FETCHED_EVENTS_TO_ASSERT; i++) {
		// printf("%d) Searching for event %d: (%s)\n", i, events_to_assert[i],
		//        scap_get_event_info_table()[events_to_assert[i]].name);
		while(true) {
			ret = scap_next(h, &evt, &buffer_id, &flags);
			if(ret == SCAP_SUCCESS) {
				timeouts = 0;
				if(evt->tid == actual_pid && evt->type == events_to_assert[i]) {
					/* We found our event */
					// printf("Found Event %d: (%s)\n", evt->type,
					//        scap_get_event_info_table()[evt->type].name);

					break;
				} else if(evt->tid == actual_pid) {
					// printf("Other Event %d: (%s)\n", evt->type,
					//        scap_get_event_info_table()[evt->type].name);
				}
			} else if(ret == SCAP_TIMEOUT) {
				timeouts++;
				if(timeouts == 5) {
					FAIL() << "we didn't find event '" << events_to_assert[i] << "' at position '"
					       << i << "'" << std::endl;
				}
			}
		}
	}
}

#else

void check_pre_fetched_event_order(scap_t* h) {
	GTEST_SKIP() << "Some syscalls required by the test are not defined" << std::endl;
}
#endif
