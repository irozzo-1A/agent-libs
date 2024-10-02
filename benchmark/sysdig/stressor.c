#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* to get O_PATH, AT_EMPTY_PATH */
#endif
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/time.h>

static void signal_callback(int signal) {
	printf("\nStop\n");
	exit(EXIT_SUCCESS);
}

int main(int argc, char** argv) {
	if(signal(SIGINT, signal_callback) == SIG_ERR) {
		fprintf(stderr, "An error occurred while setting SIGINT signal handler.\n");
		return EXIT_FAILURE;
	}

	if(argc != 2) {
		fprintf(stderr, "Wrong number of params. The stressor takes exactly 1 param\n");
		return EXIT_FAILURE;
	}

	uint64_t num_syscalls = strtoul(argv[1], NULL, 10);

	for(size_t i = 0; i < num_syscalls; i++) {
		syscall(__NR_open_by_handle_at, -1, NULL, 0);
	}

	return EXIT_SUCCESS;
}
