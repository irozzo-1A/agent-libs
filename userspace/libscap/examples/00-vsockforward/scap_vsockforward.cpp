#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <errno.h>
#include <stdint.h>

#define VSOCK_HOST_CID 2  // Host CID is always 2 in Kata containers
#define VSOCK_PORT 5000   // Make sure this matches the listening server on the host
#define BUFFER_SIZE 1024 * 1024

int main() {
	int sock;
	struct sockaddr_vm sa;

	// Create a vsock socket
	sock = socket(AF_VSOCK, SOCK_STREAM, 0);
	if(sock < 0) {
		perror("socket");
		return EXIT_FAILURE;
	}

	// Initialize vsock address structure
	memset(&sa, 0, sizeof(sa));
	sa.svm_family = AF_VSOCK;
	sa.svm_port = VSOCK_PORT;     // Same as the listening server
	sa.svm_cid = VSOCK_HOST_CID;  // Host CID

	// Connect to the vsock server on the host
	if(connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("connect");
		close(sock);
		return EXIT_FAILURE;
	}

	uint8_t buffer[BUFFER_SIZE];
	while(true) {
		if(send(sock, buffer, BUFFER_SIZE, 0) < 0) {
			perror("send");
			close(sock);
			return EXIT_FAILURE;
		}
	}

	// Close the socket
	close(sock);
	return EXIT_SUCCESS;
}
