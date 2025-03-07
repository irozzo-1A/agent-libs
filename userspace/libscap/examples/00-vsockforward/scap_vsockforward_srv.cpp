#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <errno.h>

#include <iostream>
#include <thread>
#include <atomic>
#include <list>
#include <chrono>

#define VSOCK_PORT 5000
#define BUFFER_SIZE 1024 * 1024

void exit_on_err(int code) {
	if(code != 0) {
		std::cerr << "FATAL: " << strerror(code) << std::endl;
		exit(code);
	}
}

void handle_connection(std::atomic<bool>* exit, int sock, int cid) {
	std::cerr << "client connected from CID " << cid << std::endl;

	uint8_t buffer[BUFFER_SIZE];
	int64_t sample_bytes = 0;
	auto last_sample_time = std::chrono::system_clock::now();
	while(true) {
		if(exit->load()) {
			break;
		}

		int bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
		if(bytes_received < 0) {
			std::cerr << "closing client connection for CID " << cid << std::endl;
			break;
		}
		if(bytes_received == 0) {
			continue;
		}

		// todo: do something with the data
		sample_bytes += (int64_t)bytes_received;

		auto now = std::chrono::system_clock::now();
		auto elapsed_sec = std::chrono::duration_cast<std::chrono::seconds>(now - last_sample_time);
		if(elapsed_sec.count() < 1) {
			continue;
		}

		auto elapsed_ms = (int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
		                          now - last_sample_time)
		                          .count();
		auto bytes_per_ms = sample_bytes / elapsed_ms;
		std::cerr << "client consuming " << bytes_per_ms * 1000 << " bytes/s" << std::endl;

		last_sample_time = now;
		sample_bytes = 0;
	}

	close(sock);
}

int listen_for_connections(int port) {
	int server_sock = socket(AF_VSOCK, SOCK_STREAM, 0);
	if(server_sock < 0) {
		return errno;
	}

	struct sockaddr_vm sa;
	memset(&sa, 0, sizeof(sa));
	sa.svm_family = AF_VSOCK;
	sa.svm_port = port;
	sa.svm_cid = VMADDR_CID_ANY;  // Listen for any CID

	if(bind(server_sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
		close(server_sock);
		return errno;
	}

	if(listen(server_sock, 1) < 0) {
		close(server_sock);
		return errno;
	}

	std::cerr << "waiting vsock for connection on port " << port << std::endl;

	int res = 0;
	std::atomic<bool> exit{false};
	std::list<std::thread> threads;
	while(!exit.load()) {
		struct sockaddr_vm client_sa;
		socklen_t client_sa_len = sizeof(client_sa);

		int client_sock = accept(server_sock, (struct sockaddr*)&client_sa, &client_sa_len);
		if(client_sock < 0) {
			res = errno;
			exit.store(true);
			continue;
		}

		threads.emplace_back(std::thread(handle_connection, &exit, client_sock, client_sa.svm_cid));
	}

	for(auto& t : threads) {
		if(t.joinable()) {
			t.join();
		}
	}

	close(server_sock);
	return res;
}

int main() {
	int res = listen_for_connections(VSOCK_PORT);
	exit_on_err(res);
	return EXIT_SUCCESS;
}
