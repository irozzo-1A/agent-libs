#include <libscap/scap.h>
#include <libscap/scap_engines.h>
#include <libscap/scap_engine_util.h>
#include <benchmark/benchmark.h>
#include <unordered_set>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sysdig_bench_var.h>
#include <sys/wait.h>
#include <libscap/ringbuffer/sysdig/common/ringbuffer_mode.h>
#include <scap-int.h>

enum engine_type_t {
	EBPF = 0,
	KMOD,
	MODERN_EBPF,
};

enum buffer_size_t {
	MB_1 = 1024 * 1024,
	MB_8 = 8 * 1024 * 1024,
	MB_16 = 16 * 1024 * 1024,
	MB_32 = 32 * 1024 * 1024,
	MB_64 = 64 * 1024 * 1024,
};

static void null_log_fn(const char* component, const char* msg, falcosecurity_log_severity sev) {}

// At a certain point we need to move this to a common place
class ringbuffer_benchmarks : public ::benchmark::Fixture {
public:
	ringbuffer_benchmarks() {}

	void generate_syscalls(::benchmark::State& state, uint64_t buffer_dim) {
		ssize_t num_online_CPUs = sysconf(_SC_NPROCESSORS_ONLN);
		static const uint64_t open_by_handle_at_exit_size = 70;
		static const uint64_t open_by_handle_at_enter_size = 26;

		char buffer[50];
		char num_syscalls[50];
		// +100 is a safety margin
		snprintf(num_syscalls,
		         sizeof(num_syscalls),
		         "%lu",
		         (buffer_dim / (open_by_handle_at_enter_size + open_by_handle_at_exit_size)) + 100);

		while(true) {
			// For all the CPUs we generate a stressor
			for(int i = 0; i < num_online_CPUs; i++) {
				snprintf(buffer, sizeof(buffer), "%d-%d", i, i);

				int pid = fork();
				if(pid == 0) {
					const char* newargv[] =
					        {"stressor", "--cpu-list", buffer, STRESSOR_PATH, num_syscalls, NULL};
					syscall(__NR_execveat, AT_FDCWD, "/usr/bin/taskset", newargv, NULL, 0);
					// We ignore it, we will try at the next round.
					state.SkipWithMessage("cannot execve for the child");
					exit(0);
				}
				if(pid == -1) {
					state.SkipWithMessage("cannot create the child");
				}
			}

			// Wait for all the children
			int status = 0;
			while(wait(&status) > 0)
				;

			// Check the stats and restart!
			if(check_full_buffers(state)) {
				break;
			}
		}
	}

	void SetUp(::benchmark::State& state) override {
		engine_type_t engine = (engine_type_t)state.range(0);
		ringbuffer_mode_t mode = (ringbuffer_mode_t)state.range(1);
		uint64_t buffer_dim = state.range(2);
		char error_buffer[FILENAME_MAX] = {0};
		int32_t ret = 0;
		struct scap_open_args oargs = {};

		// We want to use all the syscalls to generate more entropy in the buffers
		// The bench should me more reliable.
		for(int i = 0; i < PPM_SC_MAX; i++) {
			oargs.ppm_sc_of_interest.ppm_sc[i] = 1;
		}
		oargs.ringbuffer_mode = mode;
		oargs.log_fn = null_log_fn;
		switch(engine) {
		case MODERN_EBPF: {
			struct scap_modern_bpf_engine_params modern_bpf_params = {
			        .cpus_for_each_buffer = 1,
			        .allocate_online_only = true,
			        .buffer_bytes_dim = buffer_dim,
			};
			oargs.engine_params = &modern_bpf_params;
			m_engine = scap_open(&oargs, &scap_modern_bpf_engine, error_buffer, &ret);
		} break;

		case EBPF: {
			struct scap_bpf_engine_params bpf_params = {
			        .buffer_bytes_dim = buffer_dim,
			        .bpf_probe = BPF_PROBE_PATH,
			};
			oargs.engine_params = &bpf_params;
			m_engine = scap_open(&oargs, &scap_bpf_engine, error_buffer, &ret);
		} break;

		case KMOD: {
			/* Remove previously inserted kernel module */
			RemoveKmod(state);

			/* Insert again the kernel module */
			InsertKmod(state);

			struct scap_kmod_engine_params kmod_params = {
			        .buffer_bytes_dim = buffer_dim,
			};
			oargs.engine_params = &kmod_params;
			m_engine = scap_open(&oargs, &scap_kmod_engine, error_buffer, &ret);
		}
		/* code */
		break;

		default:
			state.SkipWithError("unknown Engine! Skip iteration.");
			return;
		}

		if(ret != SCAP_SUCCESS) {
			state.SkipWithError("cannot open the engine! " + std::string(error_buffer));
			return;
		}

		/* Start the capture */
		if(scap_start_capture(m_engine) != SCAP_SUCCESS) {
			state.SkipWithError("cannot start the capture! " + std::string(m_engine->m_lasterr));
			return;
		}

		generate_syscalls(state, buffer_dim);

		scap_stop_capture(m_engine);

		// we perform a last call after the stop capture to check that we catch the right number of
		// total_events
		check_full_buffers(state);
	}

	void TearDown(::benchmark::State& state) { scap_close(m_engine); }

	void RemoveKmod(::benchmark::State& state) {
		std::string msg = "";
		if(syscall(__NR_delete_module, KERNEL_MODULE_NAME, O_NONBLOCK)) {
			switch(errno) {
			case ENOENT:
				return;

			// We try to remove the kernel module multiple times before giving up
			case EWOULDBLOCK:
				for(int i = 0; i < 4; i++) {
					int ret = syscall(__NR_delete_module, KERNEL_MODULE_NAME, O_NONBLOCK);
					if(ret == 0 || errno == ENOENT) {
						return;
					}
					sleep(1);
				}
				state.SkipWithError("cannot remove the kernel module! Skip iteration.");
				return;

			case EBUSY:
			case EFAULT:
			case EPERM:
				msg = "Unable to remove kernel module. Errno message: " +
				      std::string(strerror(errno)) + ", errno: " + std::to_string(errno) +
				      ". Skip iteration.";
				state.SkipWithError(msg);
				return;

			default:
				msg = "Unexpected error code. Errno message: " + std::string(strerror(errno)) +
				      ", errno: " + std::to_string(errno) + ". Skip iteration.";
				state.SkipWithError(msg);
				return;
			}
		}
	}

	void InsertKmod(::benchmark::State& state) {
		std::string msg = "";
		int fd = open(KERNEL_MODULE_PATH, O_RDONLY);
		if(fd < 0) {
			msg = "Unable to open the kmod file. Errno message: " + std::string(strerror(errno)) +
			      ", errno: " + std::to_string(errno) + ". Skip iteration.";
			state.SkipWithError(msg);
			return;
		}

		if(syscall(__NR_finit_module, fd, "", 0)) {
			// If the kernel module is already there, we assume it was just injected in a previous
			// iterarion
			if(errno != EEXIST && errno != EBUSY) {
				msg = "Unable to inject the kmod. Errno message: " + std::string(strerror(errno)) +
				      ", errno: " + std::to_string(errno) + ". Skip iteration.";
				state.SkipWithError(msg);
				return;
			}
		}
	}

	bool check_full_buffers(::benchmark::State& state) {
		uint32_t nstats;
		int32_t rc;

		const struct metrics_v2* metrics =
		        scap_get_stats_v2(m_engine, METRICS_V2_KERNEL_COUNTERS_PER_CPU, &nstats, &rc);

		if(rc != SCAP_SUCCESS) {
			state.SkipWithError("cannot obtain the metrics v2. Skip iteration.");
			return true;
		}
		m_total_events = 0;
		for(uint32_t i = 0; i < nstats; i++) {
			// we need to compare against the 2 prefixes one for the kmod and the other for ebpf
			// engines.
			if(strncmp(metrics[i].name,
			           N_EVENTS_PER_CPU_PREFIX,
			           sizeof(N_EVENTS_PER_CPU_PREFIX) - 1) == 0 ||
			   strncmp(metrics[i].name,
			           N_EVENTS_PER_DEVICE_PREFIX,
			           sizeof(N_EVENTS_PER_DEVICE_PREFIX) - 1) == 0) {
				// If we don't have drops and the CPU received at least one event we return failure
				// because the buffer associated with this CPU is not full. We check for at least
				// one event produced on that CPU because we want to exclude the CPUs that are not
				// online.
				if(metrics[i].value.u64 > 0 && metrics[i + 1].value.u64 == 0) {
					return false;
				}
				// to obtain the number of events in the buffers we should remove the number of
				// drops from the event seen at the end of the capture
				m_total_events += (metrics[i].value.u64 - metrics[i + 1].value.u64);
			}
		}
		return true;
	}

	scap_t* m_engine = NULL;
	uint64_t m_total_events = 0;
};

static void CustomArguments(benchmark::internal::Benchmark* b) {
	static std::unordered_set<int64_t> buffer_sizes = {MB_8};
	static std::unordered_set<int64_t> ring_modes = {DEFAULT_RINGBUF_MODE,
	                                                 SORTED_LINKED_LIST_RINGBUF_MODE};
	static std::unordered_set<int64_t> engines = {KMOD, EBPF, MODERN_EBPF};

	for(auto engine : engines) {
		for(auto ring_mode : ring_modes) {
			for(auto buffer_size : buffer_sizes) {
				b->Args({engine, ring_mode, buffer_size})->ArgNames({"engine", "mode", "size"});
			}
		}
	}
}

BENCHMARK_DEFINE_F(ringbuffer_benchmarks, RingBufferPerf)(benchmark::State& st) {
	uint16_t buffer_id = 0;
	uint32_t flags = 0;
	scap_evt* evt = NULL;
	// We perform a first call to move the producers and fill all the buffers with the refill logic.
	// The modern probe doesn't have the refill logic, we do this for the other drivers.
	// The kernel module and the legacy ebpf load the entire available buffers during the refill so
	// in the next `while` loop we should consume all our buffers.
	scap_next(m_engine, &evt, &buffer_id, &flags);
	uint64_t total_events = 0;

	for(auto _ : st) {
		while(true) {
			// we shouldn't face other timeouts until all the buffers are empty.
			if(scap_next(m_engine, &evt, &buffer_id, &flags) != SCAP_SUCCESS) {
				break;
			}
			total_events++;
		}
	}

	// the modern ebpf process some events during the calibration phase so we keep a margin of ~20
	// events. They should be enough.
	if(total_events < (m_total_events - 20)) {
		std::string msg = "Early timeout! expected " + std::to_string((m_total_events - 20)) +
		                  " found " + std::to_string(total_events);
		st.SkipWithError(msg);
	}
}
BENCHMARK_REGISTER_F(ringbuffer_benchmarks, RingBufferPerf)
        ->Iterations(1)
        ->Repetitions(1)
        ->ReportAggregatesOnly(true)
        ->Name("RingBufferPerf")
        ->Unit(benchmark::kMicrosecond)
        ->Apply(CustomArguments);
