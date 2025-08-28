// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

////////////////////////////////////////////////////////////////////////////
// Public definitions for the scap library
////////////////////////////////////////////////////////////////////////////
#pragma once
#include <libsinsp/fdinfo.h>
#include <libsinsp/sinsp_fdinfo_factory.h>
#include <libsinsp/sinsp_threadinfo_factory.h>
#include <libsinsp/plugin.h>
#include <libsinsp/sinsp_mode.h>
#include <libsinsp/user.h>
#include <libsinsp/threadinfo.h>
#include <libsinsp/sinsp_parser_verdict.h>
#include <memory>

class sinsp_plugin_manager;

/*!
  \brief Container holding parameters to be provided to sinsp_parser constructor.
  An instance of this struct is meant to be shared among all sinsp_parser instances.
*/
struct sinsp_parser_shared_params {
	// The following fields are externally provided and access to them is expected to be
	// read-only.
	const sinsp_mode& m_sinsp_mode;
	const scap_machine_info* const& m_machine_info;
	const std::vector<std::string>& m_event_sources;
	const size_t m_syscall_event_source_idx;
	const sinsp_network_interfaces& m_network_interfaces;
	const bool& m_hostname_and_port_resolution_enabled;
	const sinsp_threadinfo_factory m_threadinfo_factory;
	const sinsp_fdinfo_factory m_fdinfo_factory;
	const std::shared_ptr<const sinsp_plugin>& m_input_plugin;
	const bool& m_large_envs_enabled;

	// The following fields are externally provided and expected to be populated/updated by the
	// parser.
	std::shared_ptr<sinsp_plugin_manager> m_plugin_manager;
	std::shared_ptr<sinsp_thread_manager> m_thread_manager;
	std::shared_ptr<sinsp_usergroup_manager> m_usergroup_manager;
	std::shared_ptr<sinsp_stats_v2> m_sinsp_stats_v2;
	sinsp_observer* const& m_observer;
	scap_platform* const& m_scap_platform;
};

class sinsp_parser {
public:
	sinsp_parser(const std::shared_ptr<sinsp_parser_shared_params>& shared_params,
	             sinsp_evt& tmp_evt_storage);
	~sinsp_parser();

	//
	// Processing entry point
	//
	void process_event(sinsp_evt& evt, sinsp_parser_verdict& verdict);
	void event_cleanup(sinsp_evt& evt);

	bool reset(sinsp_evt& evt, sinsp_parser_verdict& verdict) const;

	//
	// Get the enter event matching the last received event
	//
	bool retrieve_enter_event(sinsp_evt& enter_evt, sinsp_evt& exit_evt) const;

	//
	// Thread event data management (moved from threadinfo)
	//
	uint8_t* get_thread_event_data(int64_t tid) const;
	void set_thread_event_data(int64_t tid, const uint8_t* data, size_t size);
	void free_thread_event_data(int64_t tid);
	void clear_thread_event_data();

	//
	// Combine the openat arguments into a full file name
	//
	static std::string parse_dirfd(sinsp_evt& evt, std::string_view name, int64_t dirfd);

	void set_track_connection_status(bool enabled);
	bool get_track_connection_status() const { return m_track_connection_status; }

private:
	//
	// Helpers
	//
	inline void store_event(sinsp_evt& evt);

	// Multi-event processing state management methods
	int64_t get_thread_lastevent_fd(int64_t tid) const;
	void set_thread_lastevent_fd(int64_t tid, int64_t fd) const;
	uint64_t get_thread_lastevent_ts(int64_t tid) const;
	void set_thread_lastevent_ts(int64_t tid, uint64_t ts) const;
	uint64_t get_thread_prevevent_ts(int64_t tid) const;
	void set_thread_prevevent_ts(int64_t tid, uint64_t ts) const;
	uint64_t get_thread_lastaccess_ts(int64_t tid) const;
	void set_thread_lastaccess_ts(int64_t tid, uint64_t ts) const;
	uint64_t get_thread_clone_ts(int64_t tid) const;
	void set_thread_clone_ts(int64_t tid, uint64_t ts) const;
	uint64_t get_thread_lastexec_ts(int64_t tid) const;
	void set_thread_lastexec_ts(int64_t tid, uint64_t ts) const;
	void clear_thread_state(int64_t tid) const;
	void clear_all_thread_state() const;

	// File descriptor table management methods
	sinsp_fdtable* get_thread_fdtable(int64_t tid) const;
	void set_thread_fdtable(int64_t tid, std::unique_ptr<sinsp_fdtable> fdtable) const;
	void clear_thread_fdtable(int64_t tid) const;

	//
	// Parsers
	//
	void parse_clone_exit_child(sinsp_evt& evt, sinsp_parser_verdict& verdict) const;
	void parse_clone_exit_caller(sinsp_evt& evt,
	                             sinsp_parser_verdict& verdict,
	                             int64_t child_tid) const;
	void parse_clone_exit(sinsp_evt& evt, sinsp_parser_verdict& verdict) const;
	void parse_execve_exit(sinsp_evt& evt, sinsp_parser_verdict& verdict) const;
	void parse_open_openat_creat_exit(sinsp_evt& evt) const;
	static void parse_fchmod_fchown_exit(sinsp_evt& evt);
	void parse_pipe_exit(sinsp_evt& evt) const;
	void parse_socketpair_exit(sinsp_evt& evt) const;
	void parse_socket_exit(sinsp_evt& evt) const;
	void parse_connect_enter(sinsp_evt& evt) const;
	void parse_connect_exit(sinsp_evt& evt, sinsp_parser_verdict& verdict) const;
	void parse_accept_exit(sinsp_evt& evt, sinsp_parser_verdict& verdict) const;
	void parse_close_exit(sinsp_evt& evt, sinsp_parser_verdict& verdict) const;
	static void parse_thread_exit(sinsp_evt& evt, sinsp_parser_verdict& verdict);
	void parse_memfd_create_exit(sinsp_evt& evt, scap_fd_type type) const;
	void parse_pidfd_open_exit(sinsp_evt& evt) const;
	void parse_pidfd_getfd_exit(sinsp_evt& evt) const;
	void parse_fspath_related_exit(sinsp_evt& evt) const;
	inline void parse_rw_exit(sinsp_evt& evt, sinsp_parser_verdict& verdict) const;
	void parse_sendfile_exit(sinsp_evt& evt, sinsp_parser_verdict& verdict) const;
	void parse_eventfd_eventfd2_exit(sinsp_evt& evt) const;
	void parse_bind_exit(sinsp_evt& evt, sinsp_parser_verdict& verdict) const;
	static void parse_chdir_exit(sinsp_evt& evt);
	static void parse_fchdir_exit(sinsp_evt& evt);
	static void parse_getcwd_exit(sinsp_evt& evt);
	void parse_shutdown_exit(sinsp_evt& evt, sinsp_parser_verdict& verdict) const;
	void parse_dup_exit(sinsp_evt& evt, sinsp_parser_verdict& verdict) const;
	void parse_single_param_fd_exit(sinsp_evt& evt, scap_fd_type type) const;
	void parse_getrlimit_setrlimit_exit(sinsp_evt& evt) const;
	void parse_prlimit_exit(sinsp_evt& evt) const;
	void parse_fcntl_exit(sinsp_evt& evt) const;
	static void parse_prctl_exit_event(sinsp_evt& evt);
	void parse_context_switch(sinsp_evt& evt);
	static void parse_brk_mmap_mmap2_munmap__exit(sinsp_evt& evt);
	void parse_setresuid_exit(sinsp_evt& evt) const;
	void parse_setreuid_exit(sinsp_evt& evt) const;
	void parse_setresgid_exit(sinsp_evt& evt) const;
	void parse_setregid_exit(sinsp_evt& evt) const;
	void parse_setuid_exit(sinsp_evt& evt) const;
	void parse_setgid_exit(sinsp_evt& evt) const;
	void parse_user_evt(sinsp_evt& evt) const;
	void parse_group_evt(sinsp_evt& evt) const;
	void parse_cpu_hotplug_enter(sinsp_evt& evt) const;
	static void parse_chroot_exit(sinsp_evt& evt);
	static void parse_setsid_exit(sinsp_evt& evt);
	void parse_getsockopt_exit(sinsp_evt& evt, sinsp_parser_verdict& verdict) const;
	static void parse_capset_exit(sinsp_evt& evt);
	static void parse_unshare_setns_exit(sinsp_evt& evt);

	// Set the event thread user to the user corresponding to the effective user id taken from the
	// provided parameter. This is no-op if there is no thread associated with the provided event
	// or the provided parameter is empty.
	void set_evt_thread_user(sinsp_evt& evt, const sinsp_evt_param& euid_param) const;

	// Set the event thread group to the group corresponding to the effective group id taken from
	// the provided parameter. This is no-op if there is no thread associated with the provided
	// event or the provided parameter is empty.
	void set_evt_thread_group(sinsp_evt& evt, const sinsp_evt_param& egid_param) const;

	static inline bool update_ipv4_addresses_and_ports(sinsp_fdinfo& fdinfo,
	                                                   uint32_t tsip,
	                                                   uint16_t tsport,
	                                                   uint32_t tdip,
	                                                   uint16_t tdport,
	                                                   bool overwrite_dest = true);
	static inline void fill_client_socket_info(sinsp_evt& evt,
	                                           const uint8_t* packed_data,
	                                           bool overwrite_dest,
	                                           bool can_resolve_hostname_and_port);
	inline void add_socket(sinsp_evt& evt,
	                       int64_t fd,
	                       uint32_t domain,
	                       uint32_t type,
	                       uint32_t protocol) const;
	inline void infer_send_sendto_sendmsg_fdinfo(sinsp_evt& evt) const;
	inline void add_pipe(sinsp_evt& evt, int64_t fd, uint64_t ino, uint32_t openflags) const;
	// Return false if the update didn't happen (for example because the tuple is NULL)
	bool update_fd(sinsp_evt& evt, const sinsp_evt_param& parinfo) const;
#ifndef _WIN32
	// Process file descriptors extracted from recvmsg ancillary data.
	static inline void process_recvmsg_ancillary_data_fds(scap_platform* scap_platform,
	                                                      int const* fds,
	                                                      size_t fds_len,
	                                                      scap_threadinfo& scap_tinfo);
	// Process recvmsg ancillary data.
	inline void process_recvmsg_ancillary_data(sinsp_evt& evt,
	                                           const sinsp_evt_param& parinfo) const;
#endif

	// Next 4 return false if the update didn't happen because the tuple is identical to the given
	// address
	static bool set_ipv4_addresses_and_ports(sinsp_fdinfo& fdinfo,
	                                         const uint8_t* packed_data,
	                                         bool overwrite_dest = true);
	static bool set_ipv4_mapped_ipv6_addresses_and_ports(sinsp_fdinfo& fdinfo,
	                                                     const uint8_t* packed_data,
	                                                     bool overwrite_dest = true);
	static bool set_ipv6_addresses_and_ports(sinsp_fdinfo& fdinfo,
	                                         const uint8_t* packed_data,
	                                         bool overwrite_dest = true);

	static void swap_addresses(sinsp_fdinfo& fdinfo);
	void erase_fd(erase_fd_params& params, sinsp_parser_verdict& verdict) const;

	bool is_syscall_plugin_enabled() const {
		return m_params->m_sinsp_mode.is_plugin() && m_params->m_input_plugin->id() == 0;
	}

	bool is_large_envs_enabled() const {
		return (m_params->m_sinsp_mode.is_live() || is_syscall_plugin_enabled()) &&
		       m_params->m_large_envs_enabled;
	}

	bool must_notify_thread_user_update() const {
		return m_params->m_sinsp_mode.is_live() || is_syscall_plugin_enabled();
	}

	bool must_notify_thread_group_update() const {
		return m_params->m_sinsp_mode.is_live() || is_syscall_plugin_enabled();
	}

	// Parameters provided at parser construction phase.
	// Notice: the struct instance is shared among all the parser instances.
	// Notice 2: this should be a plain const reference, but use a shared_ptr or the compiler will
	// complain about referencing a member whose lifetime is shorter than the ctor_params object in
	// sinsp constructor.
	const std::shared_ptr<sinsp_parser_shared_params> m_params;
	sinsp_evt& m_tmp_evt_storage;

	bool m_track_connection_status = false;

	// Per-worker thread data storage (moved from threadinfo to avoid race conditions)
	struct thread_data {
		// Event data storage
		std::unique_ptr<uint8_t[]> event_data;
		size_t event_data_size;

		// Multi-event processing state
		int64_t lastevent_fd = -1;      ///< The FD of the last event used by this thread
		uint64_t lastevent_ts = 0;      ///< timestamp of the last event for this thread
		uint64_t prevevent_ts = 0;      ///< timestamp of the event before the last for this thread
		uint64_t lastaccess_ts = 0;     ///< The last time this thread was looked up
		uint64_t clone_ts = 0;          ///< When the clone that started this process happened
		uint64_t lastexec_ts = 0;       ///< The last time exec was called for this thread

		// File descriptor table (moved from threadinfo to avoid race conditions)
		std::unique_ptr<sinsp_fdtable> fdtable;
	};

	mutable std::unordered_map<int64_t, thread_data> m_thread_data;
};
