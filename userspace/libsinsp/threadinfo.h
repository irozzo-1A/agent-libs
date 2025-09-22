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

#pragma once

#define DEFAULT_EXPIRED_CHILDREN_THRESHOLD 10

#ifdef _WIN32
struct iovec {
	void* iov_base; /* Starting address */
	size_t iov_len; /* Number of bytes to transfer */
};
#else
#include <sys/uio.h>
#endif

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <sinsp_fdtable_factory.h>
#include <libsinsp/fdtable.h>
#include <libsinsp/thread_group_info.h>
#include <libsinsp/state/table.h>
#include <libsinsp/state/table_adapters.h>
#include <libsinsp/event.h>
#include <libsinsp/filter.h>
#include <libsinsp/ifinfo.h>
#include <libscap/scap_savefile_api.h>

// Forward declare `sinsp_thread_manager` and `sinsp_usergroup_manager` to avoid cyclic
// dependencies.
class sinsp_thread_manager;
class sinsp_usergroup_manager;

struct erase_fd_params {
	bool m_remove_from_table;
	int64_t m_fd;
	sinsp_threadinfo* m_tinfo;
	sinsp_fdinfo* m_fdinfo;
};

/** @defgroup state State management
 *  @{
 */

/*!
  \brief Container holding parameters to be provided to sinsp_threadinfo constructor.
  An instance of this struct is meant to be shared among all sinsp_threadinfo instances.
*/
struct sinsp_threadinfo_ctor_params {
	// The following fields are externally provided and access to them is expected to be
	// read-only.
	const sinsp_network_interfaces& network_interfaces;
	const sinsp_fdinfo_factory& fdinfo_factory;
	const sinsp_fdtable_factory& fdtable_factory;
	const std::shared_ptr<libsinsp::state::table_entry::dynamic_struct::field_infos>&
	        thread_manager_dyn_fields;

	// The following fields are externally provided and expected to be populated/updated by the
	// thread info.
	std::shared_ptr<sinsp_thread_manager>& thread_manager;
	std::shared_ptr<sinsp_usergroup_manager>& usergroup_manager;
};

/*!
  \brief Thread/process information class.
  This class contains the full state for a thread, and a bunch of functions to
  manipulate threads and retrieve thread information.

  \note As a library user, you won't need to construct thread objects. Rather,
   you get them by calling \ref sinsp_evt::get_thread_info or
   \ref sinsp::get_thread.
  \note sinsp_threadinfo is also used to keep process state. For the sinsp
   library, a process is just a thread with TID=PID.
*/
class SINSP_PUBLIC sinsp_threadinfo : public libsinsp::state::table_entry {
public:
	using ctor_params = sinsp_threadinfo_ctor_params;

	explicit sinsp_threadinfo(const std::shared_ptr<ctor_params>& params);
	~sinsp_threadinfo() override;

	libsinsp::state::static_struct::field_infos static_fields() const override;

	/*!
	  \brief Return the name of the process containing this thread, e.g. "top".
	*/
	std::string get_comm() const;

	/*!
	  \brief Return the name of the process containing this thread from argv[0], e.g. "/bin/top".
	*/
	std::string get_exe() const;

	/*!
	  \brief Return the full executable path of the process containing this thread, e.g. "/bin/top".
	*/
	std::string get_exepath() const;

	/*!
	  \brief Return the container_id associated with this thread, if the container plugins is
	  running, leveraging sinsp state table API.
	*/
	std::string get_container_id();

	/*!
	  \brief Given the container_id associated with this thread, feetches the container user from
	  the containers table, created by the container plugins if running, leveraging sinsp state
	  table API.
	*/
	std::string get_container_user();

	/*!
	  \brief Given the container_id associated with this thread, feetches the container ip from the
	  containers table, created by the container plugins if running, leveraging sinsp state table
	  API.
	*/
	std::string get_container_ip();

	/*!
	  \brief Return the full info about thread uid.
	*/
	scap_userinfo* get_user();

	/*!
	  \brief Return the full info about thread gid.
	*/
	scap_groupinfo* get_group();

	/*!
	  \brief Return the full info about thread loginuid.
	*/
	scap_userinfo* get_loginuser();

	/*!
	  \brief Return the working directory of the process containing this thread.
	*/
	std::string get_cwd();

	inline void set_cwd(const std::string& v) {
		std::unique_lock<std::shared_mutex> lock(m_mutex);
		m_cwd = v;
	}

	/*!
	  \brief Return the values of all environment variables for the process
	  containing this thread.
	*/
	const std::vector<std::string>& get_env();

	/*!
	  \brief Return the value of the specified environment variable for the process
	  containing this thread. Returns empty string if variable is not found.
	*/
	std::string get_env(const std::string& name);

	/*!
	  \brief Return concatenated environment variables with the format of "ENV_NAME=value
	  ENV_NAME1=value1" ...
	*/
	std::string concatenate_all_env();

	/*!
	  \brief Return true if this is a process' main thread.
	*/
	inline bool is_main_thread() const {
		std::shared_lock<std::shared_mutex> lock(m_mutex);
		return (m_tid == m_pid) || m_flags & PPM_CL_IS_MAIN_THREAD;
	}

	/*!
	  \brief Return true if this thread belongs to a pid namespace.
	*/
	inline bool is_in_pid_namespace() const {
		std::shared_lock<std::shared_mutex> lock(m_mutex);
		// m_tid should be always valid because we read it from the scap event header
		return (m_flags & PPM_CL_CHILD_IN_PIDNS || (m_tid != m_vtid && m_vtid >= 0));
	}

	/*!
	  \brief Return true if the thread is invalid. Sometimes we create some
	  invalid thread info, if we are not able to scan proc.
	*/
	inline bool is_invalid() const {
		std::shared_lock<std::shared_mutex> lock(m_mutex);
		return m_tid < 0 || m_pid < 0 || m_ptid < 0;
	}

	/*!
	  \brief Return true if this thread is dead.
	*/
	inline bool is_dead() const {
		std::shared_lock<std::shared_mutex> lock(m_mutex);
		return m_flags & PPM_CL_CLOSED;
	}

	/*!
	  \brief Mark this thread as dead.
	*/
	inline void set_dead() {
		std::unique_lock<std::shared_mutex> lock(m_mutex);
		m_flags |= PPM_CL_CLOSED;
	}

	/*!
	  \brief Mark this thread as alive (resurrect it).
	*/
	inline void resurrect_thread() {
		std::unique_lock<std::shared_mutex> lock(m_mutex);
		m_flags &= ~PPM_CL_CLOSED;
	}

	/*!
	    \brief Return the number of alive threads in the thread group, including the thread leader.
	*/
	inline uint64_t get_num_threads() const { return m_tginfo ? m_tginfo->get_thread_count() : 0; }

	/*!
	    \brief Return the number of alive threads in the thread group, excluding the thread leader.
	*/
	inline uint64_t get_num_not_leader_threads() const {
		if(!m_tginfo) {
			return 0;
		}

		// Check if this thread is the main thread first to avoid deadlock
		if(is_main_thread()) {
			// This is the main thread, check if it's dead
			if(!is_dead()) {
				return m_tginfo->get_thread_count() - 1;
			}
			return m_tginfo->get_thread_count();
		}

		// This is not the main thread, get the main thread
		auto main_thread = get_main_thread();
		if(main_thread != nullptr && !main_thread->is_dead()) {
			return m_tginfo->get_thread_count() - 1;
		}
		/* we don't have the main thread in the group or it is dead */
		return m_tginfo->get_thread_count();
	}

	/*
	  \brief returns true if there is a loop detected in the thread parent state.
	  Needs traverse_parent_state() to have been called first.
	*/
	inline bool parent_loop_detected() const {
		std::shared_lock<std::shared_mutex> lock(m_mutex);
		return m_parent_loop_detected;
	}

	inline void set_parent_loop_detected(bool v) {
		std::unique_lock<std::shared_mutex> lock(m_mutex);
		m_parent_loop_detected = v;
	}

	/*!
	  \brief Get the main thread of the process containing this thread.
	*/
	std::shared_ptr<sinsp_threadinfo> get_main_thread();

	inline std::shared_ptr<const sinsp_threadinfo> get_main_thread() const {
		return const_cast<sinsp_threadinfo*>(this)->get_main_thread();
	}

	/*!
	  \brief Get the main thread of the process containing this thread (unlocked version).
	  This method should only be called from methods that already hold the lock.
	*/
	std::shared_ptr<sinsp_threadinfo> get_main_thread_unlocked();

	inline std::shared_ptr<const sinsp_threadinfo> get_main_thread_unlocked() const {
		return const_cast<sinsp_threadinfo*>(this)->get_main_thread_unlocked();
	}

	/*!
	  \brief Get the thread that launched this thread's process.
	*/
	std::shared_ptr<sinsp_threadinfo> get_parent_thread();

	/*!
	  \brief Get the process that launched this thread's process (its parent) or any of its
	  ancestors.

	  \param n when 1 it will look for the parent process, when 2 the grandparent and so forth.

	  \return Pointer to the threadinfo or NULL if it doesn't exist
	*/
	std::shared_ptr<sinsp_threadinfo> get_ancestor_process(uint32_t n = 1);

	/*!
	  \brief Retrieve information about one of this thread/process FDs.

	  \param fd The file descriptor number, e.g. 0 for stdin.

	  \return Pointer to the FD information, or NULL if the given FD doesn't
	   exist
	*/
	inline std::shared_ptr<sinsp_fdinfo> get_fd(int64_t fd) {
		if(fd < 0) {
			return nullptr;
		}

		std::shared_lock<std::shared_mutex> lock(m_mutex);
		auto fdt = get_fd_table_unlocked();

		if(fdt) {
			auto fdinfo = fdt->find(fd);
			if(fdinfo) {
				// Its current name is now its old
				// name. The name might change as a
				// result of parsing.
				// Use atomic operation to avoid race condition
				fdinfo->update_oldname_from_current();
				return fdinfo;
			}
		}

		return nullptr;
	}

	/*!
	  \brief Iterate over open file descriptors in the process.

	  \return True if all callback invoations returned true, false if not
	*/
	bool loop_fds(sinsp_fdtable::fdtable_const_visitor_t visitor);

	/*!
	  \brief Return true if this thread is bound to the given server port.
	*/
	bool is_bound_to_port(uint16_t number) const;

	/*!
	  \brief Return true if this thread has a client socket open on the given port.
	*/
	bool uses_client_port(uint16_t number) const;

	/*!
	  \brief Return the ratio between open FDs and maximum available FDs for this thread.
	*/
	uint64_t get_fd_usage_pct();
	double get_fd_usage_pct_d();

	/*!
	  \brief Return the number of open FDs for this thread.
	*/
	uint64_t get_fd_opencount() const;

	/*!
	  \brief Return the maximum number of FDs this thread can open.
	*/
	uint64_t get_fd_limit();

	/*!
	  \brief Return the cgroup name for a specific subsystem

	  If the subsystem isn't mounted, return "/"
	 */
	const std::string& get_cgroup(const std::string& subsys) const;

	/*!
	  \brief Return the cgroup name for a specific subsystem

	  If the subsystem isn't mounted, return false and leave `cgroup`
	  unchanged
	 */
	bool get_cgroup(const std::string& subsys, std::string& cgroup) const;

	//
	// Walk up the parent process hierarchy, calling the provided
	// function for each node. If the function returns false, the
	// traversal stops.
	//
	typedef std::function<bool(sinsp_threadinfo*)> visitor_func_t;
	void traverse_parent_state(visitor_func_t& visitor);

	void assign_children_to_reaper(sinsp_threadinfo* reaper);

	inline void add_child(const std::shared_ptr<sinsp_threadinfo>& child) {
		/* Then, add to parent's children list (acquire parent's mutex) */
		int64_t tmp_tid;
		{
			std::unique_lock<std::shared_mutex> lock(m_mutex);
			m_children.push_front(child);
			/* Increment the number of not expired children */
			m_not_expired_children++;
			tmp_tid = m_tid;
		}

		/* First, set current thread as parent (acquire child's mutex) */
		{
			std::unique_lock<std::shared_mutex> child_lock(child->m_mutex);
			child->m_ptid = tmp_tid;
		}
	}

	/* We call it immediately before removing the thread from the thread table. */
	inline void remove_child_from_parent() {
		std::unique_lock<std::shared_mutex> lock(m_mutex);
		auto parent = get_parent_thread();
		if(parent == nullptr) {
			return;
		}

		parent->m_not_expired_children--;

		/* Clean expired children if necessary. */
		if((parent->m_children.size() - parent->m_not_expired_children) >=
		   DEFAULT_EXPIRED_CHILDREN_THRESHOLD) {
			parent->clean_expired_children();
		}
	}

	/*!
	  \brief Remove a child from this thread's children list (called by thread manager).
	  \param child_tid The thread ID of the child to remove.
	*/
	inline void remove_child_by_tid(int64_t child_tid) {
		std::unique_lock<std::shared_mutex> lock(m_mutex);
		m_not_expired_children--;

		/* Clean expired children if necessary. */
		if((m_children.size() - m_not_expired_children) >= DEFAULT_EXPIRED_CHILDREN_THRESHOLD) {
			auto child = m_children.begin();
			while(child != m_children.end()) {
				if(child->expired()) {
					child = m_children.erase(child);
					continue;
				}
				child++;
			}
		}
	}

	inline void clean_expired_children() {
		std::unique_lock<std::shared_mutex> lock(m_mutex);
		auto child = m_children.begin();
		while(child != m_children.end()) {
			/* This child is expired */
			if(child->expired()) {
				/* `erase` returns the pointer to the next child
				 * no need for manual increment.
				 */
				child = m_children.erase(child);
				continue;
			}
			child++;
		}
	}

	static void populate_cmdline(std::string& cmdline, const sinsp_threadinfo* tinfo);
	static void populate_args(std::string& args, const sinsp_threadinfo* tinfo);

	/*!
	  \brief Translate a directory's file descriptor into its path
	  \param dir_fd  A file descriptor for a directory
	  \return  A path (or "" if failure)
	 */
	std::string get_path_for_dir_fd(int64_t dir_fd);

	/*!
	  \brief Set the thread user and optionally notify any interested component.
	  \param uid The user id.
	  \param notify A boolean indicating if any interested component must be notified of the update.
	*/
	void set_user(uint32_t uid, bool notify);
	/*!
	  \brief Set the thread group and optionally notify any interested component.
	  \param gid The group id.
	  \param notify A boolean indicating if any interested component must be notified of the update.
	*/
	void set_group(uint32_t gid, bool notify);
	void set_loginuid(uint32_t loginuid);

	using cgroups_t = std::vector<std::pair<std::string, std::string>>;
	const cgroups_t& cgroups() const;

	/*!
	  \brief Return the thread manager associated with this thread.
	*/
	std::shared_ptr<sinsp_thread_manager> get_thread_manager() const;

	//
	// Core state
	//
	int64_t m_tid;   ///< The id of this thread
	int64_t m_pid;   ///< The id of the process containing this thread. In single thread threads,
	                 ///< this is equal to tid.
	int64_t m_ptid;  ///< The id of the process that started this thread.
	int64_t m_reaper_tid;   ///< The id of the reaper for this thread
	int64_t m_sid;          ///< The session id of the process containing this thread.
	std::string m_comm;     ///< Command name (e.g. "top")
	std::string m_exe;      ///< argv[0] (e.g. "sshd: user@pts/4")
	std::string m_exepath;  ///< full executable path
	bool m_exe_writable;
	bool m_exe_upper_layer;  ///< True if the executable file belongs to upper layer in overlayfs
	bool m_exe_lower_layer;  ///< True if the executable file belongs to lower layer in overlayfs
	bool m_exe_from_memfd;   ///< True if the executable is stored in fileless memory referenced by
	                         ///< memfd
	std::vector<std::string> m_args;  ///< Command line arguments (e.g. "-d1")
	std::vector<std::string> m_env;   ///< Environment variables
	cgroups_t m_cgroups;              ///< subsystem-cgroup pairs
	uint32_t m_flags;   ///< The thread flags. See the PPM_CL_* declarations in ppm_events_public.h.
	int64_t m_fdlimit;  ///< The maximum number of FDs this thread can open
	uint32_t m_uid;     ///< uid
	uint32_t m_gid;     ///< gid
	uint32_t m_loginuid;         ///< loginuid
	uint64_t m_cap_permitted;    ///< permitted capabilities
	uint64_t m_cap_effective;    ///< effective capabilities
	uint64_t m_cap_inheritable;  ///< inheritable capabilities
	uint64_t m_exe_ino;          ///< executable inode ino
	uint64_t m_exe_ino_ctime;    ///< executable inode ctime (last status change time)
	uint64_t m_exe_ino_mtime;    ///< executable inode mtime (last modification time)
	uint64_t m_exe_ino_ctime_duration_clone_ts;  ///< duration in ns between executable inode ctime
	                                             ///< (last status change time) and clone_ts
	uint64_t m_exe_ino_ctime_duration_pidns_start;  ///< duration in ns between pidns start ts and
	                                                ///< executable inode ctime (last status change
	                                                ///< time) if pidns start predates ctime
	uint32_t m_vmsize_kb;                           ///< total virtual memory (as kb).
	uint32_t m_vmrss_kb;                            ///< resident non-swapped memory (as kb).
	uint32_t m_vmswap_kb;                           ///< swapped memory (as kb).
	uint64_t m_pfmajor;                             ///< number of major page faults since start.
	uint64_t m_pfminor;                             ///< number of minor page faults since start.
	int64_t m_vtid;                                 ///< The virtual id of this thread.
	int64_t m_vpid;   ///< The virtual id of the process containing this thread. In single thread
	                  ///< threads, this is equal to vtid.
	int64_t m_vpgid;  // The virtual process group id, as seen from its pid namespace
	int64_t m_pgid;   // Process group id, as seen from the host pid namespace
	uint64_t m_pidns_init_start_ts;  ///< The pid_namespace init task (child_reaper) start_time ts.
	std::string m_root;

	uint32_t m_tty;  ///< Number of controlling terminal
	std::shared_ptr<thread_group_info> m_tginfo;
	std::list<std::weak_ptr<sinsp_threadinfo>> m_children;
	uint64_t m_not_expired_children;
	std::string m_cmd_line;
	bool m_filtered_out;  ///< True if this thread is filtered out by the inspector filter from
	                      ///< saving to a capture

	//
	// State for multi-event processing (atomic for lock-free operations)
	//
	std::atomic<int64_t> m_lastevent_fd{-1};  ///< The FD of the last event used by this thread.
	std::atomic<uint64_t> m_lastevent_ts{0};  ///< timestamp of the last event for this thread.
	std::atomic<uint64_t> m_prevevent_ts{
	        0};  ///< timestamp of the event before the last for this thread.
	std::atomic<uint64_t> m_lastaccess_ts{0};  ///< The last time this thread was looked up. Used
	                                           ///< when cleaning up the table.
	std::atomic<uint64_t> m_clone_ts{0};     ///< When the clone that started this process happened.
	std::atomic<uint64_t> m_lastexec_ts{0};  ///< The last time exec was called
	std::atomic<uint16_t> m_lastevent_cpuid{0};  ///< CPU ID of the last event for this thread.

	size_t args_len() const;
	size_t env_len() const;

	void args_to_iovec(struct iovec** iov, int* iovcnt, std::string& rem) const;

	void env_to_iovec(struct iovec** iov, int* iovcnt, std::string& rem) const;

	void cgroups_to_iovec(struct iovec** iov,
	                      int* iovcnt,
	                      std::string& rem,
	                      const cgroups_t& cgroups) const;

	//
	// State for filtering
	//
	std::atomic<uint64_t> m_last_latency_entertime;
	std::atomic<uint64_t> m_latency;

	/* Note that `fd_table` should be shared with the main thread only if `PPM_CL_CLONE_FILES`
	 * is specified. Today we always specify `PPM_CL_CLONE_FILES` for all threads.
	 */
	inline std::shared_ptr<sinsp_fdtable> get_fd_table() {
		std::shared_lock<std::shared_mutex> lock(m_mutex);
		return get_fd_table_unlocked();
	}

	inline std::shared_ptr<const sinsp_fdtable> get_fd_table() const {
		std::shared_lock<std::shared_mutex> lock(m_mutex);
		return get_fd_table_unlocked();
	}

	void init();
	void init(const scap_threadinfo& pinfo,
	          bool can_load_env_from_proc,
	          bool notify_user_update,
	          bool notify_group_update);
	void fix_sockets_coming_from_proc(const std::set<uint16_t>& ipv4_server_ports,
	                                  bool resolve_hostname_and_port);
	std::shared_ptr<sinsp_fdinfo> add_fd(int64_t fd, std::shared_ptr<sinsp_fdinfo>&& fdinfo);
	std::shared_ptr<sinsp_fdinfo> add_fd_from_scap(const scap_fdinfo& fdi,
	                                               bool resolve_hostname_and_port);
	void remove_fd(int64_t fd);
	void update_cwd(std::string_view cwd);
	void set_args(const char* args, size_t len);
	void set_args(const std::vector<std::string>& args);
	void set_env(const char* env, size_t len, bool can_load_from_proc);
	void set_cgroups(const char* cgroups, size_t len);
	void set_cgroups(const std::vector<std::string>& cgroups);
	void set_cgroups(const cgroups_t& cgroups);
	bool is_lastevent_data_valid() const;
	inline void set_lastevent_data_validity(bool isvalid) {
		if(isvalid) {
			m_lastevent_cpuid.store((uint16_t)1);
		} else {
			m_lastevent_cpuid.store((uint16_t)-1);
		}
	}

	inline std::shared_ptr<const sinsp_fdtable> get_fdtable() const { return m_fdtable; }

	inline std::shared_ptr<sinsp_fdtable> get_fdtable() { return m_fdtable; }

	// Thread-safe fdtable operations
	inline void clear_fdtable() {
		std::unique_lock<std::shared_mutex> lock(m_mutex);
		if(m_fdtable) {
			m_fdtable->clear();
		}
	}

	inline void set_fdtable_tid(uint64_t tid) {
		std::unique_lock<std::shared_mutex> lock(m_mutex);
		if(m_fdtable) {
			m_fdtable->set_tid(tid);
		}
	}

	inline std::shared_ptr<sinsp_fdinfo> add_fd_to_table(int64_t fd,
	                                                     std::shared_ptr<sinsp_fdinfo>&& fdinfo) {
		std::unique_lock<std::shared_mutex> lock(m_mutex);
		if(m_fdtable) {
			return m_fdtable->add(fd, std::move(fdinfo));
		}
		return nullptr;
	}

	inline void reset_fdtable_cache() {
		std::unique_lock<std::shared_mutex> lock(m_mutex);
		if(m_fdtable) {
			m_fdtable->reset_cache();
		}
	}

	inline const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>&
	get_fdtable_dynamic_fields() const {
		std::shared_lock<std::shared_mutex> lock(m_mutex);
		static const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos> empty;
		return m_fdtable ? m_fdtable->dynamic_fields() : empty;
	}

	inline void set_fdtable_dynamic_fields(
	        const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>& fields) {
		std::unique_lock<std::shared_mutex> lock(m_mutex);
		if(m_fdtable) {
			m_fdtable->set_dynamic_fields(fields);
		}
	}

	inline uint16_t get_lastevent_cpuid() const { return m_lastevent_cpuid.load(); }

	inline void set_lastevent_cpuid(uint16_t v) { m_lastevent_cpuid.store(v); }

	inline const sinsp_evt::category& get_lastevent_category() const {
		return m_lastevent_category;
	}

	inline sinsp_evt::category& get_lastevent_category() { return m_lastevent_category; }

	sinsp_threadinfo* get_oldest_matching_ancestor(
	        const std::function<int64_t(sinsp_threadinfo*)>& get_thread_id,
	        bool is_virtual_id = false);

	std::string get_ancestor_field_as_string(
	        const std::function<int64_t(sinsp_threadinfo*)>& get_thread_id,
	        const std::function<std::string(sinsp_threadinfo*)>& get_field_str,
	        bool is_virtual_id = false);

	inline void update_main_fdtable() {
		std::unique_lock<std::shared_mutex> lock(m_mutex);
		auto fdtable = get_fd_table_unlocked();
		m_main_fdtable =
		        !fdtable ? nullptr
		                 : static_cast<const libsinsp::state::base_table*>(fdtable->table_ptr());
	}

	inline void set_flag(uint32_t flag) {
		std::unique_lock<std::shared_mutex> lock(m_mutex);
		m_flags |= flag;
	}

	/*!
	  \brief Thread-safe setter for parent thread ID.
	  \param ptid The parent thread ID to set.
	*/
	inline void set_ptid(int64_t ptid) {
		std::unique_lock<std::shared_mutex> lock(m_mutex);
		m_ptid = ptid;
	}

	/*!
	  \brief Thread-safe setter for virtual thread ID.
	  \param vtid The virtual thread ID to set.
	*/
	inline void set_vtid(int64_t vtid) {
		std::unique_lock<std::shared_mutex> lock(m_mutex);
		m_vtid = vtid;
	}

	/*!
	  \brief Thread-safe setter for virtual process ID.
	  \param vpid The virtual process ID to set.
	*/
	inline void set_vpid(int64_t vpid) {
		std::unique_lock<std::shared_mutex> lock(m_mutex);
		m_vpid = vpid;
	}

	/*!
	  \brief Thread-safe setter for file descriptor limit.
	  \param fdlimit The file descriptor limit to set.
	*/
	inline void set_fdlimit(int64_t fdlimit) {
		std::unique_lock<std::shared_mutex> lock(m_mutex);
		m_fdlimit = fdlimit;
	}

	/*!
	  \brief Thread-safe setter for process ID.
	  \param pid The process ID to set.
	*/
	inline void set_pid(int64_t pid) {
		std::unique_lock<std::shared_mutex> lock(m_mutex);
		m_pid = pid;
	}

	/*!
	  \brief Check if the thread has the PPM_CL_CLONE_INVERTED flag set.
	  \return true if the flag is set, false otherwise.
	*/
	inline bool is_clone_inverted() const {
		std::shared_lock<std::shared_mutex> lock(m_mutex);
		return (m_flags & PPM_CL_CLONE_INVERTED) != 0;
	}

	void set_exepath(std::string&& exepath);

	/*!
	  \brief A static version of static_fields()
	  \return The group of field infos available.
	 */
	static static_struct::field_infos get_static_fields();

protected:
	// Parameters provided at thread info construction phase.
	// Notice: the struct instance is shared among all the thread info instances.
	// Notice 2: this should be a plain const reference, but use a shared_ptr or the compiler will
	// complain about referencing a member (m_input_plugin) whose lifetime is shorter than the
	// ctor_params object in sinsp constructor.
	const std::shared_ptr<ctor_params> m_params;

private:
	sinsp_threadinfo* get_cwd_root();
	bool set_env_from_proc();
	size_t strvec_len(const std::vector<std::string>& strs) const;
	void strvec_to_iovec(const std::vector<std::string>& strs,
	                     struct iovec** iov,
	                     int* iovcnt,
	                     std::string& rem) const;

	void add_to_iovec(const std::string& str,
	                  const bool include_trailing_null,
	                  struct iovec& iov,
	                  uint32_t& alen,
	                  std::string& rem) const;

	// Private version for use by methods that already hold the lock
	inline std::shared_ptr<sinsp_fdtable> get_fd_table_unlocked() {
		if(!(m_flags & PPM_CL_CLONE_FILES)) {
			return m_fdtable;
		} else {
			std::shared_ptr<sinsp_threadinfo> root = get_main_thread_unlocked();
			return (root == nullptr) ? nullptr : root->get_fdtable();
		}
	}

	inline std::shared_ptr<const sinsp_fdtable> get_fd_table_unlocked() const {
		if(!(m_flags & PPM_CL_CLONE_FILES)) {
			return m_fdtable;
		} else {
			std::shared_ptr<const sinsp_threadinfo> root = get_main_thread_unlocked();
			return (root == nullptr) ? nullptr : root->get_fdtable();
		}
	}

	//
	// Parameters that can't be accessed directly because they could be in the
	// parent thread info
	//
	std::shared_ptr<sinsp_fdtable> m_fdtable;  // The fd table of this thread
	const libsinsp::state::base_table*
	        m_main_fdtable;  // Points to the base fd table of the current main thread
	std::string m_cwd;       // current working directory
	sinsp_evt::category m_lastevent_category;
	mutable bool m_parent_loop_detected;
	libsinsp::state::stl_container_table_adapter<decltype(m_args)> m_args_table_adapter;
	libsinsp::state::stl_container_table_adapter<decltype(m_env)> m_env_table_adapter;
	libsinsp::state::stl_container_table_adapter<
	        decltype(m_cgroups),
	        libsinsp::state::pair_table_entry_adapter<std::string, std::string>>
	        m_cgroups_table_adapter;
	mutable std::shared_mutex m_mutex;
};

/*@}*/

class threadinfo_map_t {
public:
	typedef std::function<bool(const std::shared_ptr<sinsp_threadinfo>&)>
	        const_shared_ptr_visitor_t;
	typedef std::function<bool(const sinsp_threadinfo&)> const_visitor_t;
	typedef std::function<bool(sinsp_threadinfo&)> visitor_t;
	typedef std::shared_ptr<sinsp_threadinfo> ptr_t;

	inline ptr_t put(const ptr_t& tinfo) {
		std::unique_lock<std::shared_mutex> lock(m_mutex);
		// Try inserting the thread info into the map, if it already exists do not override
		auto it = m_threads.try_emplace(tinfo->m_tid, tinfo);
		if(it.second) {
			return it.first->second;
		} else {
			return m_threads[tinfo->m_tid];
		}
	}

	inline ptr_t get(uint64_t tid) {
		std::shared_lock<std::shared_mutex> lock(m_mutex);
		auto it = m_threads.find(tid);
		if(it == m_threads.end()) {
			return ptr_t();  // Return empty shared_ptr instead of reference
		}
		return it->second;  // Return a copy, not a reference
	}

	inline void erase(uint64_t tid) {
		std::unique_lock<std::shared_mutex> lock(m_mutex);
		m_threads.erase(tid);
	}

	inline void clear() {
		std::unique_lock<std::shared_mutex> lock(m_mutex);
		m_threads.clear();
	}

	bool const_loop_shared_pointer(const_shared_ptr_visitor_t callback) {
		std::shared_lock<std::shared_mutex> lock(m_mutex);
		for(auto& it : m_threads) {
			if(!callback(it.second)) {
				return false;
			}
		}
		return true;
	}

	bool const_loop(const_visitor_t callback) const {
		std::shared_lock<std::shared_mutex> lock(m_mutex);
		for(const auto& it : m_threads) {
			if(!callback(*it.second)) {
				return false;
			}
		}
		return true;
	}

	bool loop(visitor_t callback) {
		std::shared_lock<std::shared_mutex> lock(m_mutex);
		for(auto& it : m_threads) {
			if(!callback(*it.second)) {
				return false;
			}
		}
		return true;
	}

	inline size_t size() const {
		std::shared_lock<std::shared_mutex> lock(m_mutex);
		return m_threads.size();
	}

protected:
	std::unordered_map<int64_t, ptr_t> m_threads;
	mutable std::shared_mutex m_mutex;  // Protects m_threads
};
