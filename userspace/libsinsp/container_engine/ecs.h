#pragma once

#include <unordered_map>

class sinsp_container_info;
class sinsp_threadinfo;

#include "container_engine/container_engine_base.h"
#include "container_engine/sinsp_container_type.h"

namespace libsinsp::container_engine {
class ecs : public container_engine_base {
public:
	explicit ecs(container_cache_interface &cache): container_engine_base(cache) {
		// bite the bullet and fetch the metadata synchronously on startup
		// we only need this once, and it makes future lookups immediate
		// and much simpler compared to a background thread with async lookups
		fetch_metadata();
	}

	bool resolve(sinsp_threadinfo *tinfo, bool query_os_for_missing_info) override;

	// truncate the container id to the first TASK_PREFIX_LEN (currently 8) characters of the task
	// id, with the container number appended.
	//
	// Example:
	// before: d682f1f5481c46a5909c41b78925f649-4177833528
	// after: d682f1f5-4177833528
	static std::string truncate_container_id(std::string_view full_container_id);

protected:
	void fetch_metadata();

	static bool match(const std::string &cgroup, sinsp_container_info &container_info);

	// only enable the engine if we successfully fetch the metadata
	bool m_enabled = false;
};
}  // namespace libsinsp::container_engine
