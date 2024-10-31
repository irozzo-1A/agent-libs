#include "ecs.h"

#include "sinsp.h"

constexpr const size_t TASK_PREFIX_LEN = 8;

std::string libsinsp::container_engine::ecs::truncate_container_id(
        std::string_view full_container_id) {
	auto container_number_start = full_container_id.find('-');
	if(container_number_start == full_container_id.npos ||
	   container_number_start < TASK_PREFIX_LEN) {
		return std::string{full_container_id};
	}
	std::string_view container_prefix = full_container_id.substr(0, TASK_PREFIX_LEN);
	std::string_view container_number = full_container_id.substr(container_number_start);

	std::string truncated_id{container_prefix};
	truncated_id.append(container_number);
	return truncated_id;
}

namespace {
size_t ecs_curl_write_callback(const char* ptr, size_t size, size_t nmemb, std::string* json) {
	const std::size_t total = size * nmemb;
	json->append(ptr, total);
	return total;
}
}  // namespace

void libsinsp::container_engine::ecs::fetch_metadata() {
	const char* metadata_uri = getenv("ECS_CONTAINER_METADATA_URI_V4");
	if(metadata_uri == nullptr) {
		// not running in Fargate ECS
		return;
	}

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
	                          "ecs: ECS_CONTAINER_METADATA_URI_V4=%s",
	                          metadata_uri);

	std::string json;
	std::string url{metadata_uri};
	url.append("/task");

	CURL* curl = curl_easy_init();
	if(!curl) {
		libsinsp_logger()->format(sinsp_logger::SEV_WARNING,
		                          "ecs (%s): Failed to initialize curl handle",
		                          url.c_str());
		return;
	}

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG, "ecs (%s): Fetching url", url.c_str());

	char curl_error[CURL_ERROR_SIZE];
	curl_error[0] = '\0';

	curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ecs_curl_write_callback);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 1000);
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &json);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_error);

	CURLcode res = curl_easy_perform(curl);
	if(res != CURLE_OK) {
		libsinsp_logger()->format(sinsp_logger::SEV_WARNING,
		                          "ecs (%s): curl_easy_perform() failed: %s (%s)",
		                          url.c_str(),
		                          curl_easy_strerror(res),
		                          curl_error);
		curl_easy_cleanup(curl);
		return;
	}

	long http_code = 0;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	curl_easy_cleanup(curl);

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
	                          "ecs (%s): http_code=%ld",
	                          url.c_str(),
	                          http_code);
	if(http_code != 200) {
		return;
	}

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
	                          "ecs (%s): json=%s",
	                          url.c_str(),
	                          json.c_str());

	Json::Value root;
	Json::Reader reader;
	if(!reader.parse(json, root)) {
		libsinsp_logger()->format(sinsp_logger::SEV_ERROR,
		                          "ecs (%s): Could not parse json: %s",
		                          url.c_str(),
		                          json.c_str());
		return;
	}

	std::string cluster = root["Cluster"].asString();
	std::string task_arn = root["TaskARN"].asString();
	std::string family = root["Family"].asString();
	std::string revision = root["Revision"].asString();

	for(const auto& container : root["Containers"]) {
		const std::string container_id = container["DockerId"].asString();

		if(auto it = container_id.find("-internal"); it != std::string::npos) {
			// Fargate ECS internal "hidden" container, skip it
			continue;
		}

		sinsp_container_info container_info;
		container_info.m_type = CT_ECS;
		container_info.m_full_id = container_id;
		container_info.m_id = truncate_container_id(container_id);

		if(!container.isMember("CreatedAt") || container["CreatedAt"].asString().empty()) {
			container_info.m_created_time = static_cast<int64_t>(get_epoch_utc_seconds_now());
		} else {
			container_info.m_created_time =
			        static_cast<int64_t>(get_epoch_utc_seconds(container["CreatedAt"].asString()));
		}

		container_info.m_name = container["Name"].asString();
		container_info.m_image = container["Image"].asString();
		container_info.m_imageid = container["ImageID"].asString();

		std::string hostname, image_port;
		sinsp_utils::split_container_image(container_info.m_image,
		                                   hostname,
		                                   image_port,
		                                   container_info.m_imagerepo,
		                                   container_info.m_imagetag,
		                                   container_info.m_imagedigest,
		                                   false);

		// the exact format is not documented so assume docker compatible and cross fingers
		const auto& ports = container["Ports"];
		for(const auto& port : ports.getMemberNames()) {
			if(port.find("/tcp") == std::string::npos) {
				continue;
			}

			uint16_t container_port = atoi(port.c_str());

			const Json::Value& v = ports[port];
			if(!v.isArray()) {
				continue;
			}

			for(const auto& j : v) {
				sinsp_container_info::container_port_mapping port_mapping;

				auto ip = j["HostIp"].asString();
				std::string host_port = j["HostPort"].asString();

				if(inet_pton(AF_INET, ip.c_str(), &port_mapping.m_host_ip) == -1) {
					ASSERT(false);
					continue;
				}
				port_mapping.m_host_ip = ntohl(port_mapping.m_host_ip);

				port_mapping.m_container_port = container_port;
				port_mapping.m_host_port = atoi(host_port.c_str());
				container_info.m_port_mappings.push_back(port_mapping);
			}
		}

		const auto& labels = container["Labels"];
		for(const auto& label : labels.getMemberNames()) {
			std::string val = labels[label].asString();
			if(val.length() <= sinsp_container_info::m_container_label_max_length) {
				container_info.m_labels[label] = val;
			}
		}

		container_info.m_labels["ecs.cluster"] = cluster;
		container_info.m_labels["ecs.task_arn"] = task_arn;
		container_info.m_labels["ecs.family"] = family;
		container_info.m_labels["ecs.revision"] = revision;

		container_cache().add_container(std::make_shared<sinsp_container_info>(container_info),
		                                nullptr);
		container_cache().notify_new_container(container_info);
	}

	m_enabled = true;
}

bool libsinsp::container_engine::ecs::match(const std::string& cgroup,
                                            sinsp_container_info& container_info) {
	if(strncmp(cgroup.c_str(), "/ecs/", strlen("/ecs/")) != 0) {
		return false;
	}

	auto task_id_start = strlen("/ecs/");
	auto task_id_end = cgroup.find('/', task_id_start);
	if(task_id_end == std::string::npos) {
		return false;
	}
	std::string_view task_id{cgroup.c_str() + task_id_start, task_id_end - task_id_start};

	auto container_id_start = task_id_end + 1;
	std::string_view container_id{cgroup.c_str() + container_id_start};

	// the container id always has the form <task_id>-<container_number>
	if(strncmp(task_id.data(), container_id.data(), task_id.size()) != 0) {
		return false;
	}

	container_info.m_type = CT_ECS;
	container_info.m_full_id = container_id;
	container_info.m_id = truncate_container_id(container_id);
	return true;
}

bool libsinsp::container_engine::ecs::resolve(sinsp_threadinfo* tinfo,
                                              bool query_os_for_missing_info) {
	if(!m_enabled) {
		return false;
	}

	sinsp_container_info container_info;

	for(const auto& [subsys, cgroup] : tinfo->cgroups()) {
		if(match(cgroup, container_info)) {
			tinfo->m_container_id = container_info.m_id;
			return true;
		}
	}
	return false;
}
