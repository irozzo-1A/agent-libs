// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include <sys/stat.h>

#include <libsinsp/container_engine/containerd.h>
#include <libsinsp/cri.h>
#include <libsinsp/grpc_channel_registry.h>
#include <libsinsp/runc.h>
#include <libsinsp/sinsp.h>

using namespace libsinsp::container_engine;
using namespace libsinsp::runc;

// Containers created via ctr use the "default" namespace (instead of the cri "k8s.io" namespace)
// which will result in the `/default` cgroup path.
// https://github.com/containerd/containerd/blob/3b15606e196e450cf817fa9f835ab5324b35a28b/pkg/namespaces/context.go#L32
constexpr const cgroup_layout CONTAINERD_CGROUP_LAYOUT[] = {{"/default/", ""}, {nullptr, nullptr}};

constexpr const std::string_view CONTAINERD_SOCKETS[] = {
        "/run/host-containerd/containerd.sock",  // bottlerocket host containers socket
};

bool containerd_async_source::is_ok() {
	return m_container_stub && m_image_stub;
}

static inline void setup_grpc_client_context(grpc::ClientContext &context) {
	auto deadline = std::chrono::system_clock::now() +
	                std::chrono::milliseconds(libsinsp::cri::cri_settings::get_cri_timeout());

	context.set_deadline(deadline);

	// The `default` namesapce is the default one of containerd
	// and the one used by host-containers in bottlerocket.
	// This is mandatory to query the containers.
	context.AddMetadata("containerd-namespace", "default");
}

containerd_async_source::containerd_async_source(const std::string &socket_path,
                                                 uint64_t max_wait_ms,
                                                 uint64_t ttl_ms,
                                                 container_cache_interface *cache):
        container_async_source(max_wait_ms, ttl_ms, cache),
        m_socket_path(socket_path) {
	grpc::ChannelArguments args;
	args.SetInt(GRPC_ARG_ENABLE_HTTP_PROXY, 0);
	std::shared_ptr<grpc::Channel> channel =
	        libsinsp::grpc_channel_registry::get_channel("unix://" + socket_path, &args);

	// Check the status of the container stub.
	{
		grpc::ClientContext context;
		setup_grpc_client_context(context);

		m_container_stub = ContainerdContainerService::Containers::NewStub(channel);

		ContainerdContainerService::ListContainersRequest req;
		ContainerdContainerService::ListContainersResponse resp;

		grpc::Status status = m_container_stub->List(&context, req, &resp);

		if(!status.ok()) {
			libsinsp_logger()->format(sinsp_logger::SEV_NOTICE,
			                          "containerd (%s): containerd runtime returned an error after "
			                          "trying to list containers: %s",
			                          socket_path.c_str(),
			                          status.error_message().c_str());
			m_container_stub.reset(nullptr);
			return;
		}
	}

	// Check the status of the image stub.
	{
		grpc::ClientContext context;
		setup_grpc_client_context(context);

		m_image_stub = ContainerdImageService::Images::NewStub(channel);

		ContainerdImageService::ListImagesRequest req;
		ContainerdImageService::ListImagesResponse resp;

		grpc::Status status = m_image_stub->List(&context, req, &resp);

		if(!status.ok()) {
			libsinsp_logger()->format(sinsp_logger::SEV_NOTICE,
			                          "containerd (%s): containerd runtime returned an error after "
			                          "trying to list images: %s",
			                          socket_path.c_str(),
			                          status.error_message().c_str());
			m_image_stub.reset(nullptr);
			return;
		}
	}
}

containerd_async_source::~containerd_async_source() {
	this->stop();
	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
	                          "containerd_async(%s): Source destructor",
	                          m_socket_path.c_str());
}

grpc::Status containerd_async_source::list_container_resp(
        const std::string &container_id,
        ContainerdContainerService::ListContainersResponse &resp) {
	ContainerdContainerService::ListContainersRequest req;

	// To match the container using a truncated containerd id
	// we need to use a match filter (~=).
	req.add_filters("id~=" + container_id);
	grpc::ClientContext context;
	context.AddMetadata("containerd-namespace", "default");
	auto deadline = std::chrono::system_clock::now() +
	                std::chrono::milliseconds(libsinsp::cri::cri_settings::get_cri_timeout());
	context.set_deadline(deadline);
	return m_container_stub->List(&context, req, &resp);
}

grpc::Status containerd_async_source::get_image_resp(
        const std::string &image_name,
        ContainerdImageService::GetImageResponse &resp) {
	ContainerdImageService::GetImageRequest req;

	req.set_name(image_name);
	grpc::ClientContext context;
	context.AddMetadata("containerd-namespace", "default");
	auto deadline = std::chrono::system_clock::now() +
	                std::chrono::milliseconds(libsinsp::cri::cri_settings::get_cri_timeout());
	context.set_deadline(deadline);
	return m_image_stub->Get(&context, req, &resp);
}

libsinsp::container_engine::containerd::containerd(container_cache_interface &cache,
                                                   size_t engine_index):
        container_engine_base(cache) {
	m_engine_index = engine_index;

	for(const auto &p : CONTAINERD_SOCKETS) {
		if(p.empty()) {
			continue;
		}

		std::string socket_path = std::string(scap_get_host_root()) + std::string(p);
		struct stat s = {};
		if(stat(socket_path.c_str(), &s) != 0 || (s.st_mode & S_IFMT) != S_IFSOCK) {
			libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			                          "containerd (%s): %s is not a sock.",
			                          socket_path.c_str(),
			                          socket_path.c_str());
			continue;
		}

		container_cache_interface *cache_interface = &container_cache();
		m_containerd_info_source =
		        std::make_unique<containerd_async_source>(socket_path, 0, 10000, cache_interface);
		if(!m_containerd_info_source->is_ok()) {
			m_containerd_info_source.reset(nullptr);
			libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			                          "containerd (%s): cannot create connection.",
			                          socket_path.c_str());
			continue;
		}
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
		                          "containerd (%s): ok",
		                          socket_path.c_str());
	}
}

bool containerd_async_source::parse(const containerd_lookup_request &request,
                                    sinsp_container_info &container) {
	if(!is_ok()) {
		return false;
	}

	auto container_id = request.container_id;

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
	                          "containerd_async (%s): Looking up info for container via socket %s",
	                          request.container_id.c_str(),
	                          m_socket_path.c_str());

	// given the truncated container id, the full container id needs to be retrivied from
	// containerd.
	ContainerdContainerService::ListContainersResponse resp;
	grpc::Status status = list_container_resp(container_id, resp);

	if(!status.ok()) {
		libsinsp_logger()->format(
		        sinsp_logger::SEV_DEBUG,
		        "containerd (%s): ListContainerResponse status error message: (%s)",
		        container.m_id.c_str(),
		        status.error_message().c_str());
		return false;
	}

	auto containers = resp.containers();

	if(containers.size() == 0) {
		libsinsp_logger()->format(
		        sinsp_logger::SEV_DEBUG,
		        "containerd_async (%s): ListContainerResponse status error message: "
		        "(container id has no match)",
		        container.m_id.c_str());
		return false;
	} else if(containers.size() > 1) {
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
		                          "containerd (%s): ListContainerResponse status error message: "
		                          "(container id has more than one match)",
		                          container.m_id.c_str());
		return false;
	}

	// Usually the image has this form: `docker.io/library/ubuntu:22.04`
	const auto &retrieved_image = containers[0].image();
	auto image_name_index = retrieved_image.rfind('/');
	auto tag_index = retrieved_image.rfind(':');

	container.m_id = container_id;
	container.m_name = container.m_id;
	container.m_full_id = containers[0].id();
	// We assume that the last `/`-separated field is the image
	container.m_image = retrieved_image.substr(image_name_index + 1);
	// and the first part is the repo
	container.m_imagerepo = retrieved_image.substr(0, image_name_index);
	container.m_imagetag = retrieved_image.substr(tag_index + 1);
	container.m_type = CT_CONTAINERD;

	// Retrieve the image digest.
	ContainerdImageService::GetImageResponse img_resp;
	status = get_image_resp(containers[0].image(), img_resp);

	if(!status.ok()) {
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
		                          "containerd (%s): GetImageResponse status error message: (%s)",
		                          container.m_id.c_str(),
		                          status.error_message().c_str());

		// Don't exit given that we have part of the needed information.
	}

	container.m_imagedigest = img_resp.image().target().digest();

	// Retrieve the labels.
	for(const auto &pair : containers[0].labels()) {
		if(pair.second.length() <= sinsp_container_info::m_container_label_max_length) {
			container.m_labels[pair.first] = pair.second;
		}
	}

	// The spec field keeps the information about the mounts.
	Json::Value spec;
	Json::Reader reader;
	// The spec field of the response is just a raw json.
	reader.parse(containers[0].spec().value(), spec);

	// Retrieve the mounts.
	for(const auto &m : spec["mounts"]) {
		bool readonly = false;
		std::string mode;
		for(const auto &jopt : m["options"]) {
			std::string opt = jopt.asString();
			if(opt == "ro") {
				readonly = true;
			} else if(opt.rfind("mode=") == 0) {
				mode = opt.substr(5);
			}
		}
		container.m_mounts.emplace_back(m["source"].asString(),
		                                m["destination"].asString(),
		                                mode,
		                                !readonly,
		                                spec["linux"]["rootfsPropagation"].asString());
	}

	// Retrieve the env.
	for(const auto &env : spec["process"]["env"]) {
		container.m_env.emplace_back(env.asString());
	}

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
	                          "containerd_async (%s): parse returning true",
	                          request.container_id.c_str());

	return true;
}

void libsinsp::container_engine::containerd::parse_containerd(
        const containerd_lookup_request &request,
        container_cache_interface *cache) {
	sinsp_container_info result;

	bool done;
	if(cache->async_allowed()) {
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
		                          "containerd_async (%s): Starting asynchronous lookup",
		                          request.container_id.c_str());
		done = m_containerd_info_source && m_containerd_info_source->lookup(request, result);
	} else {
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
		                          "containerd_sync (%s): Starting synchronous lookup",
		                          request.container_id.c_str());

		done = m_containerd_info_source && m_containerd_info_source->lookup_sync(request, result);
	}
	if(done) {
		// if a previous lookup call already found the metadata, process it now
		m_containerd_info_source->source_callback(request, result);

		if(cache->async_allowed()) {
			// This should *never* happen, in async mode as ttl is 0 (never wait)
			libsinsp_logger()->format(sinsp_logger::SEV_ERROR,
			                          "containerd_async (%s): Unexpected immediate return from "
			                          "containerd_info_source.lookup()",
			                          request.container_id.c_str());
		}
	}
}

bool libsinsp::container_engine::containerd::resolve(sinsp_threadinfo *tinfo,
                                                     bool query_os_for_missing_info) {
	container_cache_interface *cache = &container_cache();
	std::string container_id, cgroup;

	if(!matches_runc_cgroups(tinfo, CONTAINERD_CGROUP_LAYOUT, container_id, cgroup)) {
		return false;
	}

	tinfo->m_container_id = container_id;

	containerd_lookup_request request(container_id, CT_CONTAINERD, m_engine_index);

	// Try to check if the container id was already encountered.
	// If yes, the lookup is skipped.
	if(!cache->should_lookup(request.container_id, request.container_type, m_engine_index)) {
		return true;
	}

	auto container = sinsp_container_info();
	container.m_type = CT_CONTAINERD;
	container.m_id = request.container_id;

	// note: query_os_for_missing_info is set to 'true' by default
	if(query_os_for_missing_info) {
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
		                          "containerd (%s): Performing lookup on %d",
		                          container_id.c_str(),
		                          m_engine_index);

		// Getting limits
		libsinsp::cgroup_limits::cgroup_limits_key key(container.m_id,
		                                               tinfo->get_cgroup("cpu"),
		                                               tinfo->get_cgroup("memory"),
		                                               tinfo->get_cgroup("cpuset"));

		libsinsp::cgroup_limits::cgroup_limits_value limits;
		libsinsp::cgroup_limits::get_cgroup_resource_limits(key, limits);

		container.m_memory_limit = limits.m_memory_limit;
		container.m_cpu_shares = limits.m_cpu_shares;
		container.m_cpu_quota = limits.m_cpu_quota;
		container.m_cpu_period = limits.m_cpu_period;
		container.m_cpuset_cpu_count = limits.m_cpuset_cpu_count;

		cache->set_lookup_status(request.container_id,
		                         request.container_type,
		                         sinsp_container_lookup::state::STARTED,
		                         m_engine_index);
		parse_containerd(request, cache);

	} else {
		cache->notify_new_container(container, tinfo);
	}
	// note: with more than one container runtime we cannot be sure if a resolution is enough
	// and we have to query all the runtimes.
	return false;
}
