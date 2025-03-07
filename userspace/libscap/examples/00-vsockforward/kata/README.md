## Building a custom kernel with eBPF support for Kata

Clone kata containers at a given release:
```
git clone --depth 1 --branch 3.14.0 https://github.com/kata-containers/kata-containers.git
```

Copy `bpf.conf` into `<DIR>/kata-containers/tools/packaging/kernel/configs/fragments/common/bpf.conf`.

Move into kernel subdirectory of kata-container repository, then setup+build+install the kernel.
This will build the kernel at the version pinned for the given kata release (kernel v6.12.13-147 as per kata v3.14.0).
```
cd <DIR>/kata-containers/tools/packaging/kernel
./build-kernel.sh setup
./build-kernel.sh build
./build-kernel.sh install
```

The results should installed in `/opt/kata/share/kata-containers/`. The `vmlinux.container` and `vmlinuz.container` are the uncompressed and compressed compiled kernels for the machine's architecture. Those should both be symlinks to specific kernel
binary files in the same directory. The compiled kernel can then be copied over into a host with kata-containers available.

Useful links:
- https://github.com/hitsz-ids/duetector/blob/main/docs/how-to/run-with-kata-containers.md
- https://gist.github.com/PiyushRaj927/5eb49595a82d9ca5313ae11e16593b71


## Running custom kernel in kata VMs

Once copied the kernel binary into the node, we must apply few changes to the kata config file at `/opt/kata/share/defaults/kata-containers/configuration-qemu.toml`.

The `enable_annotations` list should have the `kernel` value being added (e.g. `enable_annotations = ["enable_iommu", "virtio_fs_extra_args", "kernel_params", "kernel"]`). This allows loading the custom kernel on a per pod/deployment basis when in K8S through the `io.katacontainers.config.hypervisor.kernel` annotation.

We can also load the custom kernel in every VM by modifying the proper kata config line (as shown below) or by installing the custom kernel manually in the node's `/opt/kata/share/kata-containers/` by replacing the default kernel. Both these are not optimal options, as being able to opt-in/out on the custom kernel through k8s annotations makes for a better UX in case of trouble.
```
kernel = "<PATH TO YOUR CUSTOM vmlinux.container FILE>
```

Finally, in the containerd config (usually at `/etc/containerd/config.toml`) should have the `privileged_without_host_devices` flag set to true for the kata plugin. This allows running privileged containers in kata VMs without making host devices accessible. Example of the config entry:
```
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata-qemu]
runtime_type = "io.containerd.kata-qemu.v2"
runtime_path = "/opt/kata/bin/containerd-shim-kata-v2"
privileged_without_host_devices = true
pod_annotations = ["io.katacontainers.*"]
```

Essentially, loading an eBPF-enabled kernel for kata VMs requires two installation steps:
- Updating the containerd config for the `privileged_without_host_devices` flag. This needs to happen anyway when setting up the kata container shim
- Updating the kata config for accepting the `io.katacontainers.config.hypervisor.kernel`
- Copying the custom kernel into the node

As for the custom kernel, those can affordably be pre-built as the base kernel version get updated only when a new release of kata container is out (once a month).


## Running Pod examples in Kata Containers

Assuming you have your node with kata installed being part of a k8s cluster, you can play around by running some of the examples in this directory. They successfully run OSS Sysdig and Falco in a sidecar container alongside the VM of a certain workload (e.g. nginx). There's also a sample tester/stresser of the vsock communication with the client being in the VM, and the server running on the host and consuming data from multiple clients. So far, the maximum data throughput measured for vsocks is of ~2GB/s per socket, having tested this with 8 clients sending data to a single concurrent server consuming from each socket in parallel.