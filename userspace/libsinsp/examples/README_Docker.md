# Sinsp Example Docker Image

This directory contains a Dockerfile to build a containerized version of the `sinsp-example` application based on UBI 9 (Red Hat Universal Base Image).

## Prerequisites

- Docker installed on your system
- Access to the Red Hat registry (for UBI 9 base image)

## Building the Image

To build the Docker image, run the following command from the project root directory:

```bash
docker build -f userspace/libsinsp/examples/Dockerfile -t sinsp-example:latest .
```

## Running the Container

### Basic Usage

```bash
docker run --rm -it --privileged sinsp-example:latest
```

### With Host Mount (for system monitoring)

```bash
docker run --rm -it --privileged \
  -v /:/host:ro \
  -v /sys:/sys:ro \
  -v /proc:/proc:ro \
  sinsp-example:latest -j -a
```

### With Custom Configuration

```bash
docker run --rm -it --privileged \
  -v /:/host:ro \
  sinsp-example:latest -j -a -f "evt.type=execve"
```

## Command Line Options

The `sinsp-example` supports various command line options:

- `-j`: Output events in JSON format
- `-a`: Show all threads
- `-f <filter>`: Apply event filter
- `-e <engine>`: Specify capture engine (kmod, bpf, modern_bpf, etc.)
- `-b <path>`: Path to BPF probe
- `-m <port>`: Enable Prometheus metrics on specified port

For a complete list of options, run:

```bash
docker run --rm sinsp-example:latest --help
```

## Security Considerations

- The container requires `--privileged` access to capture system events
- When mounting the host filesystem, use read-only mounts (`:ro`) when possible
- Consider using security profiles and capabilities instead of full privileged mode in production

## Troubleshooting

### Permission Denied Errors

If you encounter permission errors, ensure the container is running with sufficient privileges:

```bash
docker run --rm -it --privileged --cap-add=SYS_ADMIN sinsp-example:latest
```

### Driver Loading Issues

If the kernel module or BPF probe fails to load, check:

1. Kernel version compatibility
2. Available kernel headers
3. BPF support in the kernel

### Build Issues

If the build fails, ensure:

1. All source files are present
2. Sufficient disk space for the build
3. Network access to download dependencies

## Development

To modify the Dockerfile:

1. Make your changes to the Dockerfile
2. Rebuild the image
3. Test with different configurations

## License

This Dockerfile is licensed under the Apache License 2.0, same as the main project.

