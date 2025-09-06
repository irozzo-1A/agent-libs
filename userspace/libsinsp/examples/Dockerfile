# Build stage
FROM ubuntu:noble-20250716 AS builder

# Install build dependencies
RUN apt-get update -y && \
    apt-get install -y \
        --no-install-recommends \
        curl \
        ca-certificates \
        build-essential \
        git \
        clang \
        llvm \
        pkg-config \
        autoconf \
        automake \
        libtool \
        libelf-dev \
        wget \
        libtbb-dev \
        libjq-dev \
        libjsoncpp-dev \
        protobuf-compiler \
        libgtest-dev \
        libprotobuf-dev \
        linux-headers-$(uname -r) \
        cmake \
        ninja-build \
        zip \
        unzip \
        tar \
        && \
    apt-get clean all

# Install bpftool
RUN git clone --recurse-submodules https://github.com/libbpf/bpftool.git /opt/bpftool && \
    cd /opt/bpftool/src && \
    make && \
    make install

# Install vcpkg for dependency management
RUN git clone https://github.com/Microsoft/vcpkg.git /opt/vcpkg && \
    cd /opt/vcpkg && \
    ./bootstrap-vcpkg.sh -disableMetrics

# Set vcpkg environment
ENV VCPKG_ROOT=/opt/vcpkg
ENV PATH="${VCPKG_ROOT}:${PATH}"


# Set working directory
WORKDIR /workspace

# Copy source code
COPY . .

RUN vcpkg install
# Create build directory and build
RUN cmake -B build -S . -G "Unix Makefiles" --preset sinsp-example-docker-build && \
    cmake --build build -j$(nproc)

# Runtime stage
FROM ubuntu:noble-20250716

# Set environment variables
# Copy the built binary from builder stage
COPY --from=builder /workspace/build/libsinsp/examples/sinsp-example /opt/bin/sinsp-example

# Create necessary directories
RUN mkdir -p /driver /plugins

# Set the entrypoint
ENTRYPOINT ["/opt/bin/sinsp-example"]

# Default command (can be overridden)
CMD ["-m", "-M", "8080"]