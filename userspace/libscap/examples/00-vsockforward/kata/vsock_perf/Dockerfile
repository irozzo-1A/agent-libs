FROM gcc:12.4.0 AS build
WORKDIR /app
COPY ./ ./
RUN make vsock_perf

FROM redhat/ubi9-minimal:9.5
WORKDIR /app
COPY --from=build /app/vsock_perf .
ENTRYPOINT ["./vsock_perf"]
