set(UDIG_SOCKET_PATH
	"/dev/shm/udig.sock"
	CACHE STRING "Path to the udig socket"
)
add_compile_definitions(UDIG_SOCKET="${UDIG_SOCKET_PATH}")

add_library(
	scap_engine_udig
	udig-alloc.c
	udig-consumer-open.c
	udig-next.c
	udig-open.c
	udig-settings.c
	udig-stats.c
	udig-vtable.c
)

set_property(TARGET scap_engine_udig PROPERTY C_STANDARD 99)
add_dependencies(scap_engine_udig uthash)
target_include_directories(
	scap_engine_udig PRIVATE ${UTHASH_INCLUDE} ${LIBS_DIR} ${LIBS_DIR}/userspace/
)
target_link_libraries(scap_engine_udig scap_engine_util pthread rt)
