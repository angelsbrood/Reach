#ifndef C_REACH_LINUX_MSQUIC_H
#define C_REACH_LINUX_MSQUIC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct reach_msquic_listener reach_msquic_listener;
typedef struct reach_msquic_stream reach_msquic_stream;

enum {
    REACH_MSQUIC_OK = 0,
    REACH_MSQUIC_TIMEOUT = 1,
    REACH_MSQUIC_CLOSED = 2,
    REACH_MSQUIC_REFUSED = 3,
    REACH_MSQUIC_ERROR = -1,
};

enum {
    REACH_MSQUIC_MAX_CONNECTIONS = 16,
    REACH_MSQUIC_MAX_STREAMS_PER_CONNECTION = 8,
    REACH_MSQUIC_MAX_STREAMS_PROCESS = 16,
    REACH_MSQUIC_MAX_FRAME_LENGTH = 16 * 1024 * 1024,
    REACH_MSQUIC_STREAM_RECEIVE_LIMIT = REACH_MSQUIC_MAX_FRAME_LENGTH + 4,
    REACH_MSQUIC_PROCESS_RECEIVE_LIMIT = 256 * 1024 * 1024,
    REACH_MSQUIC_MAX_PEER_CERTIFICATE = 1024 * 1024,
};

enum {
    REACH_MSQUIC_RECEIVE_TEST_DEFERRED_MULTI_BUFFER = 1,
    REACH_MSQUIC_RECEIVE_TEST_LOCAL_CANCELLATION = 2,
    REACH_MSQUIC_RECEIVE_TEST_PEER_ABORT = 3,
    REACH_MSQUIC_RECEIVE_TEST_CLOSE_RACE = 4,
    REACH_MSQUIC_RECEIVE_TEST_EMPTY_FIN = 5,
    REACH_MSQUIC_RECEIVE_TEST_RETENTION_BUDGET = 6,
};

enum {
    REACH_MSQUIC_SHUTDOWN_TEST_SUCCESS = 1,
    REACH_MSQUIC_SHUTDOWN_TEST_TIMEOUT_REUSE = 2,
    REACH_MSQUIC_SHUTDOWN_TEST_DESTRUCTOR_REUSE = 3,
};

typedef struct reach_msquic_listener_configuration {
    const char *listen_address;
    uint16_t listen_port;
    const char *certificate_chain_path;
    const char *private_key_path;
    const char *cluster_ca_path;
} reach_msquic_listener_configuration;

typedef struct reach_msquic_metrics {
    uint32_t raw_connections;
    uint32_t accepted_connections;
    uint32_t active_connections;
    uint32_t refused_connections;
    uint32_t accepted_streams;
    uint32_t active_streams;
    uint32_t refused_streams;
    uint32_t peak_connections;
    uint32_t peak_streams;
    uint64_t retained_receive_bytes;
    uint64_t peak_retained_receive_bytes;
    uint32_t suspended_receive_streams;
} reach_msquic_metrics;

/**
 * Creates and starts the exact Reach QUIC-v1/TLS-1.3/mTLS listener.
 * Credential and bind failures are synchronous and leave *out_listener null.
 */
int reach_msquic_listener_start(
    const reach_msquic_listener_configuration *configuration,
    reach_msquic_listener **out_listener,
    char *error_buffer,
    size_t error_buffer_size);

/**
 * Transfers one accepted bidirectional stream reference to the caller.
 * The caller must eventually call reach_msquic_stream_release.
 */
int reach_msquic_listener_accept(
    reach_msquic_listener *listener,
    uint32_t timeout_milliseconds,
    reach_msquic_stream **out_stream);

void reach_msquic_listener_snapshot(
    reach_msquic_listener *listener,
    reach_msquic_metrics *out_metrics);

/** Returns CLOCK_MONOTONIC in nanoseconds for one process-wide deadline. */
uint64_t reach_msquic_monotonic_now_nanoseconds(void);

/** Stops admission and children against one absolute monotonic deadline. */
int reach_msquic_listener_stop_until(
    reach_msquic_listener *listener,
    uint64_t deadline_nanoseconds);

/** Reuses the first stop deadline; it never grants destruction a new wait. */
int reach_msquic_listener_destroy(reach_msquic_listener *listener);

/** Copies the authenticated portable leaf DER; returns the required byte count. */
size_t reach_msquic_stream_peer_certificate_length(reach_msquic_stream *stream);
int reach_msquic_stream_copy_peer_certificate(
    reach_msquic_stream *stream,
    uint8_t *destination,
    size_t destination_capacity);

/**
 * Copies at most destination_capacity borrowed receive bytes and atomically
 * transfers that exact byte count into Swift-owned retention before MsQuic is
 * permitted to indicate more bytes. The caller must release the transferred
 * count when the frame leaves the transport/parser handoff.
 */
int reach_msquic_stream_read(
    reach_msquic_stream *stream,
    uint8_t *destination,
    size_t destination_capacity,
    uint32_t timeout_milliseconds,
    size_t *out_length,
    int *out_fin);

int reach_msquic_stream_release_receive_bytes(
    reach_msquic_stream *stream,
    size_t length);

/** Copies bytes into one owned send context and waits for its completion. */
int reach_msquic_stream_send(
    reach_msquic_stream *stream,
    const uint8_t *bytes,
    size_t length,
    int finish,
    uint32_t timeout_milliseconds);

void reach_msquic_stream_finish(reach_msquic_stream *stream);
void reach_msquic_stream_cancel(reach_msquic_stream *stream, uint64_t error_code);
void reach_msquic_stream_release(reach_msquic_stream *stream);

/** Deterministic, network-free probe of the callback receive ownership state. */
int reach_msquic_receive_contract_test(uint32_t scenario, uint32_t iterations);

/** Deterministic proof that stop and destruction reuse one absolute deadline. */
int reach_msquic_shutdown_contract_test(uint32_t scenario);

/** Frozen ABI/runtime proof surfaced to deterministic tests and diagnostics. */
int reach_msquic_version_settings_layout(
    size_t *out_size,
    size_t *out_alignment,
    size_t out_offsets[6]);

/** Sends one bounded datagram to systemd's inherited local notify socket. */
int reach_linux_systemd_notify(const char *message);

#ifdef __cplusplus
}
#endif

#endif
