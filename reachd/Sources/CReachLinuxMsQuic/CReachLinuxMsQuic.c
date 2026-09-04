#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#define QUIC_API_ENABLE_PREVIEW_FEATURES 1
#include "CReachLinuxMsQuic.h"
#include "msquic.h"

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define REACH_ALPN_LENGTH 7U
#define REACH_STREAM_ENVELOPE_LIMIT ((uint64_t)REACH_MSQUIC_MAX_FRAME_LENGTH + 4U)
#define REACH_RECEIVE_DESCRIPTOR_LIMIT 2U
#define REACH_SEND_ERROR 0x52450001ULL
#define REACH_RECEIVE_ERROR 0x52450002ULL
#define REACH_SHUTDOWN_ERROR 0x52450003ULL

typedef struct reach_msquic_connection reach_msquic_connection;

typedef struct reach_configuration_test_witness {
    _Atomic uint64_t callback_dispatches;
    _Atomic uint64_t context_release_events;
    _Atomic uint64_t stop_latches;
    _Atomic uint64_t late_dispatch_attempts;
    _Atomic uint64_t late_dispatch_refusals;
    _Atomic uint64_t post_release_callback_accesses;
    _Atomic uint32_t released;
} reach_configuration_test_witness;

typedef struct reach_send_context {
    _Atomic uint32_t references;
    pthread_mutex_t lock;
    pthread_cond_t changed;
    int completed;
    int cancelled;
    QUIC_BUFFER buffer;
    uint8_t bytes[];
} reach_send_context;

struct reach_msquic_stream {
    _Atomic uint32_t references;
    pthread_mutex_t lock;
    pthread_cond_t changed;
    HQUIC handle;
    reach_msquic_connection *connection;
    QUIC_BUFFER receive_buffers[REACH_RECEIVE_DESCRIPTOR_LIMIT];
    uint32_t receive_buffer_count;
    uint64_t receive_total;
    uint64_t borrowed_receive_bytes;
    uint64_t owned_receive_bytes;
    uint64_t physical_borrowed_receive_bytes;
    uint64_t physical_owned_receive_bytes;
    uint8_t *receive_mapping_base;
    uint64_t receive_mapping_body_offset;
    uint64_t receive_mapping_logical_length;
    uint64_t receive_mapping_length;
    uint64_t receive_mapping_page_size;
    uint64_t receive_mapping_written_length;
    uint64_t receive_mapping_charged_length;
    QUIC_RECEIVE_FLAGS receive_flags;
    int receive_pending;
    int receive_suspended;
    int receive_suspend_transition;
    uint64_t suspend_stream_retained;
    uint64_t suspend_process_retained;
    int peer_fin;
    int peer_aborted;
    int closed;
    uint32_t active_api_calls;
    int shutdown_complete;
    int handle_closed;
};

struct reach_msquic_connection {
    _Atomic uint32_t references;
    pthread_mutex_t lock;
    reach_msquic_listener *listener;
    HQUIC handle;
    uint8_t *peer_certificate;
    size_t peer_certificate_length;
    uint32_t active_streams;
    int connected;
    int closed;
    uint32_t active_api_calls;
    int shutdown_complete;
    int handle_closed;
    uint32_t configuration_ownership;
    int shutdown_requested;
    int shutdown_issued;
    reach_configuration_test_witness *test_witness;
};

struct reach_msquic_listener {
    const QUIC_API_TABLE *api;
    HQUIC registration;
    HQUIC configuration;
    HQUIC listener;
    pthread_mutex_t lock;
    pthread_cond_t changed;
    reach_msquic_connection *connections[REACH_MSQUIC_MAX_CONNECTIONS];
    reach_msquic_stream *streams[REACH_MSQUIC_MAX_STREAMS_PROCESS];
    reach_msquic_stream *accepted[REACH_MSQUIC_MAX_STREAMS_PROCESS];
    uint32_t accepted_head;
    uint32_t accepted_count;
    reach_msquic_metrics metrics;
    void (*receive_test_before_copy)(
        reach_msquic_stream *, uint8_t *, size_t, void *);
    void *receive_test_context;
    uint64_t shutdown_deadline_nanoseconds;
    int stopping;
    int stopped;
};

static const uint8_t ReachAlpnBytes[REACH_ALPN_LENGTH] = {
    'r', 'e', 'a', 'c', 'h', '/', '0',
};
static const QUIC_BUFFER ReachAlpn = {
    REACH_ALPN_LENGTH,
    (uint8_t *)ReachAlpnBytes,
};

static void
SaturatingIncrement32(uint32_t *value)
{
    if (*value != UINT32_MAX) {
        *value += 1;
    }
}

static void
SetError(char *buffer, size_t capacity, const char *operation, QUIC_STATUS status)
{
    if (buffer == NULL || capacity == 0) {
        return;
    }
    (void)snprintf(buffer, capacity, "%s failed (0x%x)", operation, (unsigned)status);
}

uint64_t
reach_msquic_monotonic_now_nanoseconds(void)
{
    struct timespec now = {0};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}

static struct timespec
DeadlineFromNanoseconds(uint64_t nanoseconds)
{
    struct timespec deadline = {
        .tv_sec = (time_t)(nanoseconds / 1000000000ULL),
        .tv_nsec = (long)(nanoseconds % 1000000000ULL),
    };
    return deadline;
}

static struct timespec
DeadlineAfter(uint32_t milliseconds)
{
    uint64_t now = reach_msquic_monotonic_now_nanoseconds();
    uint64_t interval = (uint64_t)milliseconds * 1000000ULL;
    uint64_t deadline = UINT64_MAX - now < interval ? UINT64_MAX : now + interval;
    return DeadlineFromNanoseconds(deadline);
}

static int
ConditionInitialize(pthread_cond_t *condition)
{
    pthread_condattr_t attributes;
    if (pthread_condattr_init(&attributes) != 0) {
        return 0;
    }
    int result = pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC) == 0 &&
        pthread_cond_init(condition, &attributes) == 0;
    (void)pthread_condattr_destroy(&attributes);
    return result;
}

static void ConnectionRetain(reach_msquic_connection *connection)
{
    (void)atomic_fetch_add_explicit(&connection->references, 1, memory_order_relaxed);
}

static void ConnectionRelease(reach_msquic_connection *connection)
{
    if (atomic_fetch_sub_explicit(&connection->references, 1, memory_order_acq_rel) != 1) {
        return;
    }
    reach_configuration_test_witness *witness = connection->test_witness;
    if (witness != NULL) {
        (void)atomic_fetch_add_explicit(
            &witness->context_release_events,
            1,
            memory_order_relaxed);
        atomic_store_explicit(&witness->released, 1, memory_order_release);
    }
    reach_msquic_listener *listener = connection->listener;
    (void)pthread_mutex_lock(&listener->lock);
    SaturatingIncrement32(&listener->metrics.connection_context_releases);
    (void)pthread_mutex_unlock(&listener->lock);
    free(connection->peer_certificate);
    (void)pthread_mutex_destroy(&connection->lock);
    free(connection);
}

static void
CloseApplicationConnection(reach_msquic_listener *listener, HQUIC handle)
{
    listener->api->ConnectionClose(handle);
    (void)pthread_mutex_lock(&listener->lock);
    SaturatingIncrement32(&listener->metrics.application_connection_closes);
    (void)pthread_mutex_unlock(&listener->lock);
}

static HQUIC
ConnectionRequestShutdown(reach_msquic_connection *connection)
{
    HQUIC handle = NULL;
    (void)pthread_mutex_lock(&connection->lock);
    if (!connection->shutdown_requested) {
        connection->shutdown_requested = 1;
        if (connection->test_witness != NULL) {
            (void)atomic_fetch_add_explicit(
                &connection->test_witness->stop_latches,
                1,
                memory_order_relaxed);
        }
    }
    if (connection->configuration_ownership ==
            REACH_MSQUIC_CONNECTION_OWNERSHIP_APPLICATION &&
        !connection->shutdown_issued && !connection->closed &&
        !connection->handle_closed && connection->handle != NULL) {
        connection->shutdown_issued = 1;
        connection->active_api_calls += 1;
        handle = connection->handle;
    }
    (void)pthread_mutex_unlock(&connection->lock);
    return handle;
}

static void
ConnectionEndAPICall(reach_msquic_connection *connection)
{
    HQUIC close_handle = NULL;
    (void)pthread_mutex_lock(&connection->lock);
    if (connection->active_api_calls > 0) {
        connection->active_api_calls -= 1;
    }
    if (connection->configuration_ownership ==
            REACH_MSQUIC_CONNECTION_OWNERSHIP_APPLICATION &&
        connection->shutdown_complete && connection->active_api_calls == 0 &&
        !connection->handle_closed && connection->handle != NULL) {
        close_handle = connection->handle;
        connection->handle = NULL;
        connection->handle_closed = 1;
    }
    (void)pthread_mutex_unlock(&connection->lock);
    if (close_handle != NULL) {
        CloseApplicationConnection(connection->listener, close_handle);
    }
}

static void
ConnectionBeginConfiguration(reach_msquic_connection *connection)
{
    ConnectionRetain(connection);
    (void)pthread_mutex_lock(&connection->lock);
    connection->active_api_calls += 1;
    (void)pthread_mutex_unlock(&connection->lock);
}

typedef struct reach_configuration_completion {
    HQUIC shutdown_handle;
    HQUIC close_handle;
} reach_configuration_completion;

static reach_configuration_completion
ConnectionCompleteConfiguration(
    reach_msquic_connection *connection,
    uint32_t ownership)
{
    reach_configuration_completion completion = {0};
    (void)pthread_mutex_lock(&connection->lock);
    connection->configuration_ownership = ownership;
    if (connection->active_api_calls > 0) {
        connection->active_api_calls -= 1;
    }
    if (ownership == REACH_MSQUIC_CONNECTION_OWNERSHIP_MSQUIC) {
        /* Returning configuration failure transfers rejection cleanup back to
         * MsQuic.  The application must neither close nor retain this handle. */
        connection->handle = NULL;
        connection->handle_closed = 1;
    } else if (connection->shutdown_complete && connection->active_api_calls == 0 &&
        !connection->handle_closed && connection->handle != NULL) {
        completion.close_handle = connection->handle;
        connection->handle = NULL;
        connection->handle_closed = 1;
    } else if (connection->shutdown_requested && !connection->shutdown_issued &&
        !connection->closed && !connection->handle_closed && connection->handle != NULL) {
        connection->shutdown_issued = 1;
        connection->active_api_calls += 1;
        completion.shutdown_handle = connection->handle;
    }
    (void)pthread_mutex_unlock(&connection->lock);
    return completion;
}

static void
RecordLocalApplicationShutdown(reach_msquic_listener *listener)
{
    (void)pthread_mutex_lock(&listener->lock);
    listener->metrics.last_shutdown_origin =
        REACH_MSQUIC_SHUTDOWN_ORIGIN_LOCAL_APPLICATION;
    listener->metrics.last_shutdown_status = QUIC_STATUS_SUCCESS;
    listener->metrics.last_shutdown_error_code = REACH_SHUTDOWN_ERROR;
    (void)pthread_mutex_unlock(&listener->lock);
}

static void StreamRetain(reach_msquic_stream *stream)
{
    (void)atomic_fetch_add_explicit(&stream->references, 1, memory_order_relaxed);
}

static void
UpdatePhysicalPeakLocked(reach_msquic_listener *listener)
{
    if (listener->metrics.physical_receive_bytes >
        listener->metrics.peak_physical_receive_bytes) {
        listener->metrics.peak_physical_receive_bytes =
            listener->metrics.physical_receive_bytes;
    }
}

static int
IsValidReceivePageSize(uint64_t page_size)
{
    return page_size > 0 &&
        (page_size & (page_size - 1)) == 0 &&
        page_size <= REACH_MSQUIC_MAX_RECEIVE_PAGE_SIZE &&
        REACH_MSQUIC_RECEIVE_COPY_QUANTUM % page_size == 0 &&
        REACH_MSQUIC_MAX_FRAME_LENGTH % page_size == 0;
}

static int
RoundReceiveMappingLength(uint64_t logical_length, uint64_t page_size, uint64_t *result)
{
    if (result == NULL || logical_length == 0 || !IsValidReceivePageSize(page_size) ||
        logical_length > REACH_MSQUIC_MAX_FRAME_LENGTH - 1) {
        return 0;
    }
    uint64_t remainder = logical_length % page_size;
    uint64_t addition = remainder == 0 ? 0 : page_size - remainder;
    if (UINT64_MAX - logical_length < addition) {
        return 0;
    }
    *result = logical_length + addition;
    return *result <= REACH_MSQUIC_MAX_FRAME_LENGTH;
}

static void StreamRelease(reach_msquic_stream *stream)
{
    if (atomic_fetch_sub_explicit(&stream->references, 1, memory_order_acq_rel) != 1) {
        return;
    }
    if (stream->receive_mapping_base != NULL) {
        (void)munmap(stream->receive_mapping_base, stream->receive_mapping_length);
    }
    if (stream->owned_receive_bytes > 0 || stream->borrowed_receive_bytes > 0 ||
        stream->physical_owned_receive_bytes > 0 ||
        stream->physical_borrowed_receive_bytes > 0 ||
        stream->receive_mapping_length > 0) {
        reach_msquic_listener *listener = stream->connection->listener;
        uint64_t retained = stream->owned_receive_bytes + stream->borrowed_receive_bytes;
        (void)pthread_mutex_lock(&listener->lock);
        if (retained <= listener->metrics.retained_receive_bytes) {
            listener->metrics.retained_receive_bytes -= retained;
        } else {
            listener->metrics.retained_receive_bytes = 0;
        }
        if (stream->physical_owned_receive_bytes <=
            listener->metrics.physical_owned_receive_bytes) {
            listener->metrics.physical_owned_receive_bytes -=
                stream->physical_owned_receive_bytes;
        } else {
            listener->metrics.physical_owned_receive_bytes = 0;
        }
        if (stream->physical_borrowed_receive_bytes <=
            listener->metrics.physical_borrowed_receive_bytes) {
            listener->metrics.physical_borrowed_receive_bytes -=
                stream->physical_borrowed_receive_bytes;
        } else {
            listener->metrics.physical_borrowed_receive_bytes = 0;
        }
        uint64_t physical = stream->physical_owned_receive_bytes +
            stream->physical_borrowed_receive_bytes;
        if (physical <= listener->metrics.physical_receive_bytes) {
            listener->metrics.physical_receive_bytes -= physical;
        } else {
            listener->metrics.physical_receive_bytes = 0;
        }
        if (stream->receive_mapping_length <= listener->metrics.virtual_receive_bytes) {
            listener->metrics.virtual_receive_bytes -= stream->receive_mapping_length;
        } else {
            listener->metrics.virtual_receive_bytes = 0;
        }
        (void)pthread_mutex_unlock(&listener->lock);
    }
    reach_msquic_listener *listener = stream->connection->listener;
    (void)pthread_mutex_lock(&listener->lock);
    for (uint32_t index = 0; index < REACH_MSQUIC_MAX_STREAMS_PROCESS; ++index) {
        if (listener->streams[index] == stream) {
            listener->streams[index] = NULL;
            if (listener->metrics.active_streams > 0) {
                listener->metrics.active_streams -= 1;
            }
            if (stream->receive_suspended &&
                listener->metrics.suspended_receive_streams > 0) {
                listener->metrics.suspended_receive_streams -= 1;
            }
            break;
        }
    }
    (void)pthread_mutex_unlock(&listener->lock);
    ConnectionRelease(stream->connection);
    (void)pthread_cond_destroy(&stream->changed);
    (void)pthread_mutex_destroy(&stream->lock);
    free(stream);
}

static HQUIC
StreamBeginAPICall(reach_msquic_stream *stream)
{
    HQUIC handle = NULL;
    (void)pthread_mutex_lock(&stream->lock);
    if (!stream->closed && !stream->handle_closed && stream->handle != NULL) {
        stream->active_api_calls += 1;
        handle = stream->handle;
    }
    (void)pthread_mutex_unlock(&stream->lock);
    return handle;
}

static void
StreamEndAPICall(reach_msquic_stream *stream)
{
    HQUIC close_handle = NULL;
    (void)pthread_mutex_lock(&stream->lock);
    if (stream->active_api_calls > 0) {
        stream->active_api_calls -= 1;
    }
    if (stream->shutdown_complete && stream->active_api_calls == 0 &&
        !stream->handle_closed && stream->handle != NULL) {
        close_handle = stream->handle;
        stream->handle = NULL;
        stream->handle_closed = 1;
    }
    (void)pthread_cond_broadcast(&stream->changed);
    (void)pthread_mutex_unlock(&stream->lock);
    if (close_handle != NULL) {
        stream->connection->listener->api->StreamClose(close_handle);
    }
}

typedef struct reach_receive_completion {
    HQUIC handle;
    uint64_t length;
    uint64_t physical_borrowed_length;
    int reenable;
} reach_receive_completion;

/*
 * Claims the single outstanding asynchronous receive while stream->lock is
 * held.  Every path that ends the borrowed-byte lifetime uses this transition,
 * so only its winner may call StreamReceiveComplete.
 */
static reach_receive_completion
TakePendingReceiveLocked(
    reach_msquic_stream *stream,
    uint64_t completed_length,
    uint64_t transferred_length)
{
    reach_receive_completion completion = {0};
    if (!stream->receive_pending) {
        return completion;
    }
    if (!stream->handle_closed && stream->handle != NULL) {
        stream->active_api_calls += 1;
        completion.handle = stream->handle;
        completion.length = completed_length;
        completion.reenable = completed_length < stream->receive_total;
    } else {
        transferred_length = 0;
    }
    completion.physical_borrowed_length = stream->borrowed_receive_bytes;
    reach_msquic_listener *listener = stream->connection->listener;
    (void)pthread_mutex_lock(&listener->lock);
    if (listener->metrics.retained_receive_bytes >= stream->borrowed_receive_bytes) {
        listener->metrics.retained_receive_bytes -= stream->borrowed_receive_bytes;
    } else {
        listener->metrics.retained_receive_bytes = 0;
    }
    listener->metrics.retained_receive_bytes += transferred_length;
    (void)pthread_mutex_unlock(&listener->lock);
    stream->owned_receive_bytes += transferred_length;
    stream->borrowed_receive_bytes = 0;
    stream->receive_pending = 0;
    memset(stream->receive_buffers, 0, sizeof(stream->receive_buffers));
    stream->receive_buffer_count = 0;
    stream->receive_total = 0;
    stream->receive_flags = 0;
    return completion;
}

static void
FinishPendingReceive(
    reach_msquic_stream *stream,
    reach_receive_completion completion)
{
    if (completion.handle != NULL) {
        stream->connection->listener->api->StreamReceiveComplete(
            completion.handle,
            completion.length);
    }
    if (completion.physical_borrowed_length > 0) {
        reach_msquic_listener *listener = stream->connection->listener;
        (void)pthread_mutex_lock(&stream->lock);
        (void)pthread_mutex_lock(&listener->lock);
        uint64_t released = completion.physical_borrowed_length;
        if (released > stream->physical_borrowed_receive_bytes) {
            released = stream->physical_borrowed_receive_bytes;
        }
        stream->physical_borrowed_receive_bytes -= released;
        if (released <= listener->metrics.physical_borrowed_receive_bytes) {
            listener->metrics.physical_borrowed_receive_bytes -= released;
        } else {
            listener->metrics.physical_borrowed_receive_bytes = 0;
        }
        if (released <= listener->metrics.physical_receive_bytes) {
            listener->metrics.physical_receive_bytes -= released;
        } else {
            listener->metrics.physical_receive_bytes = 0;
        }
        (void)pthread_mutex_unlock(&listener->lock);
        (void)pthread_mutex_unlock(&stream->lock);
    }
    if (completion.handle != NULL && completion.reenable) {
        QUIC_STATUS status = stream->connection->listener->api->StreamReceiveSetEnabled(
            completion.handle,
            TRUE);
        if (QUIC_FAILED(status)) {
            stream->connection->listener->api->StreamShutdown(
                completion.handle,
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT,
                REACH_RECEIVE_ERROR);
        }
    }
    if (completion.handle != NULL) {
        StreamEndAPICall(stream);
    }
}

static void
CancelPendingReceive(reach_msquic_stream *stream)
{
    (void)pthread_mutex_lock(&stream->lock);
    reach_receive_completion completion = TakePendingReceiveLocked(stream, 0, 0);
    (void)pthread_cond_broadcast(&stream->changed);
    (void)pthread_mutex_unlock(&stream->lock);
    FinishPendingReceive(stream, completion);
}

static void SendRelease(reach_send_context *send)
{
    if (atomic_fetch_sub_explicit(&send->references, 1, memory_order_acq_rel) != 1) {
        return;
    }
    (void)pthread_cond_destroy(&send->changed);
    (void)pthread_mutex_destroy(&send->lock);
    free(send);
}

static reach_msquic_connection *
ConnectionCreate(reach_msquic_listener *listener, HQUIC handle)
{
    reach_msquic_connection *connection = calloc(1, sizeof(*connection));
    if (connection == NULL) {
        return NULL;
    }
    atomic_init(&connection->references, 1);
    if (pthread_mutex_init(&connection->lock, NULL) != 0) {
        free(connection);
        return NULL;
    }
    connection->listener = listener;
    connection->handle = handle;
    return connection;
}

static reach_msquic_stream *
StreamCreate(reach_msquic_connection *connection, HQUIC handle)
{
    reach_msquic_stream *stream = calloc(1, sizeof(*stream));
    if (stream == NULL) {
        return NULL;
    }
    atomic_init(&stream->references, 1);
    if (pthread_mutex_init(&stream->lock, NULL) != 0) {
        free(stream);
        return NULL;
    }
    if (!ConditionInitialize(&stream->changed)) {
        (void)pthread_mutex_destroy(&stream->lock);
        free(stream);
        return NULL;
    }
    ConnectionRetain(connection);
    stream->connection = connection;
    stream->handle = handle;
    return stream;
}

static int
QueueAcceptedStream(reach_msquic_listener *listener, reach_msquic_stream *stream)
{
    if (listener->accepted_count == REACH_MSQUIC_MAX_STREAMS_PROCESS) {
        return 0;
    }
    uint32_t tail = (listener->accepted_head + listener->accepted_count) %
        REACH_MSQUIC_MAX_STREAMS_PROCESS;
    StreamRetain(stream);
    listener->accepted[tail] = stream;
    listener->accepted_count += 1;
    (void)pthread_cond_broadcast(&listener->changed);
    return 1;
}

static int
RegisterStreamLocked(reach_msquic_listener *listener, reach_msquic_stream *stream)
{
    for (uint32_t index = 0; index < REACH_MSQUIC_MAX_STREAMS_PROCESS; ++index) {
        if (listener->streams[index] == NULL) {
            listener->streams[index] = stream;
            return 1;
        }
    }
    return 0;
}

static void
RemoveStreamLocked(reach_msquic_listener *listener, reach_msquic_stream *stream)
{
    for (uint32_t index = 0; index < REACH_MSQUIC_MAX_STREAMS_PROCESS; ++index) {
        if (listener->streams[index] == stream) {
            listener->streams[index] = NULL;
            return;
        }
    }
}

/*
 * A suspended stream owns no callback descriptor or byte span.  Re-enabling
 * merely asks MsQuic to re-indicate its still-transport-owned data, at which
 * point the receive callback repeats both ceilings before it may pend bytes.
 */
static void
ResumeSuspendedReceives(reach_msquic_listener *listener)
{
    reach_msquic_stream *streams[REACH_MSQUIC_MAX_STREAMS_PROCESS] = {0};
    (void)pthread_mutex_lock(&listener->lock);
    for (uint32_t index = 0; index < REACH_MSQUIC_MAX_STREAMS_PROCESS; ++index) {
        streams[index] = listener->streams[index];
        if (streams[index] != NULL) {
            StreamRetain(streams[index]);
        }
    }
    (void)pthread_mutex_unlock(&listener->lock);

    for (uint32_t index = 0; index < REACH_MSQUIC_MAX_STREAMS_PROCESS; ++index) {
        reach_msquic_stream *stream = streams[index];
        if (stream == NULL) {
            continue;
        }
        HQUIC handle = NULL;
        (void)pthread_mutex_lock(&stream->lock);
        (void)pthread_mutex_lock(&listener->lock);
        int has_logical_capacity =
            stream->owned_receive_bytes < REACH_MSQUIC_STREAM_RECEIVE_LIMIT &&
            listener->metrics.retained_receive_bytes < REACH_MSQUIC_PROCESS_RECEIVE_LIMIT;
        int has_physical_capacity =
            stream->physical_owned_receive_bytes + stream->physical_borrowed_receive_bytes <
                REACH_MSQUIC_STREAM_PHYSICAL_RECEIVE_LIMIT &&
            listener->metrics.physical_receive_bytes <
                REACH_MSQUIC_PROCESS_PHYSICAL_RECEIVE_LIMIT;
        if (stream->receive_suspended && !stream->receive_suspend_transition &&
            has_logical_capacity && has_physical_capacity && !stream->closed &&
            !stream->handle_closed && stream->handle != NULL) {
            stream->receive_suspended = 0;
            stream->suspend_stream_retained = 0;
            stream->suspend_process_retained = 0;
            if (listener->metrics.suspended_receive_streams > 0) {
                listener->metrics.suspended_receive_streams -= 1;
            }
            stream->active_api_calls += 1;
            handle = stream->handle;
        }
        (void)pthread_mutex_unlock(&listener->lock);
        (void)pthread_mutex_unlock(&stream->lock);
        if (handle != NULL) {
            QUIC_STATUS status = listener->api->StreamReceiveSetEnabled(handle, TRUE);
            if (QUIC_FAILED(status)) {
                listener->api->StreamShutdown(
                    handle,
                    QUIC_STREAM_SHUTDOWN_FLAG_ABORT,
                    REACH_RECEIVE_ERROR);
            }
            StreamEndAPICall(stream);
        }
        StreamRelease(stream);
    }
}

static int
RemoveConnectionLocked(reach_msquic_listener *listener, reach_msquic_connection *connection)
{
    for (uint32_t index = 0; index < REACH_MSQUIC_MAX_CONNECTIONS; ++index) {
        if (listener->connections[index] == connection) {
            listener->connections[index] = NULL;
            SaturatingIncrement32(&listener->metrics.connection_registrations_removed);
            return 1;
        }
    }
    return 0;
}

static QUIC_STATUS QUIC_API
StreamCallback(HQUIC handle, void *opaque, QUIC_STREAM_EVENT *event)
{
    reach_msquic_stream *stream = opaque;
    reach_msquic_listener *listener = stream->connection->listener;

    switch (event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE: {
        int empty_fin =
            event->RECEIVE.BufferCount == 0 &&
            event->RECEIVE.TotalBufferLength == 0 &&
            (event->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) != 0;
        if (empty_fin) {
            (void)pthread_mutex_lock(&stream->lock);
            if (stream->closed || stream->receive_pending) {
                (void)pthread_mutex_unlock(&stream->lock);
                listener->api->StreamShutdown(
                    handle,
                    QUIC_STREAM_SHUTDOWN_FLAG_ABORT,
                    REACH_RECEIVE_ERROR);
                return QUIC_STATUS_SUCCESS;
            }
            stream->peer_fin = 1;
            (void)pthread_cond_broadcast(&stream->changed);
            (void)pthread_mutex_unlock(&stream->lock);
            return QUIC_STATUS_SUCCESS;
        }

        uint64_t described_length = 0;
        int invalid_receive =
            event->RECEIVE.BufferCount == 0 ||
            event->RECEIVE.BufferCount > REACH_RECEIVE_DESCRIPTOR_LIMIT ||
            event->RECEIVE.Buffers == NULL ||
            event->RECEIVE.TotalBufferLength == 0 ||
            event->RECEIVE.TotalBufferLength > REACH_STREAM_ENVELOPE_LIMIT;
        if (!invalid_receive) {
            for (uint32_t index = 0; index < event->RECEIVE.BufferCount; ++index) {
                const QUIC_BUFFER *buffer = &event->RECEIVE.Buffers[index];
                if ((buffer->Length > 0 && buffer->Buffer == NULL) ||
                    UINT64_MAX - described_length < buffer->Length) {
                    invalid_receive = 1;
                    break;
                }
                described_length += buffer->Length;
            }
            if (!invalid_receive) {
                invalid_receive = described_length != event->RECEIVE.TotalBufferLength;
            }
        }
        if (invalid_receive) {
            listener->api->StreamShutdown(
                handle,
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT,
                REACH_RECEIVE_ERROR);
            return QUIC_STATUS_SUCCESS;
        }
        (void)pthread_mutex_lock(&stream->lock);
        if (stream->closed || stream->receive_pending) {
            (void)pthread_mutex_unlock(&stream->lock);
            listener->api->StreamShutdown(
                handle,
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT,
                REACH_RECEIVE_ERROR);
            return QUIC_STATUS_SUCCESS;
        }
        (void)pthread_mutex_lock(&listener->lock);
        uint64_t stream_retained =
            stream->borrowed_receive_bytes + stream->owned_receive_bytes;
        int stream_fits =
            stream_retained <= REACH_MSQUIC_STREAM_RECEIVE_LIMIT &&
            event->RECEIVE.TotalBufferLength <=
                REACH_MSQUIC_STREAM_RECEIVE_LIMIT - stream_retained;
        int process_fits =
            listener->metrics.retained_receive_bytes <=
                REACH_MSQUIC_PROCESS_RECEIVE_LIMIT &&
            event->RECEIVE.TotalBufferLength <=
                REACH_MSQUIC_PROCESS_RECEIVE_LIMIT -
                    listener->metrics.retained_receive_bytes;
        uint64_t stream_physical = stream->physical_owned_receive_bytes +
            stream->physical_borrowed_receive_bytes;
        int stream_physical_fits =
            stream_physical <= REACH_MSQUIC_STREAM_PHYSICAL_RECEIVE_LIMIT &&
            event->RECEIVE.TotalBufferLength <=
                REACH_MSQUIC_STREAM_PHYSICAL_RECEIVE_LIMIT - stream_physical;
        int process_physical_fits =
            listener->metrics.physical_receive_bytes <=
                REACH_MSQUIC_PROCESS_PHYSICAL_RECEIVE_LIMIT &&
            event->RECEIVE.TotalBufferLength <=
                REACH_MSQUIC_PROCESS_PHYSICAL_RECEIVE_LIMIT -
                    listener->metrics.physical_receive_bytes;
        if (!stream_fits || !process_fits ||
            !stream_physical_fits || !process_physical_fits) {
            if (!stream->receive_suspended) {
                stream->receive_suspended = 1;
                listener->metrics.suspended_receive_streams += 1;
            }
            stream->receive_suspend_transition = 1;
            stream->suspend_stream_retained = stream_retained;
            stream->suspend_process_retained = listener->metrics.retained_receive_bytes;
            stream->active_api_calls += 1;
            HQUIC suspend_handle = handle;
            (void)pthread_mutex_unlock(&listener->lock);
            event->RECEIVE.TotalBufferLength = 0;
            (void)pthread_mutex_unlock(&stream->lock);
            QUIC_STATUS suspend_status = listener->api->StreamReceiveSetEnabled(
                suspend_handle,
                FALSE);
            (void)pthread_mutex_lock(&stream->lock);
            stream->receive_suspend_transition = 0;
            (void)pthread_mutex_lock(&listener->lock);
            int capacity_was_released =
                stream->owned_receive_bytes + stream->borrowed_receive_bytes <
                    stream->suspend_stream_retained ||
                listener->metrics.retained_receive_bytes <
                    stream->suspend_process_retained;
            (void)pthread_mutex_unlock(&listener->lock);
            (void)pthread_mutex_unlock(&stream->lock);
            StreamEndAPICall(stream);
            if (QUIC_FAILED(suspend_status)) {
                listener->api->StreamShutdown(
                    handle,
                    QUIC_STREAM_SHUTDOWN_FLAG_ABORT,
                    REACH_RECEIVE_ERROR);
            } else if (capacity_was_released) {
                ResumeSuspendedReceives(listener);
            }
            return QUIC_STATUS_SUCCESS;
        }
        listener->metrics.retained_receive_bytes += event->RECEIVE.TotalBufferLength;
        if (listener->metrics.retained_receive_bytes >
            listener->metrics.peak_retained_receive_bytes) {
            listener->metrics.peak_retained_receive_bytes =
                listener->metrics.retained_receive_bytes;
        }
        listener->metrics.physical_borrowed_receive_bytes +=
            event->RECEIVE.TotalBufferLength;
        listener->metrics.physical_receive_bytes +=
            event->RECEIVE.TotalBufferLength;
        UpdatePhysicalPeakLocked(listener);
        (void)pthread_mutex_unlock(&listener->lock);
        /* MsQuic's pinned circular receive mode emits at most two descriptors.
         * Their pointed-to byte spans remain borrowed while this receive is
         * pending, but the callback-scoped descriptors themselves do not. */
        memcpy(
            stream->receive_buffers,
            event->RECEIVE.Buffers,
            event->RECEIVE.BufferCount * sizeof(QUIC_BUFFER));
        stream->receive_buffer_count = event->RECEIVE.BufferCount;
        stream->receive_total = event->RECEIVE.TotalBufferLength;
        stream->borrowed_receive_bytes = event->RECEIVE.TotalBufferLength;
        stream->physical_borrowed_receive_bytes += event->RECEIVE.TotalBufferLength;
        stream->receive_flags = event->RECEIVE.Flags;
        stream->receive_pending = 1;
        (void)pthread_cond_broadcast(&stream->changed);
        (void)pthread_mutex_unlock(&stream->lock);
        return QUIC_STATUS_PENDING;
    }
    case QUIC_STREAM_EVENT_SEND_COMPLETE: {
        reach_send_context *send = event->SEND_COMPLETE.ClientContext;
        if (send != NULL) {
            (void)pthread_mutex_lock(&send->lock);
            send->completed = 1;
            send->cancelled = event->SEND_COMPLETE.Canceled ? 1 : 0;
            (void)pthread_cond_broadcast(&send->changed);
            (void)pthread_mutex_unlock(&send->lock);
            SendRelease(send);
        }
        break;
    }
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        (void)pthread_mutex_lock(&stream->lock);
        stream->peer_fin = 1;
        (void)pthread_cond_broadcast(&stream->changed);
        (void)pthread_mutex_unlock(&stream->lock);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        CancelPendingReceive(stream);
        (void)pthread_mutex_lock(&stream->lock);
        stream->peer_aborted = 1;
        (void)pthread_cond_broadcast(&stream->changed);
        (void)pthread_mutex_unlock(&stream->lock);
        listener->api->StreamShutdown(
            handle,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND,
            event->PEER_SEND_ABORTED.ErrorCode);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {
        CancelPendingReceive(stream);
        HQUIC close_handle = NULL;
        int was_receive_suspended = 0;
        (void)pthread_mutex_lock(&stream->lock);
        stream->closed = 1;
        stream->shutdown_complete = 1;
        was_receive_suspended = stream->receive_suspended;
        stream->receive_suspended = 0;
        if (stream->active_api_calls == 0 && !stream->handle_closed &&
            stream->handle != NULL) {
            close_handle = stream->handle;
            stream->handle = NULL;
            stream->handle_closed = 1;
        }
        (void)pthread_cond_broadcast(&stream->changed);
        (void)pthread_mutex_unlock(&stream->lock);

        (void)pthread_mutex_lock(&stream->connection->lock);
        if (stream->connection->active_streams > 0) {
            stream->connection->active_streams -= 1;
        }
        (void)pthread_mutex_unlock(&stream->connection->lock);

        (void)pthread_mutex_lock(&listener->lock);
        RemoveStreamLocked(listener, stream);
        if (was_receive_suspended) {
            if (listener->metrics.suspended_receive_streams > 0) {
                listener->metrics.suspended_receive_streams -= 1;
            }
        }
        if (listener->metrics.active_streams > 0) {
            listener->metrics.active_streams -= 1;
        }
        (void)pthread_cond_broadcast(&listener->changed);
        (void)pthread_mutex_unlock(&listener->lock);

        if (close_handle != NULL) {
            listener->api->StreamClose(close_handle);
        }
        StreamRelease(stream);
        break;
    }
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

static void
CopyPeerCertificate(reach_msquic_connection *connection, const QUIC_BUFFER *certificate)
{
    if (certificate == NULL || certificate->Buffer == NULL || certificate->Length == 0 ||
        certificate->Length > REACH_MSQUIC_MAX_PEER_CERTIFICATE) {
        return;
    }
    uint8_t *copy = malloc(certificate->Length);
    if (copy == NULL) {
        return;
    }
    memcpy(copy, certificate->Buffer, certificate->Length);
    (void)pthread_mutex_lock(&connection->lock);
    if (connection->peer_certificate == NULL) {
        connection->peer_certificate = copy;
        connection->peer_certificate_length = certificate->Length;
        copy = NULL;
    }
    (void)pthread_mutex_unlock(&connection->lock);
    free(copy);
}

static QUIC_STATUS QUIC_API
ConnectionCallback(HQUIC handle, void *opaque, QUIC_CONNECTION_EVENT *event)
{
    reach_msquic_connection *connection = opaque;
    reach_msquic_listener *listener = connection->listener;

    switch (event->Type) {
    case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED: {
        const QUIC_BUFFER *certificate =
            (const QUIC_BUFFER *)event->PEER_CERTIFICATE_RECEIVED.Certificate;
        (void)pthread_mutex_lock(&listener->lock);
        SaturatingIncrement32(&listener->metrics.peer_certificate_callbacks);
        listener->metrics.last_peer_certificate_length =
            certificate == NULL ? 0 : certificate->Length;
        (void)pthread_mutex_unlock(&listener->lock);
        CopyPeerCertificate(
            connection,
            certificate);
        break;
    }
    case QUIC_CONNECTION_EVENT_CONNECTED: {
        QUIC_HANDSHAKE_INFO handshake = {0};
        uint32_t handshake_length = sizeof(handshake);
        QUIC_STATUS status = listener->api->GetParam(
            handle,
            QUIC_PARAM_TLS_HANDSHAKE_INFO,
            &handshake_length,
            &handshake);
        int alpn_matches =
            event->CONNECTED.NegotiatedAlpnLength == ReachAlpn.Length &&
            memcmp(event->CONNECTED.NegotiatedAlpn, ReachAlpn.Buffer, ReachAlpn.Length) == 0;
        (void)pthread_mutex_lock(&listener->lock);
        SaturatingIncrement32(&listener->metrics.connected_callbacks);
        listener->metrics.last_tls_query_status = (int32_t)status;
        listener->metrics.last_tls_handshake_info_length = handshake_length;
        listener->metrics.last_tls_protocol_version = handshake.TlsProtocolVersion;
        listener->metrics.last_negotiated_alpn_length =
            event->CONNECTED.NegotiatedAlpnLength;
        listener->metrics.last_negotiated_alpn_match = alpn_matches ? 1U : 0U;
        (void)pthread_mutex_unlock(&listener->lock);
        if (QUIC_FAILED(status) || handshake_length != sizeof(handshake) ||
            handshake.TlsProtocolVersion != QUIC_TLS_PROTOCOL_1_3 ||
            !alpn_matches) {
            (void)pthread_mutex_lock(&listener->lock);
            listener->metrics.last_shutdown_origin =
                REACH_MSQUIC_SHUTDOWN_ORIGIN_LOCAL_APPLICATION;
            listener->metrics.last_shutdown_status = (int32_t)status;
            listener->metrics.last_shutdown_error_code = REACH_SHUTDOWN_ERROR;
            (void)pthread_mutex_unlock(&listener->lock);
            listener->api->ConnectionShutdown(
                handle,
                QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                REACH_SHUTDOWN_ERROR);
            break;
        }
        (void)pthread_mutex_lock(&connection->lock);
        connection->connected = 1;
        (void)pthread_mutex_unlock(&connection->lock);
        (void)pthread_mutex_lock(&listener->lock);
        listener->metrics.accepted_connections += 1;
        (void)pthread_mutex_unlock(&listener->lock);
        break;
    }
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        (void)pthread_mutex_lock(&listener->lock);
        listener->metrics.last_shutdown_origin = REACH_MSQUIC_SHUTDOWN_ORIGIN_TRANSPORT;
        listener->metrics.last_shutdown_status =
            (int32_t)event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status;
        listener->metrics.last_shutdown_error_code =
            event->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode;
        (void)pthread_mutex_unlock(&listener->lock);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        (void)pthread_mutex_lock(&listener->lock);
        listener->metrics.last_shutdown_origin = REACH_MSQUIC_SHUTDOWN_ORIGIN_PEER;
        listener->metrics.last_shutdown_status = 0;
        listener->metrics.last_shutdown_error_code =
            event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode;
        (void)pthread_mutex_unlock(&listener->lock);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
        (void)pthread_mutex_lock(&listener->lock);
        SaturatingIncrement32(&listener->metrics.peer_stream_callbacks);
        (void)pthread_mutex_unlock(&listener->lock);
        int permitted = 0;
        (void)pthread_mutex_lock(&connection->lock);
        /* Network.framework can acknowledge CONNECTED before MsQuic delivers
         * the indicated portable peer certificate.  Built-in validation and
         * required client authentication have already guarded CONNECTED;
         * require the copied DER at the first application stream instead of
         * depending on callback order. */
        int has_certificate = connection->peer_certificate != NULL;
        if (connection->connected && !connection->closed &&
            has_certificate &&
            connection->active_streams < REACH_MSQUIC_MAX_STREAMS_PER_CONNECTION &&
            (event->PEER_STREAM_STARTED.Flags & QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL) == 0) {
            (void)pthread_mutex_lock(&listener->lock);
            if (!listener->stopping &&
                listener->metrics.active_streams < REACH_MSQUIC_MAX_STREAMS_PROCESS) {
                connection->active_streams += 1;
                listener->metrics.active_streams += 1;
                listener->metrics.accepted_streams += 1;
                if (listener->metrics.active_streams > listener->metrics.peak_streams) {
                    listener->metrics.peak_streams = listener->metrics.active_streams;
                }
                permitted = 1;
            } else {
                listener->metrics.refused_streams += 1;
            }
            (void)pthread_mutex_unlock(&listener->lock);
        } else {
            (void)pthread_mutex_lock(&listener->lock);
            listener->metrics.refused_streams += 1;
            (void)pthread_mutex_unlock(&listener->lock);
        }
        (void)pthread_mutex_unlock(&connection->lock);

        if (!permitted) {
            listener->api->StreamShutdown(
                event->PEER_STREAM_STARTED.Stream,
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT,
                REACH_RECEIVE_ERROR);
            listener->api->StreamClose(event->PEER_STREAM_STARTED.Stream);
            break;
        }

        reach_msquic_stream *stream = StreamCreate(
            connection,
            event->PEER_STREAM_STARTED.Stream);
        if (stream == NULL) {
            (void)pthread_mutex_lock(&connection->lock);
            connection->active_streams -= 1;
            (void)pthread_mutex_unlock(&connection->lock);
            (void)pthread_mutex_lock(&listener->lock);
            listener->metrics.active_streams -= 1;
            listener->metrics.refused_streams += 1;
            (void)pthread_mutex_unlock(&listener->lock);
            listener->api->StreamShutdown(
                event->PEER_STREAM_STARTED.Stream,
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT,
                REACH_RECEIVE_ERROR);
            listener->api->StreamClose(event->PEER_STREAM_STARTED.Stream);
            break;
        }
        listener->api->SetCallbackHandler(
            event->PEER_STREAM_STARTED.Stream,
            (void *)StreamCallback,
            stream);
        (void)pthread_mutex_lock(&listener->lock);
        int registered = RegisterStreamLocked(listener, stream);
        int queued = registered && QueueAcceptedStream(listener, stream);
        if (!queued) {
            listener->metrics.refused_streams += 1;
        }
        (void)pthread_mutex_unlock(&listener->lock);
        if (!queued) {
            listener->api->StreamShutdown(
                event->PEER_STREAM_STARTED.Stream,
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT,
                REACH_RECEIVE_ERROR);
        }
        break;
    }
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE: {
        HQUIC close_handle = NULL;
        uint32_t ownership = REACH_MSQUIC_CONNECTION_OWNERSHIP_NONE;
        (void)pthread_mutex_lock(&connection->lock);
        connection->closed = 1;
        connection->shutdown_complete = 1;
        ownership = connection->configuration_ownership;
        if (connection->configuration_ownership ==
                REACH_MSQUIC_CONNECTION_OWNERSHIP_APPLICATION &&
            connection->active_api_calls == 0 && !connection->handle_closed &&
            connection->handle != NULL) {
            close_handle = connection->handle;
            connection->handle = NULL;
            connection->handle_closed = 1;
        }
        (void)pthread_mutex_unlock(&connection->lock);
        (void)pthread_mutex_lock(&listener->lock);
        int removed = RemoveConnectionLocked(listener, connection);
        if (removed && listener->metrics.active_connections > 0) {
            listener->metrics.active_connections -= 1;
        }
        SaturatingIncrement32(&listener->metrics.connection_shutdown_completions);
        listener->metrics.last_shutdown_handshake_completed =
            event->SHUTDOWN_COMPLETE.HandshakeCompleted ? 1U : 0U;
        if (ownership != REACH_MSQUIC_CONNECTION_OWNERSHIP_NONE) {
            listener->metrics.last_connection_ownership = ownership;
        }
        (void)pthread_cond_broadcast(&listener->changed);
        (void)pthread_mutex_unlock(&listener->lock);
        if (close_handle != NULL) {
            CloseApplicationConnection(listener, close_handle);
        }
        if (removed) {
            ConnectionRelease(connection);
        }
        break;
    }
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS QUIC_API
ListenerCallback(HQUIC handle, void *opaque, QUIC_LISTENER_EVENT *event)
{
    (void)handle;
    reach_msquic_listener *listener = opaque;
    if (event->Type != QUIC_LISTENER_EVENT_NEW_CONNECTION) {
        return QUIC_STATUS_SUCCESS;
    }

    (void)pthread_mutex_lock(&listener->lock);
    listener->metrics.raw_connections += 1;
    if (listener->stopping ||
        listener->metrics.active_connections >= REACH_MSQUIC_MAX_CONNECTIONS) {
        listener->metrics.refused_connections += 1;
        (void)pthread_mutex_unlock(&listener->lock);
        return QUIC_STATUS_CONNECTION_REFUSED;
    }
    uint32_t slot = REACH_MSQUIC_MAX_CONNECTIONS;
    for (uint32_t index = 0; index < REACH_MSQUIC_MAX_CONNECTIONS; ++index) {
        if (listener->connections[index] == NULL) {
            slot = index;
            break;
        }
    }
    if (slot == REACH_MSQUIC_MAX_CONNECTIONS) {
        listener->metrics.refused_connections += 1;
        (void)pthread_mutex_unlock(&listener->lock);
        return QUIC_STATUS_CONNECTION_REFUSED;
    }
    reach_msquic_connection *connection = ConnectionCreate(
        listener,
        event->NEW_CONNECTION.Connection);
    if (connection == NULL) {
        listener->metrics.refused_connections += 1;
        (void)pthread_mutex_unlock(&listener->lock);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    listener->connections[slot] = connection;
    listener->metrics.active_connections += 1;
    SaturatingIncrement32(&listener->metrics.configuration_attempts);
    if (listener->metrics.active_connections > listener->metrics.peak_connections) {
        listener->metrics.peak_connections = listener->metrics.active_connections;
    }
    (void)pthread_mutex_unlock(&listener->lock);

    /* The extra reference and active-call token keep the callback context and
     * handle state valid across synchronous/reentrant callback delivery from
     * ConnectionSetConfiguration. */
    ConnectionBeginConfiguration(connection);
    listener->api->SetCallbackHandler(
        event->NEW_CONNECTION.Connection,
        (void *)ConnectionCallback,
        connection);
    QUIC_STATUS status = listener->api->ConnectionSetConfiguration(
        event->NEW_CONNECTION.Connection,
        listener->configuration);
    uint32_t ownership = QUIC_FAILED(status) ?
        REACH_MSQUIC_CONNECTION_OWNERSHIP_MSQUIC :
        REACH_MSQUIC_CONNECTION_OWNERSHIP_APPLICATION;
    reach_configuration_completion completion =
        ConnectionCompleteConfiguration(connection, ownership);

    (void)pthread_mutex_lock(&listener->lock);
    listener->metrics.last_configuration_status = (int32_t)status;
    listener->metrics.last_connection_ownership = ownership;
    if (QUIC_FAILED(status)) {
        SaturatingIncrement32(&listener->metrics.configuration_failed);
    } else {
        SaturatingIncrement32(&listener->metrics.configuration_succeeded);
    }
    (void)pthread_mutex_unlock(&listener->lock);

    if (QUIC_FAILED(status)) {
        (void)pthread_mutex_lock(&listener->lock);
        int removed = RemoveConnectionLocked(listener, connection);
        if (removed && listener->metrics.active_connections > 0) {
            listener->metrics.active_connections -= 1;
        }
        SaturatingIncrement32(&listener->metrics.refused_connections);
        (void)pthread_cond_broadcast(&listener->changed);
        (void)pthread_mutex_unlock(&listener->lock);
        if (removed) {
            ConnectionRelease(connection);
        }
    } else {
        if (completion.shutdown_handle != NULL) {
            RecordLocalApplicationShutdown(listener);
            listener->api->ConnectionShutdown(
                completion.shutdown_handle,
                QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                REACH_SHUTDOWN_ERROR);
            ConnectionEndAPICall(connection);
        }
        if (completion.close_handle != NULL) {
            CloseApplicationConnection(listener, completion.close_handle);
        }
    }
    ConnectionRelease(connection);
    return status;
}

static void
ClosePartiallyStartedListener(reach_msquic_listener *listener)
{
    if (listener->listener != NULL) {
        listener->api->ListenerClose(listener->listener);
        listener->listener = NULL;
    }
    if (listener->configuration != NULL) {
        listener->api->ConfigurationClose(listener->configuration);
        listener->configuration = NULL;
    }
    if (listener->registration != NULL) {
        listener->api->RegistrationClose(listener->registration);
        listener->registration = NULL;
    }
    if (listener->api != NULL) {
        MsQuicClose(listener->api);
        listener->api = NULL;
    }
}

int
reach_msquic_listener_start(
    const reach_msquic_listener_configuration *configuration,
    reach_msquic_listener **out_listener,
    char *error_buffer,
    size_t error_buffer_size)
{
    if (out_listener == NULL || configuration == NULL ||
        configuration->listen_address == NULL ||
        configuration->certificate_chain_path == NULL ||
        configuration->private_key_path == NULL ||
        configuration->cluster_ca_path == NULL) {
        SetError(error_buffer, error_buffer_size, "invalid listener configuration", QUIC_STATUS_INVALID_PARAMETER);
        return REACH_MSQUIC_ERROR;
    }
    *out_listener = NULL;
    reach_msquic_listener *listener = calloc(1, sizeof(*listener));
    if (listener == NULL) {
        SetError(error_buffer, error_buffer_size, "listener allocation", QUIC_STATUS_OUT_OF_MEMORY);
        return REACH_MSQUIC_ERROR;
    }
    if (pthread_mutex_init(&listener->lock, NULL) != 0) {
        free(listener);
        SetError(error_buffer, error_buffer_size, "listener allocation", QUIC_STATUS_OUT_OF_MEMORY);
        return REACH_MSQUIC_ERROR;
    }
    if (!ConditionInitialize(&listener->changed)) {
        (void)pthread_mutex_destroy(&listener->lock);
        free(listener);
        SetError(error_buffer, error_buffer_size, "listener allocation", QUIC_STATUS_OUT_OF_MEMORY);
        return REACH_MSQUIC_ERROR;
    }

    QUIC_STATUS status = MsQuicOpen2(&listener->api);
    if (QUIC_FAILED(status)) {
        SetError(error_buffer, error_buffer_size, "MsQuicOpen2", status);
        goto fail;
    }
    static const QUIC_REGISTRATION_CONFIG registration_configuration = {
        "reachd-linux",
        QUIC_EXECUTION_PROFILE_LOW_LATENCY,
    };
    status = listener->api->RegistrationOpen(
        &registration_configuration,
        &listener->registration);
    if (QUIC_FAILED(status)) {
        SetError(error_buffer, error_buffer_size, "RegistrationOpen", status);
        goto fail;
    }

    static const uint32_t version = 0x00000001U;
    QUIC_VERSION_SETTINGS versions = {
        .AcceptableVersions = &version,
        .OfferedVersions = &version,
        .FullyDeployedVersions = &version,
        .AcceptableVersionsLength = 1,
        .OfferedVersionsLength = 1,
        .FullyDeployedVersionsLength = 1,
    };
    status = listener->api->SetParam(
        NULL,
        QUIC_PARAM_GLOBAL_VERSION_SETTINGS,
        sizeof(versions),
        &versions);
    if (QUIC_FAILED(status)) {
        SetError(error_buffer, error_buffer_size, "global QUIC-v1 restriction", status);
        goto fail;
    }

    QUIC_SETTINGS settings = {0};
    settings.IdleTimeoutMs = 30000;
    settings.IsSet.IdleTimeoutMs = TRUE;
    settings.PeerBidiStreamCount = REACH_MSQUIC_MAX_STREAMS_PER_CONNECTION;
    settings.IsSet.PeerBidiStreamCount = TRUE;
    settings.PeerUnidiStreamCount = 0;
    settings.IsSet.PeerUnidiStreamCount = TRUE;
    /* MsQuic caps a single stream receive window at 16 MiB.  The four-byte
     * Reach envelope is consumed incrementally, so a frame at the wire cap
     * still progresses while the transport remains explicitly bounded. */
    settings.StreamRecvWindowBidiRemoteDefault = REACH_MSQUIC_MAX_FRAME_LENGTH;
    settings.IsSet.StreamRecvWindowBidiRemoteDefault = TRUE;
    settings.StreamRecvBufferDefault = 64U * 1024U;
    settings.IsSet.StreamRecvBufferDefault = TRUE;
    settings.MigrationEnabled = FALSE;
    settings.IsSet.MigrationEnabled = TRUE;
    settings.DatagramReceiveEnabled = FALSE;
    settings.IsSet.DatagramReceiveEnabled = TRUE;
    settings.ServerResumptionLevel = QUIC_SERVER_NO_RESUME;
    settings.IsSet.ServerResumptionLevel = TRUE;

    status = listener->api->ConfigurationOpen(
        listener->registration,
        &ReachAlpn,
        1,
        &settings,
        sizeof(settings),
        NULL,
        &listener->configuration);
    if (QUIC_FAILED(status)) {
        SetError(error_buffer, error_buffer_size, "ConfigurationOpen", status);
        goto fail;
    }

    QUIC_CERTIFICATE_FILE certificate_files = {
        .PrivateKeyFile = configuration->private_key_path,
        .CertificateFile = configuration->certificate_chain_path,
    };
    QUIC_CREDENTIAL_CONFIG credential = {0};
    credential.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    credential.CertificateFile = &certificate_files;
    credential.CaCertificateFile = configuration->cluster_ca_path;
    credential.Flags = QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION |
        QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION |
        QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED |
        QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES |
        QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE;
    status = listener->api->ConfigurationLoadCredential(listener->configuration, &credential);
    if (QUIC_FAILED(status)) {
        SetError(error_buffer, error_buffer_size, "ConfigurationLoadCredential", status);
        goto fail;
    }

    status = listener->api->ListenerOpen(
        listener->registration,
        ListenerCallback,
        listener,
        &listener->listener);
    if (QUIC_FAILED(status)) {
        SetError(error_buffer, error_buffer_size, "ListenerOpen", status);
        goto fail;
    }
    QUIC_ADDR address = {0};
    if (!QuicAddrFromString(
            configuration->listen_address,
            configuration->listen_port,
            &address)) {
        SetError(error_buffer, error_buffer_size, "numeric listen address", QUIC_STATUS_INVALID_PARAMETER);
        goto fail;
    }
    status = listener->api->ListenerStart(listener->listener, &ReachAlpn, 1, &address);
    if (QUIC_FAILED(status)) {
        SetError(error_buffer, error_buffer_size, "ListenerStart", status);
        goto fail;
    }

    *out_listener = listener;
    return REACH_MSQUIC_OK;

fail:
    ClosePartiallyStartedListener(listener);
    (void)pthread_cond_destroy(&listener->changed);
    (void)pthread_mutex_destroy(&listener->lock);
    free(listener);
    return REACH_MSQUIC_ERROR;
}

int
reach_msquic_listener_accept(
    reach_msquic_listener *listener,
    uint32_t timeout_milliseconds,
    reach_msquic_stream **out_stream)
{
    if (listener == NULL || out_stream == NULL) {
        return REACH_MSQUIC_ERROR;
    }
    *out_stream = NULL;
    struct timespec deadline = DeadlineAfter(timeout_milliseconds);
    (void)pthread_mutex_lock(&listener->lock);
    while (listener->accepted_count == 0 && !listener->stopping) {
        int result = pthread_cond_timedwait(&listener->changed, &listener->lock, &deadline);
        if (result == ETIMEDOUT) {
            (void)pthread_mutex_unlock(&listener->lock);
            return REACH_MSQUIC_TIMEOUT;
        }
        if (result != 0) {
            (void)pthread_mutex_unlock(&listener->lock);
            return REACH_MSQUIC_ERROR;
        }
    }
    if (listener->accepted_count == 0) {
        (void)pthread_mutex_unlock(&listener->lock);
        return REACH_MSQUIC_CLOSED;
    }
    reach_msquic_stream *stream = listener->accepted[listener->accepted_head];
    listener->accepted[listener->accepted_head] = NULL;
    listener->accepted_head = (listener->accepted_head + 1) % REACH_MSQUIC_MAX_STREAMS_PROCESS;
    listener->accepted_count -= 1;
    (void)pthread_mutex_unlock(&listener->lock);
    *out_stream = stream;
    return REACH_MSQUIC_OK;
}

void
reach_msquic_listener_snapshot(
    reach_msquic_listener *listener,
    reach_msquic_metrics *out_metrics)
{
    if (listener == NULL || out_metrics == NULL) {
        return;
    }
    (void)pthread_mutex_lock(&listener->lock);
    *out_metrics = listener->metrics;
    (void)pthread_mutex_unlock(&listener->lock);
}

int
reach_msquic_listener_stop_until(
    reach_msquic_listener *listener,
    uint64_t deadline_nanoseconds)
{
    if (listener == NULL || deadline_nanoseconds == 0) {
        return REACH_MSQUIC_ERROR;
    }
    reach_msquic_connection *connections[REACH_MSQUIC_MAX_CONNECTIONS] = {0};
    reach_msquic_stream *queued[REACH_MSQUIC_MAX_STREAMS_PROCESS] = {0};
    uint32_t queued_count = 0;

    (void)pthread_mutex_lock(&listener->lock);
    if (listener->shutdown_deadline_nanoseconds == 0 ||
        deadline_nanoseconds < listener->shutdown_deadline_nanoseconds) {
        listener->shutdown_deadline_nanoseconds = deadline_nanoseconds;
    }
    uint64_t effective_deadline = listener->shutdown_deadline_nanoseconds;
    if (listener->stopped) {
        (void)pthread_mutex_unlock(&listener->lock);
        return REACH_MSQUIC_OK;
    }
    listener->stopping = 1;
    for (uint32_t index = 0; index < REACH_MSQUIC_MAX_CONNECTIONS; ++index) {
        connections[index] = listener->connections[index];
        if (connections[index] != NULL) {
            ConnectionRetain(connections[index]);
        }
    }
    while (listener->accepted_count > 0) {
        queued[queued_count++] = listener->accepted[listener->accepted_head];
        listener->accepted[listener->accepted_head] = NULL;
        listener->accepted_head = (listener->accepted_head + 1) % REACH_MSQUIC_MAX_STREAMS_PROCESS;
        listener->accepted_count -= 1;
    }
    (void)pthread_cond_broadcast(&listener->changed);
    (void)pthread_mutex_unlock(&listener->lock);

    if (listener->listener != NULL) {
        listener->api->ListenerStop(listener->listener);
    }
    for (uint32_t index = 0; index < queued_count; ++index) {
        reach_msquic_stream_cancel(queued[index], REACH_SHUTDOWN_ERROR);
        StreamRelease(queued[index]);
    }
    for (uint32_t index = 0; index < REACH_MSQUIC_MAX_CONNECTIONS; ++index) {
        if (connections[index] != NULL) {
            HQUIC handle = ConnectionRequestShutdown(connections[index]);
            if (handle != NULL) {
                RecordLocalApplicationShutdown(listener);
                listener->api->ConnectionShutdown(
                    handle,
                    QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                    REACH_SHUTDOWN_ERROR);
                ConnectionEndAPICall(connections[index]);
            }
            ConnectionRelease(connections[index]);
        }
    }

    struct timespec deadline = DeadlineFromNanoseconds(effective_deadline);
    (void)pthread_mutex_lock(&listener->lock);
    while (listener->metrics.active_connections != 0 || listener->metrics.active_streams != 0) {
        int result = pthread_cond_timedwait(&listener->changed, &listener->lock, &deadline);
        if (result == ETIMEDOUT) {
            (void)pthread_mutex_unlock(&listener->lock);
            return REACH_MSQUIC_TIMEOUT;
        }
        if (result != 0) {
            (void)pthread_mutex_unlock(&listener->lock);
            return REACH_MSQUIC_ERROR;
        }
    }
    listener->stopped = 1;
    (void)pthread_mutex_unlock(&listener->lock);
    return REACH_MSQUIC_OK;
}

int
reach_msquic_listener_destroy(reach_msquic_listener *listener)
{
    if (listener == NULL) {
        return REACH_MSQUIC_ERROR;
    }
    (void)pthread_mutex_lock(&listener->lock);
    uint64_t deadline = listener->shutdown_deadline_nanoseconds;
    (void)pthread_mutex_unlock(&listener->lock);
    if (deadline == 0) {
        /* Destruction without an explicit stop may clean an already-quiescent
         * listener, but it receives no implicit waiting budget. */
        deadline = reach_msquic_monotonic_now_nanoseconds();
    }
    int stop_status = reach_msquic_listener_stop_until(listener, deadline);
    if (stop_status != REACH_MSQUIC_OK) {
        // A bounded process-lifetime leak is safer than freeing callback state
        // whose termination MsQuic has not acknowledged. The service exits on
        // this path, so the kernel remains the final reclamation boundary.
        return stop_status;
    }
    ClosePartiallyStartedListener(listener);
    (void)pthread_cond_destroy(&listener->changed);
    (void)pthread_mutex_destroy(&listener->lock);
    free(listener);
    return REACH_MSQUIC_OK;
}

size_t
reach_msquic_stream_peer_certificate_length(reach_msquic_stream *stream)
{
    if (stream == NULL) {
        return 0;
    }
    (void)pthread_mutex_lock(&stream->connection->lock);
    size_t length = stream->connection->peer_certificate_length;
    (void)pthread_mutex_unlock(&stream->connection->lock);
    return length;
}

int
reach_msquic_stream_copy_peer_certificate(
    reach_msquic_stream *stream,
    uint8_t *destination,
    size_t destination_capacity)
{
    if (stream == NULL || destination == NULL) {
        return REACH_MSQUIC_ERROR;
    }
    (void)pthread_mutex_lock(&stream->connection->lock);
    size_t length = stream->connection->peer_certificate_length;
    if (length == 0 || destination_capacity < length) {
        (void)pthread_mutex_unlock(&stream->connection->lock);
        return REACH_MSQUIC_ERROR;
    }
    memcpy(destination, stream->connection->peer_certificate, length);
    (void)pthread_mutex_unlock(&stream->connection->lock);
    return REACH_MSQUIC_OK;
}

int
reach_msquic_stream_register_receive_mapping(
    reach_msquic_stream *stream,
    void *base,
    size_t body_offset,
    size_t logical_length,
    size_t mapped_length,
    size_t page_size)
{
    uint64_t expected_length = 0;
    uint64_t expected_body_offset = logical_length < page_size ?
        page_size - logical_length : 0;
    if (stream == NULL || base == NULL ||
        !RoundReceiveMappingLength(logical_length, page_size, &expected_length) ||
        expected_length != mapped_length ||
        expected_body_offset != body_offset ||
        ((uintptr_t)base % page_size) != 0) {
        return REACH_MSQUIC_ERROR;
    }
    reach_msquic_listener *listener = stream->connection->listener;
    (void)pthread_mutex_lock(&stream->lock);
    if (stream->receive_mapping_base != NULL ||
        stream->owned_receive_bytes != 0 ||
        stream->physical_owned_receive_bytes != 0 ||
        stream->closed) {
        (void)pthread_mutex_unlock(&stream->lock);
        return REACH_MSQUIC_REFUSED;
    }
    (void)pthread_mutex_lock(&listener->lock);
    if (UINT64_MAX - listener->metrics.virtual_receive_bytes < mapped_length) {
        (void)pthread_mutex_unlock(&listener->lock);
        (void)pthread_mutex_unlock(&stream->lock);
        return REACH_MSQUIC_REFUSED;
    }
    stream->receive_mapping_base = base;
    stream->receive_mapping_body_offset = body_offset;
    stream->receive_mapping_logical_length = logical_length;
    stream->receive_mapping_length = mapped_length;
    stream->receive_mapping_page_size = page_size;
    listener->metrics.virtual_receive_bytes += mapped_length;
    (void)pthread_mutex_unlock(&listener->lock);
    (void)pthread_mutex_unlock(&stream->lock);
    return REACH_MSQUIC_OK;
}

static int
PrechargeReceiveDestinationLocked(
    reach_msquic_stream *stream,
    uint8_t *destination,
    uint64_t copied)
{
    reach_msquic_listener *listener = stream->connection->listener;
    if (stream->receive_mapping_base == NULL) {
        uint64_t stream_physical = stream->physical_owned_receive_bytes +
            stream->physical_borrowed_receive_bytes;
        (void)pthread_mutex_lock(&listener->lock);
        int fits = stream_physical <= REACH_MSQUIC_STREAM_PHYSICAL_RECEIVE_LIMIT &&
            copied <= REACH_MSQUIC_STREAM_PHYSICAL_RECEIVE_LIMIT - stream_physical &&
            listener->metrics.physical_receive_bytes <=
                REACH_MSQUIC_PROCESS_PHYSICAL_RECEIVE_LIMIT &&
            copied <= REACH_MSQUIC_PROCESS_PHYSICAL_RECEIVE_LIMIT -
                listener->metrics.physical_receive_bytes;
        if (fits) {
            stream->physical_owned_receive_bytes += copied;
            listener->metrics.physical_owned_receive_bytes += copied;
            listener->metrics.physical_receive_bytes += copied;
            UpdatePhysicalPeakLocked(listener);
        }
        (void)pthread_mutex_unlock(&listener->lock);
        return fits;
    }

    uintptr_t base = (uintptr_t)stream->receive_mapping_base;
    uintptr_t address = (uintptr_t)destination;
    if (address < base ||
        address - base != stream->receive_mapping_body_offset +
            stream->receive_mapping_written_length ||
        copied == 0 || copied > REACH_MSQUIC_RECEIVE_COPY_QUANTUM ||
        copied > stream->receive_mapping_logical_length -
            stream->receive_mapping_written_length) {
        return 0;
    }
    uint64_t written = stream->receive_mapping_written_length + copied;
    uint64_t page_size = stream->receive_mapping_page_size;
    uint64_t rounded = stream->receive_mapping_body_offset + written;
    uint64_t remainder = rounded % page_size;
    if (remainder != 0) {
        rounded += page_size - remainder;
    }
    if (rounded > stream->receive_mapping_length ||
        rounded < stream->receive_mapping_charged_length) {
        return 0;
    }
    uint64_t additional = rounded - stream->receive_mapping_charged_length;
    uint64_t stream_physical = stream->physical_owned_receive_bytes +
        stream->physical_borrowed_receive_bytes;
    (void)pthread_mutex_lock(&listener->lock);
    int fits = stream_physical <= REACH_MSQUIC_STREAM_PHYSICAL_RECEIVE_LIMIT &&
        additional <= REACH_MSQUIC_STREAM_PHYSICAL_RECEIVE_LIMIT - stream_physical &&
        listener->metrics.physical_receive_bytes <=
            REACH_MSQUIC_PROCESS_PHYSICAL_RECEIVE_LIMIT &&
        additional <= REACH_MSQUIC_PROCESS_PHYSICAL_RECEIVE_LIMIT -
            listener->metrics.physical_receive_bytes;
    if (fits) {
        stream->physical_owned_receive_bytes += additional;
        stream->receive_mapping_charged_length = rounded;
        listener->metrics.physical_owned_receive_bytes += additional;
        listener->metrics.physical_receive_bytes += additional;
        UpdatePhysicalPeakLocked(listener);
    }
    (void)pthread_mutex_unlock(&listener->lock);
    return fits;
}

int
reach_msquic_stream_read(
    reach_msquic_stream *stream,
    uint8_t *destination,
    size_t destination_capacity,
    uint32_t timeout_milliseconds,
    size_t *out_length,
    int *out_fin)
{
    if (stream == NULL || destination == NULL || destination_capacity == 0 ||
        out_length == NULL || out_fin == NULL) {
        return REACH_MSQUIC_ERROR;
    }
    *out_length = 0;
    *out_fin = 0;
    struct timespec deadline = DeadlineAfter(timeout_milliseconds);
    (void)pthread_mutex_lock(&stream->lock);
    while (!stream->receive_pending && !stream->peer_fin &&
           !stream->peer_aborted && !stream->closed) {
        int result = pthread_cond_timedwait(&stream->changed, &stream->lock, &deadline);
        if (result == ETIMEDOUT) {
            (void)pthread_mutex_unlock(&stream->lock);
            return REACH_MSQUIC_TIMEOUT;
        }
        if (result != 0) {
            (void)pthread_mutex_unlock(&stream->lock);
            return REACH_MSQUIC_ERROR;
        }
    }
    if (!stream->receive_pending) {
        int clean_fin = stream->peer_fin && !stream->peer_aborted;
        (void)pthread_mutex_unlock(&stream->lock);
        *out_fin = clean_fin;
        return clean_fin ? REACH_MSQUIC_CLOSED : REACH_MSQUIC_ERROR;
    }

    if (stream->handle_closed || stream->handle == NULL) {
        (void)pthread_mutex_unlock(&stream->lock);
        return REACH_MSQUIC_ERROR;
    }
    size_t wanted = destination_capacity;
    if ((uint64_t)wanted > stream->receive_total) {
        wanted = (size_t)stream->receive_total;
    }
    if (wanted == 0 || !PrechargeReceiveDestinationLocked(stream, destination, wanted)) {
        (void)pthread_mutex_unlock(&stream->lock);
        return REACH_MSQUIC_REFUSED;
    }
    if (stream->connection->listener->receive_test_before_copy != NULL) {
        stream->connection->listener->receive_test_before_copy(
            stream,
            destination,
            wanted,
            stream->connection->listener->receive_test_context);
    }
    size_t copied = 0;
    for (uint32_t index = 0; index < stream->receive_buffer_count && copied < wanted; ++index) {
        const QUIC_BUFFER *buffer = &stream->receive_buffers[index];
        size_t amount = buffer->Length;
        if (amount > wanted - copied) {
            amount = wanted - copied;
        }
        memcpy(destination + copied, buffer->Buffer, amount);
        copied += amount;
    }
    if (copied != wanted) {
        (void)pthread_mutex_unlock(&stream->lock);
        return REACH_MSQUIC_ERROR;
    }
    if (stream->receive_mapping_base != NULL) {
        stream->receive_mapping_written_length += copied;
    }
    int receive_finished = copied == stream->receive_total;
    int final_fragment = receive_finished &&
        (stream->receive_flags & QUIC_RECEIVE_FLAG_FIN) != 0;
    if (final_fragment) {
        stream->peer_fin = 1;
    }
    /* A partial completion returns the unconsumed suffix to MsQuic for a new
     * bounded indication. This is the ownership transfer that prevents a
     * complete Swift frame allocation from coexisting with a complete
     * callback-borrowed frame. */
    reach_receive_completion completion =
        TakePendingReceiveLocked(stream, copied, copied);
    (void)pthread_mutex_unlock(&stream->lock);

    if (copied == 0 || completion.handle == NULL) {
        FinishPendingReceive(stream, completion);
        return REACH_MSQUIC_ERROR;
    }
    FinishPendingReceive(stream, completion);
    *out_length = copied;
    *out_fin = final_fragment;
    return REACH_MSQUIC_OK;
}

int
reach_msquic_stream_release_receive_bytes(
    reach_msquic_stream *stream,
    size_t length)
{
    if (stream == NULL || length == 0) {
        return length == 0 ? REACH_MSQUIC_OK : REACH_MSQUIC_ERROR;
    }
    reach_msquic_listener *listener = stream->connection->listener;
    (void)pthread_mutex_lock(&stream->lock);
    if (stream->receive_mapping_base != NULL ||
        (uint64_t)length > stream->owned_receive_bytes) {
        (void)pthread_mutex_unlock(&stream->lock);
        return REACH_MSQUIC_ERROR;
    }
    (void)pthread_mutex_lock(&listener->lock);
    if ((uint64_t)length > listener->metrics.retained_receive_bytes) {
        (void)pthread_mutex_unlock(&listener->lock);
        (void)pthread_mutex_unlock(&stream->lock);
        return REACH_MSQUIC_ERROR;
    }
    if (stream->receive_mapping_base == NULL) {
        if ((uint64_t)length > stream->physical_owned_receive_bytes ||
            (uint64_t)length > listener->metrics.physical_owned_receive_bytes ||
            (uint64_t)length > listener->metrics.physical_receive_bytes) {
            (void)pthread_mutex_unlock(&listener->lock);
            (void)pthread_mutex_unlock(&stream->lock);
            return REACH_MSQUIC_ERROR;
        }
    }
    stream->owned_receive_bytes -= (uint64_t)length;
    listener->metrics.retained_receive_bytes -= (uint64_t)length;
    if (stream->receive_mapping_base == NULL) {
        stream->physical_owned_receive_bytes -= (uint64_t)length;
        listener->metrics.physical_owned_receive_bytes -= (uint64_t)length;
        listener->metrics.physical_receive_bytes -= (uint64_t)length;
    }
    (void)pthread_mutex_unlock(&listener->lock);
    (void)pthread_mutex_unlock(&stream->lock);
    ResumeSuspendedReceives(listener);
    return REACH_MSQUIC_OK;
}

int
reach_msquic_stream_release_receive_mapping(
    reach_msquic_stream *stream,
    void *base,
    size_t body_offset,
    size_t logical_length,
    size_t mapped_length,
    size_t page_size)
{
    if (stream == NULL || base == NULL) {
        return REACH_MSQUIC_ERROR;
    }
    reach_msquic_listener *listener = stream->connection->listener;
    (void)pthread_mutex_lock(&stream->lock);
    if (stream->receive_mapping_base != base ||
        stream->receive_mapping_body_offset != body_offset ||
        stream->receive_mapping_logical_length != logical_length ||
        stream->receive_mapping_length != mapped_length ||
        stream->receive_mapping_page_size != page_size ||
        stream->receive_mapping_written_length > logical_length ||
        stream->receive_mapping_charged_length > mapped_length ||
        stream->physical_owned_receive_bytes != stream->receive_mapping_charged_length ||
        stream->owned_receive_bytes > logical_length) {
        (void)pthread_mutex_unlock(&stream->lock);
        return REACH_MSQUIC_ERROR;
    }
    uint64_t logical = stream->owned_receive_bytes;
    uint64_t physical = stream->physical_owned_receive_bytes;
    (void)pthread_mutex_lock(&listener->lock);
    if (logical > listener->metrics.retained_receive_bytes ||
        physical > listener->metrics.physical_owned_receive_bytes ||
        physical > listener->metrics.physical_receive_bytes ||
        mapped_length > listener->metrics.virtual_receive_bytes) {
        (void)pthread_mutex_unlock(&listener->lock);
        (void)pthread_mutex_unlock(&stream->lock);
        return REACH_MSQUIC_ERROR;
    }
    if (munmap(base, mapped_length) != 0) {
        (void)pthread_mutex_unlock(&listener->lock);
        (void)pthread_mutex_unlock(&stream->lock);
        return REACH_MSQUIC_ERROR;
    }
    stream->owned_receive_bytes = 0;
    stream->physical_owned_receive_bytes = 0;
    stream->receive_mapping_base = NULL;
    stream->receive_mapping_body_offset = 0;
    stream->receive_mapping_logical_length = 0;
    stream->receive_mapping_length = 0;
    stream->receive_mapping_page_size = 0;
    stream->receive_mapping_written_length = 0;
    stream->receive_mapping_charged_length = 0;
    listener->metrics.retained_receive_bytes -= logical;
    listener->metrics.physical_owned_receive_bytes -= physical;
    listener->metrics.physical_receive_bytes -= physical;
    listener->metrics.virtual_receive_bytes -= mapped_length;
    (void)pthread_mutex_unlock(&listener->lock);
    (void)pthread_mutex_unlock(&stream->lock);
    ResumeSuspendedReceives(listener);
    return REACH_MSQUIC_OK;
}

int
reach_msquic_stream_send(
    reach_msquic_stream *stream,
    const uint8_t *bytes,
    size_t length,
    int finish,
    uint32_t timeout_milliseconds)
{
    if (stream == NULL || bytes == NULL || length == 0 ||
        length > REACH_STREAM_ENVELOPE_LIMIT) {
        return REACH_MSQUIC_ERROR;
    }
    reach_send_context *send = malloc(sizeof(*send) + length);
    if (send == NULL) {
        return REACH_MSQUIC_ERROR;
    }
    atomic_init(&send->references, 2);
    if (pthread_mutex_init(&send->lock, NULL) != 0) {
        free(send);
        return REACH_MSQUIC_ERROR;
    }
    if (!ConditionInitialize(&send->changed)) {
        (void)pthread_mutex_destroy(&send->lock);
        free(send);
        return REACH_MSQUIC_ERROR;
    }
    send->completed = 0;
    send->cancelled = 0;
    memcpy(send->bytes, bytes, length);
    send->buffer.Buffer = send->bytes;
    send->buffer.Length = (uint32_t)length;

    HQUIC handle = StreamBeginAPICall(stream);
    if (handle == NULL) {
        SendRelease(send);
        SendRelease(send);
        return REACH_MSQUIC_CLOSED;
    }
    QUIC_SEND_FLAGS flags = finish ? QUIC_SEND_FLAG_FIN : QUIC_SEND_FLAG_NONE;
    QUIC_STATUS status = stream->connection->listener->api->StreamSend(
        handle,
        &send->buffer,
        1,
        flags,
        send);
    if (QUIC_FAILED(status)) {
        StreamEndAPICall(stream);
        SendRelease(send);
        SendRelease(send);
        return REACH_MSQUIC_ERROR;
    }

    struct timespec deadline = DeadlineAfter(timeout_milliseconds);
    (void)pthread_mutex_lock(&send->lock);
    while (!send->completed) {
        int result = pthread_cond_timedwait(&send->changed, &send->lock, &deadline);
        if (result == ETIMEDOUT) {
            (void)pthread_mutex_unlock(&send->lock);
            stream->connection->listener->api->StreamShutdown(
                handle,
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND,
                REACH_SEND_ERROR);
            StreamEndAPICall(stream);
            SendRelease(send);
            return REACH_MSQUIC_TIMEOUT;
        }
        if (result != 0) {
            (void)pthread_mutex_unlock(&send->lock);
            StreamEndAPICall(stream);
            SendRelease(send);
            return REACH_MSQUIC_ERROR;
        }
    }
    int cancelled = send->cancelled;
    (void)pthread_mutex_unlock(&send->lock);
    StreamEndAPICall(stream);
    SendRelease(send);
    return cancelled ? REACH_MSQUIC_CLOSED : REACH_MSQUIC_OK;
}

void
reach_msquic_stream_finish(reach_msquic_stream *stream)
{
    if (stream == NULL) {
        return;
    }
    HQUIC handle = StreamBeginAPICall(stream);
    if (handle != NULL) {
        stream->connection->listener->api->StreamShutdown(
            handle,
            QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,
            0);
        StreamEndAPICall(stream);
    }
}

void
reach_msquic_stream_cancel(reach_msquic_stream *stream, uint64_t error_code)
{
    if (stream == NULL) {
        return;
    }
    CancelPendingReceive(stream);
    HQUIC handle = StreamBeginAPICall(stream);
    if (handle != NULL) {
        stream->connection->listener->api->StreamShutdown(
            handle,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT,
            error_code);
        StreamEndAPICall(stream);
    }
}

void
reach_msquic_stream_release(reach_msquic_stream *stream)
{
    if (stream != NULL) {
        StreamRelease(stream);
    }
}

typedef struct reach_receive_test_capture {
    _Atomic uint32_t completions;
    _Atomic uint64_t completed_bytes;
    _Atomic uint32_t shutdowns;
    _Atomic uint32_t closes;
    _Atomic uint32_t receive_disables;
    _Atomic uint32_t receive_enables;
} reach_receive_test_capture;

static void QUIC_API
ReceiveTestComplete(HQUIC handle, uint64_t length)
{
    reach_receive_test_capture *capture = (reach_receive_test_capture *)handle;
    (void)atomic_fetch_add_explicit(&capture->completions, 1, memory_order_relaxed);
    (void)atomic_fetch_add_explicit(&capture->completed_bytes, length, memory_order_relaxed);
}

static QUIC_STATUS QUIC_API
ReceiveTestShutdown(
    HQUIC handle,
    QUIC_STREAM_SHUTDOWN_FLAGS flags,
    QUIC_UINT62 error_code)
{
    (void)flags;
    (void)error_code;
    reach_receive_test_capture *capture = (reach_receive_test_capture *)handle;
    (void)atomic_fetch_add_explicit(&capture->shutdowns, 1, memory_order_relaxed);
    return QUIC_STATUS_SUCCESS;
}

static void QUIC_API
ReceiveTestClose(HQUIC handle)
{
    reach_receive_test_capture *capture = (reach_receive_test_capture *)handle;
    (void)atomic_fetch_add_explicit(&capture->closes, 1, memory_order_relaxed);
}

static QUIC_STATUS QUIC_API
ReceiveTestSetEnabled(HQUIC handle, BOOLEAN enabled)
{
    reach_receive_test_capture *capture = (reach_receive_test_capture *)handle;
    if (enabled) {
        (void)atomic_fetch_add_explicit(
            &capture->receive_enables,
            1,
            memory_order_relaxed);
    } else {
        (void)atomic_fetch_add_explicit(
            &capture->receive_disables,
            1,
            memory_order_relaxed);
    }
    return QUIC_STATUS_SUCCESS;
}

static int
ReceiveTestListenerInitialize(
    reach_msquic_listener *listener,
    QUIC_API_TABLE *api)
{
    memset(listener, 0, sizeof(*listener));
    memset(api, 0, sizeof(*api));
    api->StreamReceiveComplete = ReceiveTestComplete;
    api->StreamReceiveSetEnabled = ReceiveTestSetEnabled;
    api->StreamShutdown = ReceiveTestShutdown;
    api->StreamClose = ReceiveTestClose;
    listener->api = api;
    if (pthread_mutex_init(&listener->lock, NULL) != 0) {
        return 0;
    }
    if (!ConditionInitialize(&listener->changed)) {
        (void)pthread_mutex_destroy(&listener->lock);
        return 0;
    }
    return 1;
}

static void
ReceiveTestListenerDestroy(reach_msquic_listener *listener)
{
    (void)pthread_cond_destroy(&listener->changed);
    (void)pthread_mutex_destroy(&listener->lock);
}

static reach_msquic_stream *
ReceiveTestStreamCreate(
    reach_msquic_listener *listener,
    reach_receive_test_capture *capture)
{
    reach_msquic_connection *connection = ConnectionCreate(listener, (HQUIC)capture);
    if (connection == NULL) {
        return NULL;
    }
    connection->active_streams = 1;
    reach_msquic_stream *stream = StreamCreate(connection, (HQUIC)capture);
    ConnectionRelease(connection);
    if (stream != NULL) {
        (void)pthread_mutex_lock(&listener->lock);
        if (!RegisterStreamLocked(listener, stream)) {
            (void)pthread_mutex_unlock(&listener->lock);
            StreamRelease(stream);
            return NULL;
        }
        listener->metrics.active_streams += 1;
        (void)pthread_mutex_unlock(&listener->lock);
    }
    return stream;
}

static QUIC_STATUS
ReceiveTestIndicate(
    reach_msquic_stream *stream,
    QUIC_BUFFER *buffers,
    uint32_t buffer_count,
    uint64_t total_length,
    QUIC_RECEIVE_FLAGS flags)
{
    QUIC_STREAM_EVENT event = {0};
    event.Type = QUIC_STREAM_EVENT_RECEIVE;
    event.RECEIVE.Buffers = buffers;
    event.RECEIVE.BufferCount = buffer_count;
    event.RECEIVE.TotalBufferLength = total_length;
    event.RECEIVE.Flags = flags;
    return StreamCallback(stream->handle, stream, &event);
}

static int
ReceiveTestDeferredMultiBuffer(void)
{
    QUIC_API_TABLE api;
    reach_msquic_listener listener;
    reach_receive_test_capture capture = {0};
    if (!ReceiveTestListenerInitialize(&listener, &api)) {
        return 0;
    }
    reach_msquic_stream *stream = ReceiveTestStreamCreate(&listener, &capture);
    if (stream == NULL) {
        ReceiveTestListenerDestroy(&listener);
        return 0;
    }
    uint8_t first[] = {'a', 'b'};
    uint8_t second[] = {'c', 'd', 'e'};
    uint8_t wrong[] = {'x'};
    QUIC_BUFFER descriptors[2] = {
        {sizeof(first), first},
        {sizeof(second), second},
    };
    int passed = ReceiveTestIndicate(
        stream,
        descriptors,
        2,
        sizeof(first) + sizeof(second),
        QUIC_RECEIVE_FLAG_FIN) == QUIC_STATUS_PENDING;

    /* Prove the consumer observes the copied descriptors, not this callback
     * array after its modeled lifetime ends. */
    descriptors[0].Buffer = wrong;
    descriptors[0].Length = sizeof(wrong);
    descriptors[1].Buffer = wrong;
    descriptors[1].Length = sizeof(wrong);

    uint8_t output[5] = {0};
    size_t length = 0;
    int fin = 0;
    passed = passed &&
        reach_msquic_stream_read(stream, output, 2, 10, &length, &fin) == REACH_MSQUIC_OK &&
        length == 2 && fin == 0 && memcmp(output, "ab", 2) == 0 &&
        atomic_load_explicit(&capture.completions, memory_order_relaxed) == 1 &&
        atomic_load_explicit(&capture.completed_bytes, memory_order_relaxed) == 2 &&
        atomic_load_explicit(&capture.receive_enables, memory_order_relaxed) == 1;
    QUIC_BUFFER remainder = {sizeof(second), second};
    passed = passed && ReceiveTestIndicate(
        stream,
        &remainder,
        1,
        sizeof(second),
        QUIC_RECEIVE_FLAG_FIN) == QUIC_STATUS_PENDING;
    passed = passed &&
        reach_msquic_stream_read(stream, output + 2, 3, 10, &length, &fin) == REACH_MSQUIC_OK &&
        length == 3 && fin == 1 && memcmp(output, "abcde", sizeof(output)) == 0 &&
        atomic_load_explicit(&capture.completions, memory_order_relaxed) == 2 &&
        atomic_load_explicit(&capture.completed_bytes, memory_order_relaxed) == 5 &&
        atomic_load_explicit(&capture.receive_enables, memory_order_relaxed) == 1;
    passed = passed &&
        reach_msquic_stream_release_receive_bytes(stream, sizeof(output)) == REACH_MSQUIC_OK &&
        listener.metrics.retained_receive_bytes == 0;
    reach_msquic_stream_cancel(stream, REACH_SHUTDOWN_ERROR);
    passed = passed &&
        atomic_load_explicit(&capture.completions, memory_order_relaxed) == 2;
    StreamRelease(stream);
    ReceiveTestListenerDestroy(&listener);
    return passed;
}

static int
ReceiveTestCancellationOrPeerAbort(int peer_abort)
{
    QUIC_API_TABLE api;
    reach_msquic_listener listener;
    reach_receive_test_capture capture = {0};
    if (!ReceiveTestListenerInitialize(&listener, &api)) {
        return 0;
    }
    reach_msquic_stream *stream = ReceiveTestStreamCreate(&listener, &capture);
    if (stream == NULL) {
        ReceiveTestListenerDestroy(&listener);
        return 0;
    }
    uint8_t bytes[] = {'a', 'b'};
    QUIC_BUFFER descriptor = {sizeof(bytes), bytes};
    int passed = ReceiveTestIndicate(
        stream,
        &descriptor,
        1,
        sizeof(bytes),
        QUIC_RECEIVE_FLAG_NONE) == QUIC_STATUS_PENDING;
    if (peer_abort) {
        QUIC_STREAM_EVENT event = {0};
        event.Type = QUIC_STREAM_EVENT_PEER_SEND_ABORTED;
        event.PEER_SEND_ABORTED.ErrorCode = REACH_RECEIVE_ERROR;
        (void)StreamCallback(stream->handle, stream, &event);
    } else {
        reach_msquic_stream_cancel(stream, REACH_SHUTDOWN_ERROR);
        reach_msquic_stream_cancel(stream, REACH_SHUTDOWN_ERROR);
    }
    passed = passed &&
        atomic_load_explicit(&capture.completions, memory_order_relaxed) == 1 &&
        atomic_load_explicit(&capture.completed_bytes, memory_order_relaxed) == 0 &&
        atomic_load_explicit(&capture.shutdowns, memory_order_relaxed) ==
            (peer_abort ? 1U : 2U);
    StreamRelease(stream);
    ReceiveTestListenerDestroy(&listener);
    return passed;
}

typedef struct reach_receive_test_race_context {
    reach_msquic_stream *stream;
    _Atomic int *start;
    uint8_t output[5];
    int read_status;
    size_t read_length;
    int read_fin;
} reach_receive_test_race_context;

static void *
ReceiveTestReadThread(void *opaque)
{
    reach_receive_test_race_context *context = opaque;
    while (!atomic_load_explicit(context->start, memory_order_acquire)) {
        (void)sched_yield();
    }
    context->read_status = reach_msquic_stream_read(
        context->stream,
        context->output,
        sizeof(context->output),
        10,
        &context->read_length,
        &context->read_fin);
    return NULL;
}

static void *
ReceiveTestCloseThread(void *opaque)
{
    reach_receive_test_race_context *context = opaque;
    while (!atomic_load_explicit(context->start, memory_order_acquire)) {
        (void)sched_yield();
    }
    QUIC_STREAM_EVENT event = {0};
    event.Type = QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE;
    (void)StreamCallback(context->stream->handle, context->stream, &event);
    return NULL;
}

static int
ReceiveTestCloseRace(uint32_t iterations)
{
    if (iterations == 0 || iterations > 10000) {
        return 0;
    }
    for (uint32_t iteration = 0; iteration < iterations; ++iteration) {
        QUIC_API_TABLE api;
        reach_msquic_listener listener;
        reach_receive_test_capture capture = {0};
        if (!ReceiveTestListenerInitialize(&listener, &api)) {
            return 0;
        }
        reach_msquic_stream *stream = ReceiveTestStreamCreate(&listener, &capture);
        if (stream == NULL) {
            ReceiveTestListenerDestroy(&listener);
            return 0;
        }
        uint8_t bytes[] = {'a', 'b', 'c', 'd', 'e'};
        QUIC_BUFFER descriptor = {sizeof(bytes), bytes};
        if (ReceiveTestIndicate(
                stream,
                &descriptor,
                1,
                sizeof(bytes),
                QUIC_RECEIVE_FLAG_FIN) != QUIC_STATUS_PENDING) {
            StreamRelease(stream);
            ReceiveTestListenerDestroy(&listener);
            return 0;
        }

        /* The callback owns one reference; this one keeps inspection safe if
         * SHUTDOWN_COMPLETE wins before the blocking reader. */
        StreamRetain(stream);
        _Atomic int start = 0;
        reach_receive_test_race_context context = {
            .stream = stream,
            .start = &start,
            .read_status = REACH_MSQUIC_ERROR,
        };
        pthread_t reader;
        pthread_t closer;
        int reader_created = pthread_create(&reader, NULL, ReceiveTestReadThread, &context) == 0;
        int closer_created = pthread_create(&closer, NULL, ReceiveTestCloseThread, &context) == 0;
        atomic_store_explicit(&start, 1, memory_order_release);
        if (reader_created) {
            (void)pthread_join(reader, NULL);
        }
        if (closer_created) {
            (void)pthread_join(closer, NULL);
        } else {
            QUIC_STREAM_EVENT event = {0};
            event.Type = QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE;
            (void)StreamCallback(stream->handle, stream, &event);
        }
        int read_won =
            context.read_status == REACH_MSQUIC_OK &&
            context.read_length == sizeof(bytes) &&
            context.read_fin == 1 &&
            memcmp(context.output, bytes, sizeof(bytes)) == 0;
        int close_won = context.read_status == REACH_MSQUIC_ERROR;
        int passed = reader_created && closer_created &&
            (read_won || close_won) &&
            atomic_load_explicit(&capture.completions, memory_order_relaxed) == 1 &&
            atomic_load_explicit(&capture.completed_bytes, memory_order_relaxed) ==
                (read_won ? sizeof(bytes) : 0U) &&
            atomic_load_explicit(&capture.closes, memory_order_relaxed) == 1 &&
            listener.metrics.active_streams == 0;
        StreamRelease(stream);
        ReceiveTestListenerDestroy(&listener);
        if (!passed) {
            return 0;
        }
    }
    return 1;
}

static int
ReceiveTestEmptyFin(void)
{
    QUIC_API_TABLE api;
    reach_msquic_listener listener;
    reach_receive_test_capture capture = {0};
    if (!ReceiveTestListenerInitialize(&listener, &api)) {
        return 0;
    }
    reach_msquic_stream *stream = ReceiveTestStreamCreate(&listener, &capture);
    if (stream == NULL) {
        ReceiveTestListenerDestroy(&listener);
        return 0;
    }
    int passed = ReceiveTestIndicate(
        stream,
        NULL,
        0,
        0,
        QUIC_RECEIVE_FLAG_FIN) == QUIC_STATUS_SUCCESS;
    uint8_t byte = 0;
    size_t length = 0;
    int fin = 0;
    passed = passed &&
        reach_msquic_stream_read(stream, &byte, 1, 10, &length, &fin) == REACH_MSQUIC_CLOSED &&
        length == 0 && fin == 1 &&
        atomic_load_explicit(&capture.completions, memory_order_relaxed) == 0 &&
        atomic_load_explicit(&capture.shutdowns, memory_order_relaxed) == 0;
    StreamRelease(stream);

    stream = ReceiveTestStreamCreate(&listener, &capture);
    if (stream == NULL) {
        ReceiveTestListenerDestroy(&listener);
        return 0;
    }
    passed = passed && ReceiveTestIndicate(
        stream,
        NULL,
        0,
        0,
        QUIC_RECEIVE_FLAG_NONE) == QUIC_STATUS_SUCCESS &&
        atomic_load_explicit(&capture.shutdowns, memory_order_relaxed) == 1;
    StreamRelease(stream);
    ReceiveTestListenerDestroy(&listener);
    return passed;
}

static int
ReceiveTestRetentionBudget(void)
{
    QUIC_API_TABLE api;
    reach_msquic_listener listener;
    reach_receive_test_capture captures[REACH_MSQUIC_MAX_STREAMS_PROCESS] = {0};
    reach_msquic_stream *streams[REACH_MSQUIC_MAX_STREAMS_PROCESS] = {0};
    if (!ReceiveTestListenerInitialize(&listener, &api)) {
        return 0;
    }
    int passed = 1;
    for (uint32_t index = 0; index < REACH_MSQUIC_MAX_STREAMS_PROCESS; ++index) {
        streams[index] = ReceiveTestStreamCreate(&listener, &captures[index]);
        if (streams[index] == NULL) {
            passed = 0;
            break;
        }
    }
    passed = passed &&
        listener.metrics.active_streams == REACH_MSQUIC_MAX_STREAMS_PROCESS;
    if (passed) {
        uint64_t retained = 0;
        for (uint32_t index = 0; index + 1 < REACH_MSQUIC_MAX_STREAMS_PROCESS; ++index) {
            streams[index]->owned_receive_bytes = REACH_MSQUIC_STREAM_RECEIVE_LIMIT;
            streams[index]->physical_owned_receive_bytes =
                REACH_MSQUIC_STREAM_RECEIVE_LIMIT;
            retained += REACH_MSQUIC_STREAM_RECEIVE_LIMIT;
        }
        streams[REACH_MSQUIC_MAX_STREAMS_PROCESS - 1]->owned_receive_bytes =
            REACH_MSQUIC_PROCESS_RECEIVE_LIMIT - retained - 1;
        streams[REACH_MSQUIC_MAX_STREAMS_PROCESS - 1]->physical_owned_receive_bytes =
            REACH_MSQUIC_PROCESS_RECEIVE_LIMIT - retained - 1;
        listener.metrics.retained_receive_bytes = REACH_MSQUIC_PROCESS_RECEIVE_LIMIT - 1;
        listener.metrics.peak_retained_receive_bytes = listener.metrics.retained_receive_bytes;
        listener.metrics.physical_owned_receive_bytes =
            REACH_MSQUIC_PROCESS_RECEIVE_LIMIT - 1;
        listener.metrics.physical_receive_bytes = REACH_MSQUIC_PROCESS_RECEIVE_LIMIT - 1;
        listener.metrics.peak_physical_receive_bytes =
            listener.metrics.physical_receive_bytes;

        uint8_t bytes[2] = {'a', 'b'};
        QUIC_BUFFER one = {1, bytes};
        reach_msquic_stream *last = streams[REACH_MSQUIC_MAX_STREAMS_PROCESS - 1];
        passed = ReceiveTestIndicate(
            last,
            &one,
            1,
            1,
            QUIC_RECEIVE_FLAG_NONE) == QUIC_STATUS_PENDING;
        uint8_t output[2] = {0};
        size_t length = 0;
        int fin = 0;
        passed = passed &&
            reach_msquic_stream_read(last, output, 1, 10, &length, &fin) == REACH_MSQUIC_OK &&
            length == 1 && output[0] == 'a' &&
            listener.metrics.retained_receive_bytes == REACH_MSQUIC_PROCESS_RECEIVE_LIMIT &&
            listener.metrics.peak_retained_receive_bytes == REACH_MSQUIC_PROCESS_RECEIVE_LIMIT;
        passed = passed &&
            reach_msquic_stream_release_receive_bytes(last, 1) == REACH_MSQUIC_OK;

        QUIC_BUFFER two = {2, bytes};
        passed = passed && ReceiveTestIndicate(
            last,
            &two,
            1,
            2,
            QUIC_RECEIVE_FLAG_NONE) == QUIC_STATUS_SUCCESS &&
            atomic_load_explicit(
                &captures[REACH_MSQUIC_MAX_STREAMS_PROCESS - 1].receive_disables,
                memory_order_relaxed) == 1 &&
            listener.metrics.suspended_receive_streams == 1 &&
            listener.metrics.retained_receive_bytes == REACH_MSQUIC_PROCESS_RECEIVE_LIMIT - 1;
        passed = passed &&
            reach_msquic_stream_release_receive_bytes(streams[0], 1) == REACH_MSQUIC_OK &&
            atomic_load_explicit(
                &captures[REACH_MSQUIC_MAX_STREAMS_PROCESS - 1].receive_enables,
                memory_order_relaxed) == 1 &&
            listener.metrics.suspended_receive_streams == 0;
        passed = passed && ReceiveTestIndicate(
            last,
            &two,
            1,
            2,
            QUIC_RECEIVE_FLAG_NONE) == QUIC_STATUS_PENDING &&
            reach_msquic_stream_read(last, output, 2, 10, &length, &fin) == REACH_MSQUIC_OK &&
            length == 2 && memcmp(output, bytes, 2) == 0 &&
            listener.metrics.retained_receive_bytes == REACH_MSQUIC_PROCESS_RECEIVE_LIMIT;

        for (uint32_t index = 0; index < REACH_MSQUIC_MAX_STREAMS_PROCESS; ++index) {
            uint64_t owned = streams[index]->owned_receive_bytes;
            if (owned > 0 && reach_msquic_stream_release_receive_bytes(
                    streams[index],
                    (size_t)owned) != REACH_MSQUIC_OK) {
                passed = 0;
            }
        }
        streams[0]->owned_receive_bytes = REACH_MSQUIC_STREAM_RECEIVE_LIMIT - 1;
        streams[0]->physical_owned_receive_bytes =
            REACH_MSQUIC_STREAM_RECEIVE_LIMIT - 1;
        listener.metrics.retained_receive_bytes = REACH_MSQUIC_STREAM_RECEIVE_LIMIT - 1;
        listener.metrics.physical_owned_receive_bytes =
            REACH_MSQUIC_STREAM_RECEIVE_LIMIT - 1;
        listener.metrics.physical_receive_bytes =
            REACH_MSQUIC_STREAM_RECEIVE_LIMIT - 1;
        passed = passed && ReceiveTestIndicate(
            streams[0],
            &two,
            1,
            2,
            QUIC_RECEIVE_FLAG_NONE) == QUIC_STATUS_SUCCESS &&
            listener.metrics.suspended_receive_streams == 1;
        passed = passed &&
            reach_msquic_stream_release_receive_bytes(streams[0], 1) == REACH_MSQUIC_OK &&
            listener.metrics.suspended_receive_streams == 0;
        passed = passed && ReceiveTestIndicate(
            streams[0],
            &two,
            1,
            2,
            QUIC_RECEIVE_FLAG_NONE) == QUIC_STATUS_PENDING &&
            reach_msquic_stream_read(streams[0], output, 2, 10, &length, &fin) == REACH_MSQUIC_OK &&
            streams[0]->owned_receive_bytes == REACH_MSQUIC_STREAM_RECEIVE_LIMIT &&
            reach_msquic_stream_release_receive_bytes(
                streams[0],
                REACH_MSQUIC_STREAM_RECEIVE_LIMIT) == REACH_MSQUIC_OK;
        passed = passed && listener.metrics.retained_receive_bytes == 0 &&
            listener.metrics.suspended_receive_streams == 0;
    }

    for (uint32_t index = 0; index < REACH_MSQUIC_MAX_STREAMS_PROCESS; ++index) {
        if (streams[index] != NULL) {
            StreamRelease(streams[index]);
        }
    }
    passed = passed && listener.metrics.active_streams == 0 &&
        listener.metrics.retained_receive_bytes == 0 &&
        listener.metrics.suspended_receive_streams == 0;
    ReceiveTestListenerDestroy(&listener);
    return passed;
}

typedef struct reach_mapped_receive_test_context {
    reach_msquic_listener *listener;
    size_t page_size;
    _Atomic uint32_t arrivals;
    _Atomic uint32_t release;
    uint32_t barrier_count;
    _Atomic uint32_t failures;
} reach_mapped_receive_test_context;

static int
ReceiveTestResidentPrefix(
    uint8_t *base,
    size_t mapped_length,
    size_t written_length,
    size_t page_size)
{
    size_t page_count = mapped_length / page_size;
    size_t resident_pages = (written_length + page_size - 1) / page_size;
    unsigned char *residency = calloc(page_count, 1);
    if (residency == NULL || mincore(base, mapped_length, residency) != 0) {
        free(residency);
        return 0;
    }
    int passed = 1;
    for (size_t index = 0; index < page_count; ++index) {
        int resident = (residency[index] & 1U) != 0;
        if (resident != (index < resident_pages)) {
            passed = 0;
            break;
        }
    }
    free(residency);
    return passed;
}

static void
ReceiveTestBeforeMappedCopy(
    reach_msquic_stream *stream,
    uint8_t *destination,
    size_t length,
    void *opaque)
{
    reach_mapped_receive_test_context *context = opaque;
    reach_msquic_listener *listener = context->listener;
    unsigned char resident = 0;
    uintptr_t page = (uintptr_t)destination & ~(context->page_size - 1);
    int destination_was_resident = mincore(
        (void *)page,
        context->page_size,
        &resident) == 0 && (resident & 1U) != 0;
    (void)pthread_mutex_lock(&listener->lock);
    int ledger_is_precharged =
        stream->physical_borrowed_receive_bytes > 0 &&
        stream->physical_owned_receive_bytes == stream->receive_mapping_charged_length &&
        listener->metrics.physical_owned_receive_bytes > 0 &&
        listener->metrics.physical_borrowed_receive_bytes > 0 &&
        listener->metrics.physical_receive_bytes ==
            listener->metrics.physical_owned_receive_bytes +
                listener->metrics.physical_borrowed_receive_bytes &&
        listener->metrics.physical_receive_bytes <=
            REACH_MSQUIC_PROCESS_PHYSICAL_RECEIVE_LIMIT &&
        stream->physical_owned_receive_bytes +
                stream->physical_borrowed_receive_bytes <=
            REACH_MSQUIC_STREAM_PHYSICAL_RECEIVE_LIMIT &&
        length <= REACH_MSQUIC_RECEIVE_COPY_QUANTUM;
    (void)pthread_mutex_unlock(&listener->lock);
    if (!ledger_is_precharged || destination_was_resident) {
        (void)atomic_fetch_add_explicit(&context->failures, 1, memory_order_relaxed);
    }
    uint32_t arrivals = atomic_fetch_add_explicit(
        &context->arrivals,
        1,
        memory_order_acq_rel) + 1;
    if (context->barrier_count > 0 && arrivals == context->barrier_count) {
        atomic_store_explicit(&context->release, 1, memory_order_release);
    }
    while (context->barrier_count > 0 &&
           !atomic_load_explicit(&context->release, memory_order_acquire)) {
        (void)sched_yield();
    }
}

static uint8_t *
ReceiveTestCreateMapping(size_t logical_length, size_t page_size, size_t *mapped_length)
{
    uint64_t rounded = 0;
    if (!RoundReceiveMappingLength(logical_length, page_size, &rounded)) {
        return NULL;
    }
    *mapped_length = (size_t)rounded;
    void *mapping = mmap(
        NULL,
        *mapped_length,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0);
    return mapping == MAP_FAILED ? NULL : mapping;
}

static int
ReceiveTestPopulateMapping(
    reach_msquic_stream *stream,
    uint8_t *mapping,
    size_t from,
    size_t through,
    uint8_t *source)
{
    size_t offset = from;
    while (offset < through) {
        size_t amount = through - offset;
        if (amount > REACH_MSQUIC_RECEIVE_COPY_QUANTUM) {
            amount = REACH_MSQUIC_RECEIVE_COPY_QUANTUM;
        }
        QUIC_BUFFER descriptor = {(uint32_t)amount, source};
        if (ReceiveTestIndicate(
                stream,
                &descriptor,
                1,
                amount,
                QUIC_RECEIVE_FLAG_NONE) !=
            QUIC_STATUS_PENDING) {
            return 0;
        }
        size_t copied = 0;
        int fin = 0;
        if (reach_msquic_stream_read(
                stream,
                mapping + offset,
                amount,
                10,
                &copied,
                &fin) != REACH_MSQUIC_OK || copied != amount) {
            return 0;
        }
        offset += amount;
    }
    return 1;
}

static int
ReceiveTestMappedPrecharge(void)
{
    long page_size_value = sysconf(_SC_PAGESIZE);
    if (page_size_value <= 0 || !IsValidReceivePageSize((uint64_t)page_size_value)) {
        return 0;
    }
    size_t page_size = (size_t)page_size_value;
    size_t logical_length = REACH_MSQUIC_MAX_FRAME_LENGTH - 1;
    size_t mapped_length = 0;
    uint8_t *mapping = ReceiveTestCreateMapping(
        logical_length,
        page_size,
        &mapped_length);
    if (mapping == NULL ||
        !ReceiveTestResidentPrefix(mapping, mapped_length, 0, page_size)) {
        if (mapping != NULL) (void)munmap(mapping, mapped_length);
        return 0;
    }

    QUIC_API_TABLE api;
    reach_msquic_listener listener;
    reach_receive_test_capture capture = {0};
    if (!ReceiveTestListenerInitialize(&listener, &api)) {
        (void)munmap(mapping, mapped_length);
        return 0;
    }
    reach_msquic_stream *stream = ReceiveTestStreamCreate(&listener, &capture);
    uint8_t *source = malloc(REACH_MSQUIC_RECEIVE_COPY_QUANTUM);
    int passed = stream != NULL && source != NULL;
    if (passed) {
        memset(source, 0x5a, REACH_MSQUIC_RECEIVE_COPY_QUANTUM);
        passed = reach_msquic_stream_register_receive_mapping(
            stream,
            mapping,
            0,
            logical_length,
            mapped_length,
            page_size) == REACH_MSQUIC_OK;
        passed = passed && reach_msquic_stream_register_receive_mapping(
            stream,
            mapping,
            0,
            logical_length,
            mapped_length,
            page_size) == REACH_MSQUIC_REFUSED;
    }
    reach_mapped_receive_test_context context = {
        .listener = &listener,
        .page_size = page_size,
    };
    listener.receive_test_before_copy = ReceiveTestBeforeMappedCopy;
    listener.receive_test_context = &context;
    size_t offset = 0;
    while (passed && offset < logical_length) {
        size_t amount = logical_length - offset;
        if (amount > REACH_MSQUIC_RECEIVE_COPY_QUANTUM) {
            amount = REACH_MSQUIC_RECEIVE_COPY_QUANTUM;
        }
        QUIC_BUFFER descriptor = {(uint32_t)amount, source};
        QUIC_RECEIVE_FLAGS flags = offset + amount == logical_length ?
            QUIC_RECEIVE_FLAG_FIN : QUIC_RECEIVE_FLAG_NONE;
        size_t copied = 0;
        int fin = 0;
        passed = ReceiveTestIndicate(stream, &descriptor, 1, amount, flags) ==
            QUIC_STATUS_PENDING &&
            reach_msquic_stream_read(
                stream,
                mapping + offset,
                amount,
                10,
                &copied,
                &fin) == REACH_MSQUIC_OK &&
            copied == amount &&
            fin == (offset + amount == logical_length);
        offset += amount;
        passed = passed && ReceiveTestResidentPrefix(
            mapping,
            mapped_length,
            offset,
            page_size);
    }
    passed = passed &&
        atomic_load_explicit(&context.failures, memory_order_relaxed) == 0 &&
        listener.metrics.retained_receive_bytes == logical_length &&
        listener.metrics.physical_owned_receive_bytes == mapped_length &&
        listener.metrics.physical_borrowed_receive_bytes == 0 &&
        listener.metrics.physical_receive_bytes == mapped_length &&
        listener.metrics.peak_physical_receive_bytes <=
            REACH_MSQUIC_STREAM_PHYSICAL_RECEIVE_LIMIT &&
        listener.metrics.virtual_receive_bytes == mapped_length &&
        reach_msquic_stream_release_receive_mapping(
            stream,
            mapping,
            0,
            logical_length,
            mapped_length,
            page_size + 1) == REACH_MSQUIC_ERROR &&
        reach_msquic_stream_release_receive_mapping(
            stream,
            mapping,
            0,
            logical_length,
            mapped_length,
            page_size) == REACH_MSQUIC_OK &&
        listener.metrics.retained_receive_bytes == 0 &&
        listener.metrics.physical_owned_receive_bytes == 0 &&
        listener.metrics.physical_borrowed_receive_bytes == 0 &&
        listener.metrics.physical_receive_bytes == 0 &&
        listener.metrics.virtual_receive_bytes == 0;
    free(source);
    if (stream != NULL) StreamRelease(stream);
    ReceiveTestListenerDestroy(&listener);
    return passed;
}

static int
ReceiveTestMappedTailBody(void)
{
    long page_size_value = sysconf(_SC_PAGESIZE);
    if (page_size_value <= 0 || !IsValidReceivePageSize((uint64_t)page_size_value)) {
        return 0;
    }
    size_t page_size = (size_t)page_size_value;
    size_t logical_length = 1;
    size_t body_offset = page_size - logical_length;
    size_t mapped_length = 0;
    uint8_t *mapping = ReceiveTestCreateMapping(
        logical_length,
        page_size,
        &mapped_length);
    if (mapping == NULL || mapped_length != page_size ||
        !ReceiveTestResidentPrefix(mapping, mapped_length, 0, page_size)) {
        if (mapping != NULL) (void)munmap(mapping, mapped_length);
        return 0;
    }

    QUIC_API_TABLE api;
    reach_msquic_listener listener;
    reach_receive_test_capture capture = {0};
    if (!ReceiveTestListenerInitialize(&listener, &api)) {
        (void)munmap(mapping, mapped_length);
        return 0;
    }
    reach_msquic_stream *stream = ReceiveTestStreamCreate(&listener, &capture);
    int registered = 0;
    int released = 0;
    int passed = stream != NULL;
    if (passed) {
        passed = reach_msquic_stream_register_receive_mapping(
            stream,
            mapping,
            body_offset - 1,
            logical_length,
            mapped_length,
            page_size) == REACH_MSQUIC_ERROR;
    }
    if (passed) {
        registered = reach_msquic_stream_register_receive_mapping(
            stream,
            mapping,
            body_offset,
            logical_length,
            mapped_length,
            page_size) == REACH_MSQUIC_OK;
        passed = registered;
    }

    reach_mapped_receive_test_context context = {
        .listener = &listener,
        .page_size = page_size,
    };
    listener.receive_test_before_copy = ReceiveTestBeforeMappedCopy;
    listener.receive_test_context = &context;
    uint8_t source = 0x5a;
    QUIC_BUFFER descriptor = {1, &source};
    size_t copied = 0;
    int fin = 0;
    if (passed) {
        passed = ReceiveTestIndicate(
                stream,
                &descriptor,
                1,
                1,
                QUIC_RECEIVE_FLAG_FIN) == QUIC_STATUS_PENDING &&
            reach_msquic_stream_read(
                stream,
                mapping + body_offset,
                1,
                10,
                &copied,
                &fin) == REACH_MSQUIC_OK &&
            copied == 1 && fin == 1 && mapping[body_offset] == source;
    }
    passed = passed &&
        atomic_load_explicit(&context.failures, memory_order_relaxed) == 0 &&
        ReceiveTestResidentPrefix(mapping, mapped_length, page_size, page_size) &&
        listener.metrics.retained_receive_bytes == logical_length &&
        listener.metrics.physical_owned_receive_bytes == mapped_length &&
        listener.metrics.physical_borrowed_receive_bytes == 0 &&
        listener.metrics.physical_receive_bytes == mapped_length &&
        listener.metrics.virtual_receive_bytes == mapped_length &&
        reach_msquic_stream_release_receive_mapping(
            stream,
            mapping,
            body_offset - 1,
            logical_length,
            mapped_length,
            page_size) == REACH_MSQUIC_ERROR;
    if (passed) {
        released = reach_msquic_stream_release_receive_mapping(
            stream,
            mapping,
            body_offset,
            logical_length,
            mapped_length,
            page_size) == REACH_MSQUIC_OK;
        passed = released &&
            listener.metrics.retained_receive_bytes == 0 &&
            listener.metrics.physical_receive_bytes == 0 &&
            listener.metrics.virtual_receive_bytes == 0;
    }
    listener.receive_test_before_copy = NULL;
    listener.receive_test_context = NULL;
    if (stream != NULL) StreamRelease(stream);
    if (!registered) (void)munmap(mapping, mapped_length);
    ReceiveTestListenerDestroy(&listener);
    return passed;
}

typedef struct reach_mapped_receive_thread_context {
    reach_msquic_stream *stream;
    uint8_t *destination;
    size_t length;
    _Atomic uint32_t *start;
    int status;
} reach_mapped_receive_thread_context;

static void *
ReceiveTestMappedReadThread(void *opaque)
{
    reach_mapped_receive_thread_context *context = opaque;
    while (!atomic_load_explicit(context->start, memory_order_acquire)) {
        (void)sched_yield();
    }
    size_t copied = 0;
    int fin = 0;
    context->status = reach_msquic_stream_read(
        context->stream,
        context->destination,
        context->length,
        1000,
        &copied,
        &fin);
    if (copied != context->length || !fin) {
        context->status = REACH_MSQUIC_ERROR;
    }
    return NULL;
}

static int
ReceiveTestMappedSixteenStreams(void)
{
    long page_size_value = sysconf(_SC_PAGESIZE);
    if (page_size_value <= 0 || !IsValidReceivePageSize((uint64_t)page_size_value)) {
        return 0;
    }
    size_t page_size = (size_t)page_size_value;
    const size_t logical_length = REACH_MSQUIC_MAX_FRAME_LENGTH - 1;
    const size_t final_length = REACH_MSQUIC_RECEIVE_COPY_QUANTUM - 1;
    const size_t prefix_length = logical_length - final_length;
    QUIC_API_TABLE api;
    reach_msquic_listener listener;
    reach_receive_test_capture captures[REACH_MSQUIC_MAX_STREAMS_PROCESS] = {0};
    reach_msquic_stream *streams[REACH_MSQUIC_MAX_STREAMS_PROCESS] = {0};
    uint8_t *mappings[REACH_MSQUIC_MAX_STREAMS_PROCESS] = {0};
    size_t mapped_lengths[REACH_MSQUIC_MAX_STREAMS_PROCESS] = {0};
    uint8_t *source = malloc(REACH_MSQUIC_RECEIVE_COPY_QUANTUM);
    if (source == NULL || !ReceiveTestListenerInitialize(&listener, &api)) {
        free(source);
        return 0;
    }
    memset(source, 0x3c, REACH_MSQUIC_RECEIVE_COPY_QUANTUM);
    int passed = 1;
    for (uint32_t index = 0; index < REACH_MSQUIC_MAX_STREAMS_PROCESS; ++index) {
        streams[index] = ReceiveTestStreamCreate(&listener, &captures[index]);
        mappings[index] = ReceiveTestCreateMapping(
            logical_length,
            page_size,
            &mapped_lengths[index]);
        passed = passed && streams[index] != NULL && mappings[index] != NULL &&
            reach_msquic_stream_register_receive_mapping(
                streams[index],
                mappings[index],
                0,
                logical_length,
                mapped_lengths[index],
                page_size) == REACH_MSQUIC_OK &&
            ReceiveTestPopulateMapping(
                streams[index],
                mappings[index],
                0,
                prefix_length,
                source);
    }

    for (uint32_t index = 0; passed && index < REACH_MSQUIC_MAX_STREAMS_PROCESS; ++index) {
        QUIC_BUFFER descriptor = {(uint32_t)final_length, source};
        passed = ReceiveTestIndicate(
            streams[index],
            &descriptor,
            1,
            final_length,
            QUIC_RECEIVE_FLAG_FIN) == QUIC_STATUS_PENDING;
    }
    reach_mapped_receive_test_context barrier = {
        .listener = &listener,
        .page_size = page_size,
        .barrier_count = REACH_MSQUIC_MAX_STREAMS_PROCESS,
    };
    listener.receive_test_before_copy = ReceiveTestBeforeMappedCopy;
    listener.receive_test_context = &barrier;
    _Atomic uint32_t start = 0;
    pthread_t threads[REACH_MSQUIC_MAX_STREAMS_PROCESS];
    reach_mapped_receive_thread_context contexts[REACH_MSQUIC_MAX_STREAMS_PROCESS] = {0};
    uint32_t created = 0;
    for (; passed && created < REACH_MSQUIC_MAX_STREAMS_PROCESS; ++created) {
        contexts[created] = (reach_mapped_receive_thread_context){
            .stream = streams[created],
            .destination = mappings[created] + prefix_length,
            .length = final_length,
            .start = &start,
            .status = REACH_MSQUIC_ERROR,
        };
        passed = pthread_create(
            &threads[created],
            NULL,
            ReceiveTestMappedReadThread,
            &contexts[created]) == 0;
    }
    if (created == REACH_MSQUIC_MAX_STREAMS_PROCESS) {
        atomic_store_explicit(&start, 1, memory_order_release);
    } else {
        barrier.barrier_count = created;
        atomic_store_explicit(&start, 1, memory_order_release);
    }
    for (uint32_t index = 0; index < created; ++index) {
        (void)pthread_join(threads[index], NULL);
        passed = passed && contexts[index].status == REACH_MSQUIC_OK;
    }
    passed = passed &&
        atomic_load_explicit(&barrier.arrivals, memory_order_relaxed) ==
            REACH_MSQUIC_MAX_STREAMS_PROCESS &&
        atomic_load_explicit(&barrier.failures, memory_order_relaxed) == 0 &&
        listener.metrics.retained_receive_bytes ==
            (uint64_t)logical_length * REACH_MSQUIC_MAX_STREAMS_PROCESS &&
        listener.metrics.physical_owned_receive_bytes ==
            (uint64_t)REACH_MSQUIC_MAX_FRAME_LENGTH * REACH_MSQUIC_MAX_STREAMS_PROCESS &&
        listener.metrics.physical_borrowed_receive_bytes == 0 &&
        listener.metrics.physical_receive_bytes <=
            REACH_MSQUIC_PROCESS_PHYSICAL_RECEIVE_LIMIT &&
        listener.metrics.peak_physical_receive_bytes <=
            REACH_MSQUIC_PROCESS_PHYSICAL_RECEIVE_LIMIT;

    listener.receive_test_before_copy = NULL;
    listener.receive_test_context = NULL;
    for (uint32_t index = 0; index < REACH_MSQUIC_MAX_STREAMS_PROCESS; ++index) {
        if (streams[index] != NULL && mappings[index] != NULL) {
            passed = passed && ReceiveTestResidentPrefix(
                mappings[index],
                mapped_lengths[index],
                logical_length,
                page_size) &&
                reach_msquic_stream_release_receive_mapping(
                    streams[index],
                    mappings[index],
                    0,
                    logical_length,
                    mapped_lengths[index],
                    page_size) == REACH_MSQUIC_OK;
        } else if (mappings[index] != NULL) {
            (void)munmap(mappings[index], mapped_lengths[index]);
        }
        if (streams[index] != NULL) StreamRelease(streams[index]);
    }
    passed = passed && listener.metrics.retained_receive_bytes == 0 &&
        listener.metrics.physical_receive_bytes == 0 &&
        listener.metrics.virtual_receive_bytes == 0 &&
        listener.metrics.active_streams == 0;
    free(source);
    ReceiveTestListenerDestroy(&listener);
    return passed;
}

typedef struct reach_configuration_test_capture {
    QUIC_CONNECTION_CALLBACK_HANDLER callback;
    void *callback_context;
    QUIC_STATUS configuration_status;
    int deliver_reentrant_shutdown;
    int block_configuration;
    pthread_mutex_t barrier_lock;
    pthread_cond_t barrier_changed;
    int configuration_entered;
    int release_configuration;
    uint64_t close_calls;
    uint64_t shutdown_calls;
    reach_configuration_test_witness witness;
} reach_configuration_test_capture;

static void QUIC_API
ConfigurationTestSetCallbackHandler(HQUIC handle, void *handler, void *context)
{
    reach_configuration_test_capture *capture = (reach_configuration_test_capture *)handle;
    capture->callback = (QUIC_CONNECTION_CALLBACK_HANDLER)handler;
    capture->callback_context = context;
    ((reach_msquic_connection *)context)->test_witness = &capture->witness;
}

static int
ConfigurationTestDeliverShutdown(
    reach_configuration_test_capture *capture,
    HQUIC handle,
    int attempted_late_dispatch)
{
    if (attempted_late_dispatch) {
        (void)atomic_fetch_add_explicit(
            &capture->witness.late_dispatch_attempts,
            1,
            memory_order_relaxed);
    }
    if (atomic_load_explicit(&capture->witness.released, memory_order_acquire)) {
        if (attempted_late_dispatch) {
            (void)atomic_fetch_add_explicit(
                &capture->witness.late_dispatch_refusals,
                1,
                memory_order_relaxed);
        }
        return 0;
    }
    if (capture->callback == NULL || capture->callback_context == NULL) {
        return 0;
    }
    (void)atomic_fetch_add_explicit(
        &capture->witness.callback_dispatches,
        1,
        memory_order_relaxed);
    if (atomic_load_explicit(&capture->witness.released, memory_order_acquire)) {
        (void)atomic_fetch_add_explicit(
            &capture->witness.post_release_callback_accesses,
            1,
            memory_order_relaxed);
        return 0;
    }
    QUIC_CONNECTION_EVENT event = {0};
    event.Type = QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE;
    event.SHUTDOWN_COMPLETE.HandshakeCompleted = TRUE;
    (void)capture->callback(handle, capture->callback_context, &event);
    return 1;
}

static QUIC_STATUS QUIC_API
ConfigurationTestSetConfiguration(HQUIC handle, HQUIC configuration)
{
    (void)configuration;
    reach_configuration_test_capture *capture = (reach_configuration_test_capture *)handle;
    if (capture->block_configuration) {
        (void)pthread_mutex_lock(&capture->barrier_lock);
        capture->configuration_entered = 1;
        (void)pthread_cond_broadcast(&capture->barrier_changed);
        while (!capture->release_configuration) {
            (void)pthread_cond_wait(&capture->barrier_changed, &capture->barrier_lock);
        }
        (void)pthread_mutex_unlock(&capture->barrier_lock);
    }
    if (capture->deliver_reentrant_shutdown) {
        (void)ConfigurationTestDeliverShutdown(capture, handle, 0);
    }
    return capture->configuration_status;
}

static void QUIC_API
ConfigurationTestShutdown(
    HQUIC handle,
    QUIC_CONNECTION_SHUTDOWN_FLAGS flags,
    QUIC_UINT62 error_code)
{
    (void)flags;
    (void)error_code;
    reach_configuration_test_capture *capture = (reach_configuration_test_capture *)handle;
    capture->shutdown_calls += 1;
    (void)ConfigurationTestDeliverShutdown(capture, handle, 0);
}

static void QUIC_API
ConfigurationTestClose(HQUIC handle)
{
    reach_configuration_test_capture *capture = (reach_configuration_test_capture *)handle;
    capture->close_calls += 1;
}

typedef struct reach_configuration_listener_thread_context {
    reach_msquic_listener *listener;
    QUIC_LISTENER_EVENT event;
    QUIC_STATUS status;
} reach_configuration_listener_thread_context;

static void *
ConfigurationTestListenerThread(void *opaque)
{
    reach_configuration_listener_thread_context *context = opaque;
    context->status = ListenerCallback(NULL, context->listener, &context->event);
    return NULL;
}

typedef struct reach_configuration_stop_thread_context {
    reach_msquic_listener *listener;
    uint64_t deadline;
    int status;
    uint64_t completed_at;
} reach_configuration_stop_thread_context;

static void *
ConfigurationTestStopThread(void *opaque)
{
    reach_configuration_stop_thread_context *context = opaque;
    context->status = reach_msquic_listener_stop_until(
        context->listener,
        context->deadline);
    context->completed_at = reach_msquic_monotonic_now_nanoseconds();
    return NULL;
}

static int
ConfigurationTestCaptureInitialize(
    reach_configuration_test_capture *capture,
    QUIC_STATUS status,
    int reentrant,
    int blocked)
{
    memset(capture, 0, sizeof(*capture));
    capture->configuration_status = status;
    capture->deliver_reentrant_shutdown = reentrant;
    capture->block_configuration = blocked;
    atomic_init(&capture->witness.callback_dispatches, 0);
    atomic_init(&capture->witness.context_release_events, 0);
    atomic_init(&capture->witness.stop_latches, 0);
    atomic_init(&capture->witness.late_dispatch_attempts, 0);
    atomic_init(&capture->witness.late_dispatch_refusals, 0);
    atomic_init(&capture->witness.post_release_callback_accesses, 0);
    atomic_init(&capture->witness.released, 0);
    if (!blocked) {
        return 1;
    }
    if (pthread_mutex_init(&capture->barrier_lock, NULL) != 0) {
        return 0;
    }
    if (!ConditionInitialize(&capture->barrier_changed)) {
        (void)pthread_mutex_destroy(&capture->barrier_lock);
        return 0;
    }
    return 1;
}

static void
ConfigurationTestCaptureDestroy(reach_configuration_test_capture *capture)
{
    if (!capture->block_configuration) {
        return;
    }
    (void)pthread_cond_destroy(&capture->barrier_changed);
    (void)pthread_mutex_destroy(&capture->barrier_lock);
}

static int
ConfigurationTestAwaitEntry(reach_configuration_test_capture *capture)
{
    struct timespec deadline = DeadlineAfter(1000);
    (void)pthread_mutex_lock(&capture->barrier_lock);
    while (!capture->configuration_entered) {
        int status = pthread_cond_timedwait(
            &capture->barrier_changed,
            &capture->barrier_lock,
            &deadline);
        if (status != 0) {
            (void)pthread_mutex_unlock(&capture->barrier_lock);
            return 0;
        }
    }
    (void)pthread_mutex_unlock(&capture->barrier_lock);
    return 1;
}

static void
ConfigurationTestReleaseConfiguration(reach_configuration_test_capture *capture)
{
    (void)pthread_mutex_lock(&capture->barrier_lock);
    capture->release_configuration = 1;
    (void)pthread_cond_broadcast(&capture->barrier_changed);
    (void)pthread_mutex_unlock(&capture->barrier_lock);
}

static int
ConfigurationTestAwaitStopLatch(reach_configuration_test_capture *capture)
{
    uint64_t now = reach_msquic_monotonic_now_nanoseconds();
    uint64_t deadline = now + 1000000000ULL;
    while (atomic_load_explicit(&capture->witness.stop_latches, memory_order_acquire) == 0) {
        if (reach_msquic_monotonic_now_nanoseconds() >= deadline) {
            return 0;
        }
        (void)sched_yield();
    }
    return 1;
}

int
reach_msquic_configuration_contract_test(
    uint32_t iterations,
    reach_msquic_configuration_contract_result *out_result)
{
    if (iterations == 0 || out_result == NULL) {
        return REACH_MSQUIC_ERROR;
    }
    memset(out_result, 0, sizeof(*out_result));

    QUIC_API_TABLE api = {0};
    api.SetCallbackHandler = ConfigurationTestSetCallbackHandler;
    api.ConnectionSetConfiguration = ConfigurationTestSetConfiguration;
    api.ConnectionShutdown = ConfigurationTestShutdown;
    api.ConnectionClose = ConfigurationTestClose;

    reach_msquic_listener listener = {0};
    listener.api = &api;
    listener.configuration = (HQUIC)(uintptr_t)0x2;
    if (pthread_mutex_init(&listener.lock, NULL) != 0) {
        return REACH_MSQUIC_ERROR;
    }
    if (!ConditionInitialize(&listener.changed)) {
        (void)pthread_mutex_destroy(&listener.lock);
        return REACH_MSQUIC_ERROR;
    }

    uint32_t saturated_counter = UINT32_MAX;
    SaturatingIncrement32(&saturated_counter);
    int passed = saturated_counter == UINT32_MAX;
    uint64_t shutdown_calls = 0;
    uint64_t stop_deadline_settlements = 0;
    uint64_t callback_dispatches = 0;
    uint64_t context_release_events = 0;
    uint64_t stop_latches = 0;
    uint64_t late_dispatch_attempts = 0;
    uint64_t late_dispatch_refusals = 0;
    uint64_t post_release_callback_accesses = 0;
    for (uint32_t iteration = 0; iteration < iterations && passed; ++iteration) {
        for (uint32_t variant = 0; variant < 6 && passed; ++variant) {
            int succeeds = variant == 2 || variant == 3 || variant == 5;
            int blocked = variant >= 4;
            reach_configuration_test_capture capture;
            passed = ConfigurationTestCaptureInitialize(
                &capture,
                succeeds ? QUIC_STATUS_SUCCESS : QUIC_STATUS_INVALID_STATE,
                variant == 1 || variant == 3,
                blocked);
            if (!passed) {
                break;
            }
            reach_configuration_listener_thread_context callback_context = {
                .listener = &listener,
                .status = QUIC_STATUS_ABORTED,
            };
            callback_context.event.Type = QUIC_LISTENER_EVENT_NEW_CONNECTION;
            callback_context.event.NEW_CONNECTION.Connection = (HQUIC)&capture;

            uint32_t removals_before =
                listener.metrics.connection_registrations_removed;
            uint32_t releases_before = listener.metrics.connection_context_releases;
            uint32_t closes_before = listener.metrics.application_connection_closes;
            uint32_t refused_before = listener.metrics.refused_connections;
            uint32_t completions_before =
                listener.metrics.connection_shutdown_completions;
            QUIC_STATUS status = QUIC_STATUS_ABORTED;
            int stop_status = REACH_MSQUIC_ERROR;
            uint64_t stop_completed_at = 0;
            if (!blocked) {
                status = ListenerCallback(NULL, &listener, &callback_context.event);
                if (succeeds && !capture.deliver_reentrant_shutdown) {
                    passed = ConfigurationTestDeliverShutdown(
                        &capture,
                        (HQUIC)&capture,
                        0);
                }
            } else {
                pthread_t callback_thread;
                pthread_t stop_thread;
                int callback_created = pthread_create(
                    &callback_thread,
                    NULL,
                    ConfigurationTestListenerThread,
                    &callback_context) == 0;
                passed = callback_created && ConfigurationTestAwaitEntry(&capture);
                uint64_t now = reach_msquic_monotonic_now_nanoseconds();
                reach_configuration_stop_thread_context stop_context = {
                    .listener = &listener,
                    .deadline = now + 5000000000ULL,
                    .status = REACH_MSQUIC_ERROR,
                };
                int stop_created = passed && pthread_create(
                    &stop_thread,
                    NULL,
                    ConfigurationTestStopThread,
                    &stop_context) == 0;
                passed = passed && stop_created && ConfigurationTestAwaitStopLatch(&capture);
                ConfigurationTestReleaseConfiguration(&capture);
                if (callback_created) {
                    (void)pthread_join(callback_thread, NULL);
                    status = callback_context.status;
                }
                if (stop_created) {
                    (void)pthread_join(stop_thread, NULL);
                    stop_status = stop_context.status;
                    stop_completed_at = stop_context.completed_at;
                }
                passed = passed && stop_status == REACH_MSQUIC_OK &&
                    stop_completed_at > 0 && stop_completed_at <= stop_context.deadline;
                if (stop_status == REACH_MSQUIC_OK &&
                    stop_completed_at > 0 && stop_completed_at <= stop_context.deadline) {
                    stop_deadline_settlements += 1;
                }
                (void)pthread_mutex_lock(&listener.lock);
                listener.stopping = 0;
                listener.stopped = 0;
                listener.shutdown_deadline_nanoseconds = 0;
                (void)pthread_mutex_unlock(&listener.lock);
            }

            int late_dispatched = ConfigurationTestDeliverShutdown(
                &capture,
                (HQUIC)&capture,
                1);

            uint64_t expected_callbacks =
                variant == 0 || variant == 4 ? 0U : 1U;
            uint64_t expected_completions = expected_callbacks;

            passed = status == capture.configuration_status &&
                !late_dispatched &&
                listener.metrics.active_connections == 0 &&
                listener.metrics.connection_registrations_removed ==
                    removals_before + 1 &&
                listener.metrics.connection_context_releases == releases_before + 1 &&
                listener.metrics.application_connection_closes ==
                    closes_before + (succeeds ? 1U : 0U) &&
                listener.metrics.refused_connections ==
                    refused_before + (succeeds ? 0U : 1U) &&
                listener.metrics.connection_shutdown_completions ==
                    completions_before + expected_completions &&
                capture.close_calls == (succeeds ? 1U : 0U) &&
                capture.shutdown_calls == (variant == 5 ? 1U : 0U) &&
                atomic_load_explicit(
                    &capture.witness.callback_dispatches,
                    memory_order_relaxed) == expected_callbacks &&
                atomic_load_explicit(
                    &capture.witness.context_release_events,
                    memory_order_relaxed) == 1 &&
                atomic_load_explicit(
                    &capture.witness.stop_latches,
                    memory_order_relaxed) == (blocked ? 1U : 0U) &&
                atomic_load_explicit(
                    &capture.witness.late_dispatch_attempts,
                    memory_order_relaxed) == 1 &&
                atomic_load_explicit(
                    &capture.witness.late_dispatch_refusals,
                    memory_order_relaxed) == 1 &&
                atomic_load_explicit(
                    &capture.witness.post_release_callback_accesses,
                    memory_order_relaxed) == 0;

            shutdown_calls += capture.shutdown_calls;
            callback_dispatches += atomic_load_explicit(
                &capture.witness.callback_dispatches,
                memory_order_relaxed);
            context_release_events += atomic_load_explicit(
                &capture.witness.context_release_events,
                memory_order_relaxed);
            stop_latches += atomic_load_explicit(
                &capture.witness.stop_latches,
                memory_order_relaxed);
            late_dispatch_attempts += atomic_load_explicit(
                &capture.witness.late_dispatch_attempts,
                memory_order_relaxed);
            late_dispatch_refusals += atomic_load_explicit(
                &capture.witness.late_dispatch_refusals,
                memory_order_relaxed);
            post_release_callback_accesses += atomic_load_explicit(
                &capture.witness.post_release_callback_accesses,
                memory_order_relaxed);
            ConfigurationTestCaptureDestroy(&capture);
        }
    }

    out_result->attempts = listener.metrics.configuration_attempts;
    out_result->succeeded = listener.metrics.configuration_succeeded;
    out_result->failed = listener.metrics.configuration_failed;
    out_result->connection_closes = listener.metrics.application_connection_closes;
    out_result->registration_removals =
        listener.metrics.connection_registrations_removed;
    out_result->context_releases = listener.metrics.connection_context_releases;
    out_result->refused_connections = listener.metrics.refused_connections;
    out_result->active_connections = listener.metrics.active_connections;
    out_result->shutdown_calls = shutdown_calls;
    out_result->shutdown_completions =
        listener.metrics.connection_shutdown_completions;
    out_result->stop_latches = stop_latches;
    out_result->stop_deadline_settlements = stop_deadline_settlements;
    out_result->callback_dispatches = callback_dispatches;
    out_result->context_release_events = context_release_events;
    out_result->late_dispatch_attempts = late_dispatch_attempts;
    out_result->late_dispatch_refusals = late_dispatch_refusals;
    out_result->post_release_callback_accesses = post_release_callback_accesses;

    uint64_t iterations64 = (uint64_t)iterations;
    uint64_t doubled = iterations64 * 2U;
    uint64_t tripled = iterations64 * 3U;
    uint64_t quadrupled = iterations64 * 4U;
    uint64_t sextupled = iterations64 * 6U;
    passed = passed &&
        out_result->attempts == sextupled &&
        out_result->succeeded == tripled &&
        out_result->failed == tripled &&
        out_result->connection_closes == tripled &&
        out_result->registration_removals == sextupled &&
        out_result->context_releases == sextupled &&
        out_result->refused_connections == tripled &&
        out_result->active_connections == 0 &&
        out_result->shutdown_calls == iterations64 &&
        out_result->shutdown_completions == quadrupled &&
        out_result->stop_latches == doubled &&
        out_result->stop_deadline_settlements == doubled &&
        out_result->callback_dispatches == quadrupled &&
        out_result->context_release_events == sextupled &&
        out_result->late_dispatch_attempts == sextupled &&
        out_result->late_dispatch_refusals == sextupled &&
        out_result->post_release_callback_accesses == 0;

    (void)pthread_cond_destroy(&listener.changed);
    (void)pthread_mutex_destroy(&listener.lock);
    return passed ? REACH_MSQUIC_OK : REACH_MSQUIC_ERROR;
}

int
reach_msquic_receive_contract_test(uint32_t scenario, uint32_t iterations)
{
    switch (scenario) {
    case REACH_MSQUIC_RECEIVE_TEST_DEFERRED_MULTI_BUFFER:
        return ReceiveTestDeferredMultiBuffer() ? REACH_MSQUIC_OK : REACH_MSQUIC_ERROR;
    case REACH_MSQUIC_RECEIVE_TEST_LOCAL_CANCELLATION:
        return ReceiveTestCancellationOrPeerAbort(0) ? REACH_MSQUIC_OK : REACH_MSQUIC_ERROR;
    case REACH_MSQUIC_RECEIVE_TEST_PEER_ABORT:
        return ReceiveTestCancellationOrPeerAbort(1) ? REACH_MSQUIC_OK : REACH_MSQUIC_ERROR;
    case REACH_MSQUIC_RECEIVE_TEST_CLOSE_RACE:
        return ReceiveTestCloseRace(iterations) ? REACH_MSQUIC_OK : REACH_MSQUIC_ERROR;
    case REACH_MSQUIC_RECEIVE_TEST_EMPTY_FIN:
        return ReceiveTestEmptyFin() ? REACH_MSQUIC_OK : REACH_MSQUIC_ERROR;
    case REACH_MSQUIC_RECEIVE_TEST_RETENTION_BUDGET:
        return ReceiveTestRetentionBudget() ? REACH_MSQUIC_OK : REACH_MSQUIC_ERROR;
    case REACH_MSQUIC_RECEIVE_TEST_MAPPED_PRECHARGE:
        return ReceiveTestMappedPrecharge() ? REACH_MSQUIC_OK : REACH_MSQUIC_ERROR;
    case REACH_MSQUIC_RECEIVE_TEST_MAPPED_SIXTEEN_STREAMS:
        return ReceiveTestMappedSixteenStreams() ? REACH_MSQUIC_OK : REACH_MSQUIC_ERROR;
    case REACH_MSQUIC_RECEIVE_TEST_MAPPED_TAIL_BODY:
        return ReceiveTestMappedTailBody() ? REACH_MSQUIC_OK : REACH_MSQUIC_ERROR;
    default:
        return REACH_MSQUIC_ERROR;
    }
}

int
reach_msquic_shutdown_contract_test(uint32_t scenario)
{
    QUIC_API_TABLE api;
    reach_msquic_listener *listener = calloc(1, sizeof(*listener));
    if (listener == NULL || !ReceiveTestListenerInitialize(listener, &api)) {
        free(listener);
        return REACH_MSQUIC_ERROR;
    }
    listener->api = NULL;
    uint64_t now = reach_msquic_monotonic_now_nanoseconds();
    if (now == 0) {
        ReceiveTestListenerDestroy(listener);
        free(listener);
        return REACH_MSQUIC_ERROR;
    }
    uint64_t deadline = now + 1000000000ULL;
    int passed = 0;
    switch (scenario) {
    case REACH_MSQUIC_SHUTDOWN_TEST_SUCCESS:
        passed = reach_msquic_listener_stop_until(listener, deadline) == REACH_MSQUIC_OK &&
            listener->stopped && listener->shutdown_deadline_nanoseconds == deadline;
        if (passed) {
            passed = reach_msquic_listener_stop_until(
                listener,
                deadline + 1000000000ULL) == REACH_MSQUIC_OK &&
                listener->shutdown_deadline_nanoseconds == deadline;
        }
        break;
    case REACH_MSQUIC_SHUTDOWN_TEST_TIMEOUT_REUSE:
        listener->metrics.active_connections = 1;
        deadline = now;
        passed = reach_msquic_listener_stop_until(listener, deadline) == REACH_MSQUIC_TIMEOUT &&
            listener->shutdown_deadline_nanoseconds == deadline &&
            reach_msquic_listener_stop_until(
                listener,
                deadline + 1000000000ULL) == REACH_MSQUIC_TIMEOUT &&
            listener->shutdown_deadline_nanoseconds == deadline;
        listener->metrics.active_connections = 0;
        break;
    case REACH_MSQUIC_SHUTDOWN_TEST_DESTRUCTOR_REUSE:
        listener->metrics.active_streams = 1;
        deadline = now;
        passed = reach_msquic_listener_stop_until(listener, deadline) == REACH_MSQUIC_TIMEOUT &&
            listener->shutdown_deadline_nanoseconds == deadline &&
            reach_msquic_listener_destroy(listener) == REACH_MSQUIC_TIMEOUT &&
            listener->shutdown_deadline_nanoseconds == deadline;
        listener->metrics.active_streams = 0;
        if (passed) {
            return reach_msquic_listener_destroy(listener) == REACH_MSQUIC_OK ?
                REACH_MSQUIC_OK : REACH_MSQUIC_ERROR;
        }
        break;
    default:
        break;
    }
    if (scenario == REACH_MSQUIC_SHUTDOWN_TEST_SUCCESS && passed) {
        return reach_msquic_listener_destroy(listener) == REACH_MSQUIC_OK ?
            REACH_MSQUIC_OK : REACH_MSQUIC_ERROR;
    }
    if (scenario == REACH_MSQUIC_SHUTDOWN_TEST_TIMEOUT_REUSE && passed) {
        return reach_msquic_listener_destroy(listener) == REACH_MSQUIC_OK ?
            REACH_MSQUIC_OK : REACH_MSQUIC_ERROR;
    }
    ReceiveTestListenerDestroy(listener);
    free(listener);
    return REACH_MSQUIC_ERROR;
}

int
reach_msquic_version_settings_layout(
    size_t *out_size,
    size_t *out_alignment,
    size_t out_offsets[6])
{
    if (out_size == NULL || out_alignment == NULL || out_offsets == NULL) {
        return REACH_MSQUIC_ERROR;
    }
    *out_size = sizeof(QUIC_VERSION_SETTINGS);
    *out_alignment = _Alignof(QUIC_VERSION_SETTINGS);
    out_offsets[0] = offsetof(QUIC_VERSION_SETTINGS, AcceptableVersions);
    out_offsets[1] = offsetof(QUIC_VERSION_SETTINGS, OfferedVersions);
    out_offsets[2] = offsetof(QUIC_VERSION_SETTINGS, FullyDeployedVersions);
    out_offsets[3] = offsetof(QUIC_VERSION_SETTINGS, AcceptableVersionsLength);
    out_offsets[4] = offsetof(QUIC_VERSION_SETTINGS, OfferedVersionsLength);
    out_offsets[5] = offsetof(QUIC_VERSION_SETTINGS, FullyDeployedVersionsLength);
    return REACH_MSQUIC_OK;
}

int
reach_linux_systemd_notify(const char *message)
{
    const char *path = getenv("NOTIFY_SOCKET");
    if (path == NULL || path[0] == '\0' || message == NULL) {
        return REACH_MSQUIC_REFUSED;
    }
    size_t path_length = strlen(path);
    size_t message_length = strlen(message);
    if (path_length >= sizeof(((struct sockaddr_un *)0)->sun_path) ||
        message_length == 0 || message_length > 1024) {
        return REACH_MSQUIC_ERROR;
    }
    int descriptor = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0) {
        return REACH_MSQUIC_ERROR;
    }
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    socklen_t address_length;
    if (path[0] == '@') {
        address.sun_path[0] = '\0';
        memcpy(address.sun_path + 1, path + 1, path_length - 1);
        address_length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + path_length);
    } else {
        memcpy(address.sun_path, path, path_length + 1);
        address_length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + path_length + 1);
    }
    ssize_t sent = sendto(
        descriptor,
        message,
        message_length,
        MSG_NOSIGNAL,
        (const struct sockaddr *)&address,
        address_length);
    int result = sent == (ssize_t)message_length ? REACH_MSQUIC_OK : REACH_MSQUIC_ERROR;
    (void)close(descriptor);
    return result;
}
