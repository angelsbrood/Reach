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
    uint64_t shutdown_deadline_nanoseconds;
    int stopping;
    int stopped;
};

static const uint8_t ReachAlpnBytes[REACH_ALPN_LENGTH] = "reach/0";
static const QUIC_BUFFER ReachAlpn = {
    REACH_ALPN_LENGTH,
    (uint8_t *)ReachAlpnBytes,
};

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
    free(connection->peer_certificate);
    (void)pthread_mutex_destroy(&connection->lock);
    free(connection);
}

static HQUIC
ConnectionBeginAPICall(reach_msquic_connection *connection)
{
    HQUIC handle = NULL;
    (void)pthread_mutex_lock(&connection->lock);
    if (!connection->closed && !connection->handle_closed && connection->handle != NULL) {
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
    if (connection->shutdown_complete && connection->active_api_calls == 0 &&
        !connection->handle_closed && connection->handle != NULL) {
        close_handle = connection->handle;
        connection->handle = NULL;
        connection->handle_closed = 1;
    }
    (void)pthread_mutex_unlock(&connection->lock);
    if (close_handle != NULL) {
        connection->listener->api->ConnectionClose(close_handle);
    }
}

static void StreamRetain(reach_msquic_stream *stream)
{
    (void)atomic_fetch_add_explicit(&stream->references, 1, memory_order_relaxed);
}

static void StreamRelease(reach_msquic_stream *stream)
{
    if (atomic_fetch_sub_explicit(&stream->references, 1, memory_order_acq_rel) != 1) {
        return;
    }
    if (stream->owned_receive_bytes > 0 || stream->borrowed_receive_bytes > 0) {
        reach_msquic_listener *listener = stream->connection->listener;
        uint64_t retained = stream->owned_receive_bytes + stream->borrowed_receive_bytes;
        (void)pthread_mutex_lock(&listener->lock);
        if (retained <= listener->metrics.retained_receive_bytes) {
            listener->metrics.retained_receive_bytes -= retained;
        } else {
            listener->metrics.retained_receive_bytes = 0;
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
    if (completion.handle == NULL) {
        return;
    }
    stream->connection->listener->api->StreamReceiveComplete(
        completion.handle,
        completion.length);
    if (completion.reenable) {
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
    StreamEndAPICall(stream);
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
        int has_capacity =
            stream->owned_receive_bytes < REACH_MSQUIC_STREAM_RECEIVE_LIMIT &&
            listener->metrics.retained_receive_bytes < REACH_MSQUIC_PROCESS_RECEIVE_LIMIT;
        if (stream->receive_suspended && !stream->receive_suspend_transition &&
            has_capacity && !stream->closed &&
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

static void
RemoveConnectionLocked(reach_msquic_listener *listener, reach_msquic_connection *connection)
{
    for (uint32_t index = 0; index < REACH_MSQUIC_MAX_CONNECTIONS; ++index) {
        if (listener->connections[index] == connection) {
            listener->connections[index] = NULL;
            return;
        }
    }
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
        if (!stream_fits || !process_fits) {
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
    case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED:
        CopyPeerCertificate(
            connection,
            (const QUIC_BUFFER *)event->PEER_CERTIFICATE_RECEIVED.Certificate);
        break;
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
        if (QUIC_FAILED(status) || handshake_length != sizeof(handshake) ||
            handshake.TlsProtocolVersion != QUIC_TLS_PROTOCOL_1_3 ||
            !alpn_matches) {
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
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
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
        (void)pthread_mutex_lock(&connection->lock);
        connection->closed = 1;
        connection->shutdown_complete = 1;
        if (connection->active_api_calls == 0 && !connection->handle_closed &&
            connection->handle != NULL) {
            close_handle = connection->handle;
            connection->handle = NULL;
            connection->handle_closed = 1;
        }
        (void)pthread_mutex_unlock(&connection->lock);
        (void)pthread_mutex_lock(&listener->lock);
        RemoveConnectionLocked(listener, connection);
        if (listener->metrics.active_connections > 0) {
            listener->metrics.active_connections -= 1;
        }
        (void)pthread_cond_broadcast(&listener->changed);
        (void)pthread_mutex_unlock(&listener->lock);
        if (close_handle != NULL) {
            listener->api->ConnectionClose(close_handle);
        }
        ConnectionRelease(connection);
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
    if (listener->metrics.active_connections > listener->metrics.peak_connections) {
        listener->metrics.peak_connections = listener->metrics.active_connections;
    }
    (void)pthread_mutex_unlock(&listener->lock);

    listener->api->SetCallbackHandler(
        event->NEW_CONNECTION.Connection,
        (void *)ConnectionCallback,
        connection);
    QUIC_STATUS status = listener->api->ConnectionSetConfiguration(
        event->NEW_CONNECTION.Connection,
        listener->configuration);
    if (QUIC_FAILED(status)) {
        (void)pthread_mutex_lock(&listener->lock);
        RemoveConnectionLocked(listener, connection);
        listener->metrics.active_connections -= 1;
        listener->metrics.refused_connections += 1;
        (void)pthread_mutex_unlock(&listener->lock);
        listener->api->ConnectionClose(event->NEW_CONNECTION.Connection);
        ConnectionRelease(connection);
    }
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
            HQUIC handle = ConnectionBeginAPICall(connections[index]);
            if (handle != NULL) {
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

    size_t wanted = destination_capacity;
    if ((uint64_t)wanted > stream->receive_total) {
        wanted = (size_t)stream->receive_total;
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
    if ((uint64_t)length > stream->owned_receive_bytes) {
        (void)pthread_mutex_unlock(&stream->lock);
        return REACH_MSQUIC_ERROR;
    }
    (void)pthread_mutex_lock(&listener->lock);
    if ((uint64_t)length > listener->metrics.retained_receive_bytes) {
        (void)pthread_mutex_unlock(&listener->lock);
        (void)pthread_mutex_unlock(&stream->lock);
        return REACH_MSQUIC_ERROR;
    }
    stream->owned_receive_bytes -= (uint64_t)length;
    listener->metrics.retained_receive_bytes -= (uint64_t)length;
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
            retained += REACH_MSQUIC_STREAM_RECEIVE_LIMIT;
        }
        streams[REACH_MSQUIC_MAX_STREAMS_PROCESS - 1]->owned_receive_bytes =
            REACH_MSQUIC_PROCESS_RECEIVE_LIMIT - retained - 1;
        listener.metrics.retained_receive_bytes = REACH_MSQUIC_PROCESS_RECEIVE_LIMIT - 1;
        listener.metrics.peak_retained_receive_bytes = listener.metrics.retained_receive_bytes;

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
        listener.metrics.retained_receive_bytes = REACH_MSQUIC_STREAM_RECEIVE_LIMIT - 1;
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
