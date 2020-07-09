// Copyright 2018 Square, Inc.
#include "qcomdl_transport.h"

#include <stdbool.h>
#include <stdlib.h>

#include "qcomdl_log.h"

#define FIREHOSE_USB_PACKET_SIZE 512

struct qcomdl_xfer_ctx {
    qcomdl_xfer_cb *callback;
    void *user_data;
    struct libusb_transfer *transfer;
    qcomdl_xfer_status status;
    void *buffer;
    int buffer_length;
    int actual_length;
    const char *label;
    libusb_device_handle *dev;
    unsigned timeout;
    bool zlp_sent;
};

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wswitch-enum"
static qcomdl_xfer_status qcomdl_xfer_status_of_libusb_status(qcomdl_xfer_ctx *ctx,
                                                              enum libusb_transfer_status status) {
    switch (status) {
    case LIBUSB_TRANSFER_CANCELLED:
        qcomdl_log_debug("Request cancelled (label=%s)", ctx->label);
        return QCOMDL_XFER_CANCELLED;
    case LIBUSB_TRANSFER_COMPLETED:
        return QCOMDL_XFER_COMPLETED;
    default:
        qcomdl_log_error("Received unexpected libusb transfer status: %s (label=%s)",
                         libusb_error_name((int) status),
                         ctx->label);
        return QCOMDL_XFER_ERR;
    }
}
#pragma clang diagnostic pop

static void LIBUSB_CALL qcomdl_xfer_cb_fn(struct libusb_transfer *transfer) {
    qcomdl_xfer_ctx *ctx = transfer->user_data;
    if (!ctx) {
        qcomdl_log_error("Missing request context\n");
        abort();
    }

    ctx->status = qcomdl_xfer_status_of_libusb_status(ctx, transfer->status);
    ctx->actual_length = transfer->actual_length;
    ctx->callback(ctx);
}

qcomdl_xfer_ctx *qcomdl_xfer_ctx_create(libusb_device_handle *dev,
                                         uint8_t endpoint,
                                         void *buffer,
                                         int length,
                                         qcomdl_xfer_cb callback,
                                         void *user_data,
                                         unsigned timeout,
                                         const char *label) {
    if (!dev || !buffer) {
        qcomdl_log_error("Invalid argument\n");
        return NULL;
    }

    qcomdl_xfer_ctx *ctx = calloc(1, sizeof(qcomdl_xfer_ctx));
    if (!ctx) {
        qcomdl_log_error("Failed to allocate qcomdl_xfer_ctx\n");
        return NULL;
    }

    *ctx = (qcomdl_xfer_ctx) {
        .status = QCOMDL_XFER_PENDING,
        .callback = callback,
        .user_data = user_data,
        .buffer = buffer,
        .buffer_length = length,
        .label = label,
        .timeout = timeout,
        .dev = dev,
    };

    ctx->transfer = libusb_alloc_transfer(0);
    if (!ctx->transfer) {
        qcomdl_log_error("Failed to allocate libusb_transfer\n");
        free(ctx);
        return NULL;
    }

    libusb_fill_bulk_transfer(ctx->transfer,
                              dev,
                              endpoint,
                              buffer,
                              length,
                              qcomdl_xfer_cb_fn,
                              ctx,
                              timeout);

    return ctx;
}

static void LIBUSB_CALL qcomdl_xfer_cb_zlp(struct libusb_transfer *transfer)
{
    qcomdl_xfer_ctx *ctx = transfer->user_data;
    if (!ctx) {
        qcomdl_log_error("Missing request context\n");
        abort();
    }

    qcomdl_xfer_status status = qcomdl_xfer_status_of_libusb_status(ctx, transfer->status);
    if (status == QCOMDL_XFER_CANCELLED) {
        qcomdl_log_debug("libusb zlp xfer label=%s cancelled\n", ctx->label);
        return;
    }

    ctx->zlp_sent = (status == QCOMDL_XFER_COMPLETED);
}

static int qcomdl_send_zlp(qcomdl_xfer_ctx *ctx)
{
    int send_zlp_ret = -1;
    struct libusb_transfer *zlp_xfer = libusb_alloc_transfer(0);
    if (!zlp_xfer) {
        qcomdl_log_error("unable to allocate libusb xfer for zlp\n");
        return -1;
    }

    libusb_fill_bulk_transfer(zlp_xfer,
                              ctx->dev,
                              EDL_ENDPOINT_BULK_OUT,
                              (uint8_t*)"",
                              0,
                              qcomdl_xfer_cb_zlp,
                              ctx,
                              ctx->timeout);

    ctx->zlp_sent = false;
    int internal_ret = libusb_submit_transfer(zlp_xfer);
    if (internal_ret != LIBUSB_SUCCESS) {
        qcomdl_log_error("unable to submit raw_xfer: %s\n", libusb_strerror(internal_ret));
        goto exit;
    }

    while ((ctx->status != QCOMDL_XFER_ERR) && (!ctx->zlp_sent)) {
        internal_ret = qcomdl_xfer_poll();
        if (internal_ret != 0) {
            qcomdl_log_error("Failed to poll for USB events\n");
            goto exit;
        }
    }

    if (ctx->status == QCOMDL_XFER_ERR) {
        qcomdl_log_error("handle event failed with QCOMDL_XFER_ERR\n");
    }

    send_zlp_ret = 0;

exit:
    libusb_free_transfer(zlp_xfer);
    return send_zlp_ret;
}

int qcomdl_xfer_submit(qcomdl_xfer_ctx *ctx) {
    int err = libusb_submit_transfer(ctx->transfer);
    if (err) {
        qcomdl_log_error("Failed to submit USB transfer: %s\n", libusb_strerror(err));
        return -1;
    }

    if ((ctx->transfer->endpoint == EDL_ENDPOINT_BULK_OUT) &&
        (ctx->buffer_length % FIREHOSE_USB_PACKET_SIZE == 0)) {
        if (qcomdl_send_zlp(ctx) != 0) {
            ctx->status = QCOMDL_XFER_ERR;
        }
    }

    return 0;
}

int qcomdl_xfer_poll(void) {
    int err = libusb_handle_events(NULL);
    if (err) {
        qcomdl_log_error("Failed to handle USB events: %s", libusb_strerror(err));
        return -1;
    }

    return 0;
}

qcomdl_xfer_status qcomdl_xfer_get_status(qcomdl_xfer_ctx *ctx) {
    return ctx->status;
}

void qcomdl_xfer_free(qcomdl_xfer_ctx *ctx) {
    libusb_free_transfer(ctx->transfer);
    free(ctx);
}

void qcomdl_xfer_set_label(qcomdl_xfer_ctx *ctx, const char *label) {
    ctx->label = label;
}

void *qcomdl_xfer_get_buffer(qcomdl_xfer_ctx *ctx) {
    return ctx->buffer;
}

int qcomdl_xfer_get_buffer_length(qcomdl_xfer_ctx *ctx) {
    return ctx->buffer_length;
}

int qcomdl_xfer_get_actual_length(qcomdl_xfer_ctx *ctx) {
    return ctx->actual_length;
}

void *qcomdl_xfer_get_user_data(qcomdl_xfer_ctx *ctx) {
    return ctx->user_data;
}
