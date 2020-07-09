// Copyright 2018 Square, Inc.
#pragma once

#include <libusb.h>
#include <stdint.h>

#include "edl.h"

struct qcomdl_xfer_ctx;
typedef struct qcomdl_xfer_ctx qcomdl_xfer_ctx;

typedef void (qcomdl_xfer_cb)(qcomdl_xfer_ctx *ctx);

typedef enum {
    QCOMDL_XFER_PENDING,
    QCOMDL_XFER_CANCELLED,
    QCOMDL_XFER_COMPLETED,
    QCOMDL_XFER_ERR,
} qcomdl_xfer_status;

// Creates qcomdl_xfer_ctx context struct that stores data (buffers, callback, etc)
// and state needed to send/receive data from/to device.
//
// Returns -- success: allocated qcomdl_xfer_ctx; failure: NULL
qcomdl_xfer_ctx *qcomdl_xfer_ctx_create(libusb_device_handle *dev,
                                         uint8_t endpoint,
                                         void *buffer,
                                         int length,
                                         qcomdl_xfer_cb callback,
                                         void *user_data,
                                         unsigned timeout,
                                         const char *label);

// Function that submits libusb_transfer (part of qcomdl_xfer_ctx) in order to request
// USB transfer for device.
//
// Returns -- success: 0; failure: -1
int qcomdl_xfer_submit(qcomdl_xfer_ctx *ctx);

// Polls for USB events.
//
// Returns -- success: 0; failure: -1
int qcomdl_xfer_poll(void);

void qcomdl_xfer_free(qcomdl_xfer_ctx *ctx);

qcomdl_xfer_status qcomdl_xfer_get_status(qcomdl_xfer_ctx *ctx);

void qcomdl_xfer_set_label(qcomdl_xfer_ctx *ctx, const char *label);

void *qcomdl_xfer_get_buffer(qcomdl_xfer_ctx *ctx);

int qcomdl_xfer_get_buffer_length(qcomdl_xfer_ctx *ctx);

int qcomdl_xfer_get_actual_length(qcomdl_xfer_ctx *ctx);

void *qcomdl_xfer_get_user_data(qcomdl_xfer_ctx *ctx);
