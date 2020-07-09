// Copyright © 2015-2017 Square, Inc. All rights reserved.

#pragma once

#include <libusb.h>
#include <stdint.h>
#include <stdbool.h>

#include <qcomdl.h>
#include <qcomdl_usb.h>

#define EDL_INTERFACE_NUM 0
#define EDL_CONFIGURATION_NUM 1

#define EDL_ENDPOINT_BULK_IN        ((uint8_t) 0x81)
#define EDL_ENDPOINT_BULK_OUT       ((uint8_t) 0x01)

struct edl_connection {
    libusb_device_handle *usb_dev;
    bool needs_reattach;
};

typedef struct edl_connection edl_connection_t;

QCOMDL_API
edl_connection_t *edl_connect(void);

QCOMDL_API
edl_connection_t *edl_diag_connect(void);


QCOMDL_API
edl_connection_t *edl_connect_bus_and_port(uint8_t bus, uint8_t address);

QCOMDL_API
edl_connection_t *edl_connect_bus_and_port_path(uint8_t bus, const char *port_path);

QCOMDL_API
int edl_disconnect(edl_connection_t *conn);
