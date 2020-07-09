// Copyright © 2015-2017 Square, Inc. All rights reserved.

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "edl.h"
#include "qcomdl_usb.h"
#include "qcomdl_log.h"

#pragma mark Private (static) functions

static int edl_connect_do(edl_connection_t *conn)
{
    int rc = LIBUSB_SUCCESS;

    conn->needs_reattach = false;

    rc = libusb_kernel_driver_active(conn->usb_dev, EDL_INTERFACE_NUM);
    if (rc == 1) {
        rc = libusb_detach_kernel_driver(conn->usb_dev, EDL_INTERFACE_NUM);
        if (rc == LIBUSB_SUCCESS) {
            qcomdl_log_debug("Detached kernel driver from USB device interface %i\n", EDL_CONFIGURATION_NUM);
            conn->needs_reattach = true;
        } else if (rc != LIBUSB_ERROR_NOT_FOUND) {
            qcomdl_log_error("Could not detach kernel driver from USB device interface %i - %s\n", EDL_INTERFACE_NUM, libusb_strerror(rc));
            return -1;
        }
    }

    int cur_config = -1;
    rc = libusb_get_configuration(conn->usb_dev, &cur_config);
    if (rc != LIBUSB_SUCCESS) {
        qcomdl_log_error("Cannot get current USB device configuration: (%i) %s", rc, libusb_strerror(rc));
        return -1;
    }

    if (cur_config == EDL_CONFIGURATION_NUM) {
        qcomdl_log_debug("Device already in EDL configuration %i\n", EDL_CONFIGURATION_NUM);
    } else {
        // The call to set_configuration must precede the call to claim_interface below
        rc = libusb_set_configuration(conn->usb_dev, EDL_CONFIGURATION_NUM);
        if (rc != LIBUSB_SUCCESS) {
            qcomdl_log_error("Cannot set EDL configuration %i - (%i) %s\n", EDL_CONFIGURATION_NUM, rc, libusb_strerror(rc));
            return -1;
        }

        qcomdl_log_debug("Set EDL configuration %i\n", EDL_CONFIGURATION_NUM);
    }

     rc = libusb_claim_interface(conn->usb_dev, EDL_INTERFACE_NUM);
    if (rc != LIBUSB_SUCCESS) {
        qcomdl_log_error("Cannot claim EDL interface %i - (%i) %s\n", EDL_INTERFACE_NUM, rc, libusb_strerror(rc));
        return -1;
    }
    qcomdl_log_debug("Claimed EDL interface interface: %i\n", EDL_INTERFACE_NUM);

    return 0;
}


static libusb_device_handle *open_device_with_bus_and_port(uint8_t bus, uint8_t port)
{
    libusb_device_handle *found = NULL;

    libusb_device **usb_list = NULL;
    ssize_t usb_count = libusb_get_device_list(NULL, &usb_list);
    if (usb_count < 1) {
        qcomdl_log_info("No usb devices found: usb_count=%zi\n", usb_count);
        if (usb_list) {
            libusb_free_device_list(usb_list, 1);
        }
        return NULL;
    }

    ssize_t idx;
    for (idx = 0; idx < usb_count; idx++) {
        uint8_t cur_bus = libusb_get_bus_number(usb_list[idx]);
        uint8_t cur_port = libusb_get_port_number(usb_list[idx]);

        if (bus == cur_bus && port == cur_port) {
            struct libusb_device_descriptor desc;
            int r = libusb_get_device_descriptor(usb_list[idx], &desc);
            if (r != LIBUSB_SUCCESS) {
                qcomdl_log_error("Failed to get device descriptor for usb device at index %zi - %s\n", idx, libusb_strerror(r));
                break;
            }

            if (!qcomdl_usb_is_recognized_edl(desc.idVendor, desc.idProduct)) {
                qcomdl_log_error("USB device at bus=%i/port=%i is not a recognized EDL device: vid:%04x/pid:%04x\n",
                                 cur_bus, cur_port,
                                 desc.idVendor, desc.idProduct);
                break;
            }

            r = libusb_open(usb_list[idx], &found);
            if (r != LIBUSB_SUCCESS) {
                qcomdl_log_error("Unable to open EDL device at bus=%i/port=%i - %s\n", cur_bus, cur_port, libusb_strerror(r));
            }

            break;

        }
    }

    libusb_free_device_list(usb_list, 1);

    if ((idx == usb_count) && (!found)) {
        qcomdl_log_error("Unable to find a USB device attached at bus=%i/port=%i\n", bus, port);
    }

    return found;
}


static libusb_device_handle *open_device_with_bus_and_port_path(uint8_t bus, const char *port_path)
{
    libusb_device_handle *found = NULL;

    libusb_device **usb_list = NULL;
    ssize_t usb_count = libusb_get_device_list(NULL, &usb_list);
    if (usb_count < 1) {
        qcomdl_log_info("No usb devices found: usb_count=%zi\n", usb_count);
        if (usb_list) {
            libusb_free_device_list(usb_list, 1);
        }
        return NULL;
    }

    ssize_t idx;
    for (idx = 0; idx < usb_count; idx++) {
        qcomdl_usb_device_descriptor_t qcomdl_desc;
        struct libusb_device_descriptor desc;

        int r = libusb_get_device_descriptor(usb_list[idx], &desc);
        if (r != LIBUSB_SUCCESS) {
            qcomdl_log_error("Failed to get device descriptor for usb device at index %zi - %s\n", idx, libusb_strerror(r));
            break;
        }

        if (!qcomdl_usb_is_recognized_edl(desc.idVendor, desc.idProduct)) {
            qcomdl_log_debug("USB device at bus=%i/port=%s is not a recognized EDL device: vid:%04x/pid:%04x\n",
                    qcomdl_desc.bus, qcomdl_desc.port_str,
                    desc.idVendor, desc.idProduct);
            continue;
        }

        r = qcomdl_usb_get_device_descriptor_info(usb_list[idx], &desc, &qcomdl_desc);
        if (r != 0) {
            qcomdl_log_error("Failed to get get descriptor info for usb device at index %zi\n", idx);
            break;
        }

        if (bus == qcomdl_desc.bus && 0 == strcmp(port_path, qcomdl_desc.port_str)) {
            r = libusb_open(usb_list[idx], &found);
            if (r != LIBUSB_SUCCESS) {
                qcomdl_log_error("Unable to open EDL device at bus=%i/port=%s - %s\n", qcomdl_desc.bus, qcomdl_desc.port_str, libusb_strerror(r));
            }

            break;

        }
    }

    libusb_free_device_list(usb_list, 1);

    if ((idx == usb_count) && (!found)) {
        qcomdl_log_error("Unable to find a USB device attached at bus=%i/port=%s\n", bus, port_path);
    }

    return found;
}


static edl_connection_t *edl_connect_vid_pid(uint16_t vid, uint16_t pid)
{
    edl_connection_t *conn = calloc(1, sizeof(edl_connection_t));
    if (!conn) {
        qcomdl_log_error("Unable to allocate an EDL connection - %s\n", strerror(errno));
        return NULL;
    }

    libusb_device_handle *usb_dev = libusb_open_device_with_vid_pid(NULL, vid, pid);
    if (!usb_dev) {
        qcomdl_log_error("Could not connect to device with vid:%04x/pid:%04x\n", vid, pid);
        free(conn);
        return NULL;
    }

    conn->usb_dev = usb_dev;

    if (edl_connect_do(conn) != 0) {
        edl_disconnect(conn);
        return NULL;
    }

    return conn;
}


#pragma mark Public functions

edl_connection_t *edl_connect(void)
{
    qcomdl_usb_device_descriptor_t **device_list = NULL;
    ssize_t len = qcomdl_usb_get_device_list(&device_list, true);
    edl_connection_t *conn = NULL;
    bool found = false;
    // connect to first device that is NOT in EDL DIAG mode
    for (ssize_t i = 0; i < len; i++) {
        uint16_t vid = device_list[i]->vid;
        uint16_t pid = device_list[i]->pid;
        if (vid == QCOMDL_USB_VID_QCOM) {
            if ((pid == QCOMDL_USB_PID_QCOM_EDL_DIAG) ||
                (pid == QCOMDL_USB_PID_QCOM_XBL_RAMDUMP)) {
                continue;
            }
        }
        found = true;
        conn = edl_connect_vid_pid(vid, pid);
        break;
    }
    qcomdl_usb_free_device_list(device_list);
    if (!found) {
        qcomdl_log_error("Unable to connect to EDL - no suitable USB device found\n");
    }
    return conn;
}


edl_connection_t *edl_diag_connect(void)
{
    edl_connection_t *conn;
    conn = edl_connect_vid_pid(QCOMDL_USB_VID_QCOM, QCOMDL_USB_PID_QCOM_EDL_DIAG);
    if (!conn) {
        conn = edl_connect_vid_pid(QCOMDL_USB_VID_QCOM, QCOMDL_USB_PID_QCOM_XBL_RAMDUMP);
    }

    return conn;
}


edl_connection_t *edl_connect_bus_and_port(uint8_t bus, uint8_t port)
{

    edl_connection_t *conn = calloc(1, sizeof(edl_connection_t));
    if (!conn) {
        qcomdl_log_error("Unable to allocate an EDL connection - %s\n", strerror(errno));
        return NULL;
    }

    libusb_device_handle *usb_dev = open_device_with_bus_and_port(bus, port);
    if (!usb_dev) {
        free(conn);
        return NULL;
    }

    conn->usb_dev = usb_dev;
    if (edl_connect_do(conn) != 0) {
        edl_disconnect(conn);
        return NULL;
    }

    return conn;
}


edl_connection_t *edl_connect_bus_and_port_path(uint8_t bus, const char *port_path)
{

    edl_connection_t *conn = calloc(1, sizeof(edl_connection_t));
    if (!conn) {
        qcomdl_log_error("Unable to allocate an EDL connection - %s\n", strerror(errno));
        return NULL;
    }

    libusb_device_handle *usb_dev = open_device_with_bus_and_port_path(bus, port_path);
    if (!usb_dev) {
        free(conn);
        return NULL;
    }

    conn->usb_dev = usb_dev;
    if (edl_connect_do(conn) != 0) {
        edl_disconnect(conn);
        return NULL;
    }

    return conn;
}

int edl_disconnect(edl_connection_t *conn)
{
    if (!conn) {
        return 0;
    }

    int ret = 0;
    int rc = -1;

    if (conn->usb_dev) {
        qcomdl_log_debug("Releasing EDL Interface Number: %i\n", EDL_INTERFACE_NUM);
        rc = libusb_release_interface(conn->usb_dev, EDL_INTERFACE_NUM);
        if (rc == LIBUSB_ERROR_NO_DEVICE) {
            qcomdl_log_warning("Device not attached\n");
        } else if (rc != LIBUSB_SUCCESS) {
            qcomdl_log_error("There was an error releasing the EDL interface - (%i) %s\n", rc, libusb_strerror(rc));
            ret = -1;
        }

        if (conn->needs_reattach) {
            rc = libusb_attach_kernel_driver(conn->usb_dev, EDL_INTERFACE_NUM);
            if (rc == LIBUSB_ERROR_NO_DEVICE) {
                qcomdl_log_warning("Device not attached\n");
            } else if (rc != LIBUSB_SUCCESS) {
                qcomdl_log_error("There was an error re-attaching the kernel driver: (%i) %s\n", rc, libusb_strerror(rc));
                ret = -1;
            }
        }

        qcomdl_log_debug("Closing EDL Device\n");
        libusb_close(conn->usb_dev);
    }

    free(conn);
    return ret;
}
