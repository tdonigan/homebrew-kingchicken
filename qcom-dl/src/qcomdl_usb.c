// Copyright © 2015-2017 Square, Inc. All rights reserved.

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "edl.h"
#include "qcomdl_log.h"
#include "qcomdl_usb.h"

#define QCOMDL_USB_MAX_PORT_DEPTH 7

const char *qcomdl_usb_vid_str(uint16_t vid)
{
    switch (vid) {
        case QCOMDL_USB_VID_QCOM:
        {
            return "Qualcomm";
        }

        case QCOMDL_USB_VID_SQUID:
        {
            return "Square";
        }

        default:
        {
            break;
        }
    }
    return "[Unknown VID]";
}


const char *qcomdl_usb_pid_str(uint16_t pid)
{
    switch (pid) {
        case QCOMDL_USB_PID_QCOM_XBL_RAMDUMP:
        {
            return "QCOM XBL RamDump Mode";
        }

        case QCOMDL_USB_PID_QCOM_EDL_DIAG:
        {
            return "QCOM EDL Diagnostic Mode";
        }

        case QCOMDL_USB_PID_QCOM_EDL:
        {
            return "QCOM EDL";
        }

        case QCOMDL_USB_PID_BRAN_EDL:
        {
            return "Bran EDL";
        }

        case QCOMDL_USB_PID_BRAN_SQUID_USER:
        {
            return "Bran user";
        }

        case QCOMDL_USB_PID_BRAN_SQUID_USERDEBUG:
        {
            return "Bran userdebug";
        }

        case QCOMDL_USB_PID_HODOR_EDL:
        {
            return "Hodor EDL";
        }

        case QCOMDL_USB_PID_HODOR_SQUID_USER:
        {
            return "Hodor user";
        }

        case QCOMDL_USB_PID_HODOR_SQUID_USERDEBUG:
        {
            return "Hodor userdebug";
        }

        case QCOMDL_USB_PID_T2_EDL:
        {
            return "T2 EDL";
        }

        case QCOMDL_USB_PID_T2_SQUID_USER:
        {
            return "T2 user";
        }

        case QCOMDL_USB_PID_T2_SQUID_USERDEBUG:
        {
            return "T2 userdebug";
        }

        case QCOMDL_USB_PID_X2B_BRAN_EDL:
        {
            return "X2B Bran EDL";
        }

        case QCOMDL_USB_PID_X2B_BRAN_SQUID_USER:
        {
            return "X2B Bran user";
        }

        case QCOMDL_USB_PID_X2B_BRAN_SQUID_USERDEBUG:
        {
            return "X2B Bran userdebug";
        }

        case QCOMDL_USB_PID_X2B_BRAN_SQUID_USB_DEBUG:
        {
            return "X2B Bran Secondary USB debug";
        }

        case QCOMDL_USB_PID_X2B_HODOR_EDL:
        {
            return "X2B Hodor EDL";
        }

        case QCOMDL_USB_PID_X2B_HODOR_SQUID_USER:
        {
            return "X2B Hodor user";
        }

        case QCOMDL_USB_PID_X2B_HODOR_SQUID_USERDEBUG:
        {
            return "X2B Hodor userdebug";
        }

        case QCOMDL_USB_PID_X2B_HODOR_SQUID_USB_DEBUG:
        {
            return "X2B Hodor Secondary USB debug";
        }

        case QCOMDL_USB_PID_T2B_EDL:
        {
            return "T2B EDL";
        }

        case QCOMDL_USB_PID_T2B_SQUID_USER:
        {
            return "T2B user";
        }

        case QCOMDL_USB_PID_T2B_SQUID_USERDEBUG:
        {
            return "T2B userdebug";
        }

        case QCOMDL_USB_PID_T2B_SQUID_USB_DEBUG:
        {
            return "T2B Secondary USB debug";
        }

        default:
        {
            break;
        }
    }
    return "[Unknown PID]";
}


#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
static int format_port_str(uint8_t *port_numbers, int nports, char *dst, size_t dstlen)
{
    char *c = dst;
    size_t rem = dstlen;
    for (int i = 0; i < nports; i++) {
        const char *fmt = (i == nports - 1) ? "%i" : "%i:";

        int rc = snprintf(c, rem, fmt, port_numbers[i]);
        if (rc < 0) {
            return -1;
        }
        if (rc > (int)rem) {
            return -1;
        }

        c += rc;
        rem -= (size_t)rc; // rc >= 0 here
    }

    return 0;
}
#pragma clang diagnostic pop


int qcomdl_usb_get_device_descriptor_info(libusb_device *usbdev, struct libusb_device_descriptor *desc, qcomdl_usb_device_descriptor_t *info_out)
{
    info_out->vid = desc->idVendor;
    info_out->pid = desc->idProduct;
    info_out->bus = libusb_get_bus_number(usbdev);
    info_out->port = libusb_get_port_number(usbdev);
    libusb_device_handle *devh = NULL;
    int r = libusb_open(usbdev, &devh);
    if (r != LIBUSB_SUCCESS) {
        qcomdl_log_error("Unable to libusb_open(): %s\n", libusb_strerror(r));
        return -1;
    }

    r = libusb_get_string_descriptor_ascii(devh, desc->iSerialNumber, info_out->serial, (sizeof(info_out->serial) - 1));
    if (r < 0) {
        // libusb leaves the output string alone if serial string is empty or isn't set
        // and may return an error on some platforms, which we'd like to ignore.
        info_out->serial[0] = '\0';
    }

    libusb_close(devh);

    uint8_t port_numbers[QCOMDL_USB_MAX_PORT_DEPTH];
    r = libusb_get_port_numbers(usbdev, port_numbers, QCOMDL_USB_MAX_PORT_DEPTH);
    if (r == LIBUSB_ERROR_OVERFLOW) {
        qcomdl_log_error("libusb_get_port_numbers(): %s\n", libusb_strerror(r));
        return -1;
    }

    r = format_port_str(port_numbers, r, info_out->port_str, sizeof(info_out->port_str) - 1);
    if (r != 0) {
        qcomdl_log_error("Failed to format port string\n");
        return -1;
    }

    return 0;
}


qcomdl_usb_device_status_t qcomdl_usb_get_device_info(qcomdl_usb_device_descriptor_t *dev_info, bool edl_only)
{
    libusb_device **usb_list = NULL;
    ssize_t usb_count = libusb_get_device_list(NULL, &usb_list);
    if (usb_count < 1) {
        if (usb_list) {
            libusb_free_device_list(usb_list, 1);
        }
        if (usb_count < 0) {
            qcomdl_log_error("libusb_get_device_list error: %s\n", libusb_strerror((enum libusb_error) usb_count));
        } else {
            qcomdl_log_error("No usb devices detected.\n");
        }
        return QCOMDL_DEVICE_STATUS_USB_ERROR;
    }

    if (!usb_list) {
        qcomdl_log_error("libusb_get_device_list returned null list\n");
        return QCOMDL_DEVICE_STATUS_USB_ERROR;
    }

    if (usb_count > QCOMDL_USB_MAX_ADDRESSABLE_DEVICES) {
        libusb_free_device_list(usb_list, 1);
        qcomdl_log_error("More than %i USB devices detected: usb_count = %zi\n", QCOMDL_USB_MAX_ADDRESSABLE_DEVICES, usb_count);
        return QCOMDL_DEVICE_STATUS_USB_ERROR;
    }

    bool error = false;
    size_t found = 0;

    for(ssize_t idx = 0; idx < usb_count; idx++) {
        struct libusb_device_descriptor desc;
        int r = libusb_get_device_descriptor(usb_list[idx], &desc);
        if (r != LIBUSB_SUCCESS) {
            qcomdl_log_error("Failed to get device descriptor for usb device at list index %zi - %s\n", idx, libusb_strerror(r));
            error = true;
            break;
        }

        if (qcomdl_usb_is_recognized_edl(desc.idVendor, desc.idProduct) || ((!edl_only) && qcomdl_usb_is_recognized_squid(desc.idVendor, desc.idProduct))) {
            found++;
            if (qcomdl_usb_get_device_descriptor_info(usb_list[idx], &desc, dev_info) != 0) {
                error = true;
                break;
            }
        }
    }

    libusb_free_device_list(usb_list, 1);

    if (error) {
        return QCOMDL_DEVICE_STATUS_USB_ERROR;
    }

    if (found > 1) {
        qcomdl_log_error("Multiple updateable devices found: %zu\n", found);
        return QCOMDL_DEVICE_STATUS_MULTIPLE_DEVICES_ERROR;
    }

    if (found == 1) {
        return QCOMDL_DEVICE_STATUS_SUCCESS;
    }
    
    return QCOMDL_DEVICE_STATUS_DEVICE_NOT_FOUND;
}


ssize_t qcomdl_usb_get_device_list(qcomdl_usb_device_descriptor_t ***device_list, bool edl_only)
{
    if (!device_list) {
        qcomdl_log_error("Invalid argument, device_list cannot be NULL\n");
        return -1;
    }

    *device_list = NULL;

    libusb_device **usb_list = NULL;
    ssize_t usb_count = libusb_get_device_list(NULL, &usb_list);
    if ((usb_count < 1) || (!usb_list)) {
        qcomdl_log_error("No usb devices found: usb_count=%zi\n", usb_count);
        if (usb_list) {
            libusb_free_device_list(usb_list, 1);
        }
        return -1;
    }

    if (usb_count > QCOMDL_USB_MAX_ADDRESSABLE_DEVICES) {
        qcomdl_log_error("More than %i USB devices detected: usb_count=%zi\n", QCOMDL_USB_MAX_ADDRESSABLE_DEVICES, usb_count);
        if (usb_list) {
            libusb_free_device_list(usb_list, 1);
        }
        return -1;
    }

    // Allocate enough pointers to accomodate every usb device being an EDL device.
    // We will probably never actually have every usb device be EDL, but we only have to sweep the
    // list once this way.
    qcomdl_usb_device_descriptor_t **found_devices = calloc((size_t)(usb_count + 1), sizeof(qcomdl_usb_device_descriptor_t*));
    if (!found_devices) {
        qcomdl_log_error("Unable to allocate %zu bytes for EDL device descriptors list: %s\n",
                         (sizeof(qcomdl_usb_device_descriptor_t*) * (size_t)(usb_count+1)),
                         strerror(errno));
        libusb_free_device_list(usb_list, 1);
        return -1;
    }

    ssize_t found_count = 0;

    ssize_t idx;
    for (idx = 0; idx < usb_count; idx++) {
        struct libusb_device_descriptor desc;
        int r = libusb_get_device_descriptor(usb_list[idx], &desc);
        if (r < 0) {
            qcomdl_log_error("Failed to get device descriptor for usb device at index %zi\n", idx);
            found_count = -1;
            break;
        }

        if (qcomdl_usb_is_recognized_edl(desc.idVendor, desc.idProduct) || ((!edl_only) && qcomdl_usb_is_recognized_squid(desc.idVendor, desc.idProduct))) {
            qcomdl_usb_device_descriptor_t *tmp = calloc(1, sizeof(qcomdl_usb_device_descriptor_t));
            if (!tmp) {
                qcomdl_log_error("Unable to allocate a device descriptor: %s\n", strerror(errno));
                found_count = -1;
                break;
            }

            if (qcomdl_usb_get_device_descriptor_info(usb_list[idx], &desc, tmp) == 0) {
                found_devices[found_count] = tmp;
                found_count++;
            } else {
                qcomdl_log_error("Failed to get device info for usb device at index %zi\n", idx);
                found_count = -1;
                break;
            }
        }
    }

    libusb_free_device_list(usb_list, 1);

    if (found_count > 0) {
        *device_list = found_devices;
        return found_count;
    } else if ((idx == usb_count) && (found_count == 0)) {
        qcomdl_log_info("No EDL devices found\n");
    }

    qcomdl_usb_free_device_list(found_devices);
    *device_list = NULL;
    return found_count;
}


void qcomdl_usb_free_device_list(qcomdl_usb_device_descriptor_t **device_list)
{
    if (device_list) {
        for (size_t i = 0; device_list[i] != NULL; i++) {
            free(device_list[i]);
        }
    }
    free(device_list);
}


bool qcomdl_usb_is_recognized_edl(uint16_t vid, uint16_t pid)
{
    switch (QCOMDL_USBIDENTIFIER(vid, pid)) {
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_QCOM, QCOMDL_USB_PID_QCOM_EDL):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_QCOM, QCOMDL_USB_PID_QCOM_EDL_DIAG):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_QCOM, QCOMDL_USB_PID_QCOM_XBL_RAMDUMP):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_BRAN_EDL):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_HODOR_EDL):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_T2_EDL):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_X2B_BRAN_EDL):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_X2B_HODOR_EDL):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_T2B_EDL):
        {
            return true;
        }
        default:
        {
            return false;
        }
    }
}


bool qcomdl_usb_is_recognized_squid(uint16_t vid, uint16_t pid)
{
    switch (QCOMDL_USBIDENTIFIER(vid, pid)) {
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_BRAN_SQUID_USER):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_BRAN_SQUID_USERDEBUG):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_HODOR_SQUID_USER):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_HODOR_SQUID_USERDEBUG):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_T2_SQUID_USER):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_T2_SQUID_USERDEBUG):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_X2B_BRAN_SQUID_USER):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_X2B_BRAN_SQUID_USERDEBUG):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_X2B_BRAN_SQUID_USB_DEBUG):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_X2B_HODOR_SQUID_USER):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_X2B_HODOR_SQUID_USERDEBUG):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_X2B_HODOR_SQUID_USB_DEBUG):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_T2B_SQUID_USER):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_T2B_SQUID_USERDEBUG):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_T2B_SQUID_USB_DEBUG):

        {
            return true;
        }
        default:
        {
            return false;
        }
    }
}
