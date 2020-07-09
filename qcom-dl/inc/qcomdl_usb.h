// Copyright © 2015-2017 Square, Inc. All rights reserved.

#pragma once

#include <libusb.h>
#include <stdbool.h>
#include <stdint.h>

#define QCOMDL_USB_VID_QCOM                            ((uint16_t) 0x05C6)
#define QCOMDL_USB_VID_SQUID                           ((uint16_t) 0x27a8)

#define QCOMDL_USB_PID_QCOM_EDL                        ((uint16_t) 0x9008)
#define QCOMDL_USB_PID_QCOM_EDL_DIAG                   ((uint16_t) 0x9006)
#define QCOMDL_USB_PID_QCOM_XBL_RAMDUMP                ((uint16_t) 0x900e)

// MSM8916 "A" Devices
#define QCOMDL_USB_PID_BRAN_EDL                        ((uint16_t) 0x4200)
#define QCOMDL_USB_PID_BRAN_SQUID_USER                 ((uint16_t) 0x4201)
#define QCOMDL_USB_PID_BRAN_SQUID_USERDEBUG            ((uint16_t) 0x4202)

#define QCOMDL_USB_PID_HODOR_EDL                       ((uint16_t) 0x4800)
#define QCOMDL_USB_PID_HODOR_SQUID_USER                ((uint16_t) 0x4801)
#define QCOMDL_USB_PID_HODOR_SQUID_USERDEBUG           ((uint16_t) 0x4802)

#define QCOMDL_USB_PID_T2_EDL                          ((uint16_t) 0x5400)
#define QCOMDL_USB_PID_T2_SQUID_USER                   ((uint16_t) 0x5401)
#define QCOMDL_USB_PID_T2_SQUID_USERDEBUG              ((uint16_t) 0x5402)

// SDA660 "B" Devices
#define QCOMDL_USB_PID_X2B_BRAN_EDL                    ((uint16_t) 0x4220)
#define QCOMDL_USB_PID_X2B_BRAN_SQUID_USER             ((uint16_t) 0x4221)
#define QCOMDL_USB_PID_X2B_BRAN_SQUID_USERDEBUG        ((uint16_t) 0x4222)
#define QCOMDL_USB_PID_X2B_BRAN_SQUID_USB_DEBUG        ((uint16_t) 0x4223)

#define QCOMDL_USB_PID_X2B_HODOR_EDL                   ((uint16_t) 0x4820)
#define QCOMDL_USB_PID_X2B_HODOR_SQUID_USER            ((uint16_t) 0x4821)
#define QCOMDL_USB_PID_X2B_HODOR_SQUID_USERDEBUG       ((uint16_t) 0x4822)
#define QCOMDL_USB_PID_X2B_HODOR_SQUID_USB_DEBUG       ((uint16_t) 0x4823)

#define QCOMDL_USB_PID_T2B_EDL                         ((uint16_t) 0x5420)
#define QCOMDL_USB_PID_T2B_SQUID_USER                  ((uint16_t) 0x5421)
#define QCOMDL_USB_PID_T2B_SQUID_USERDEBUG             ((uint16_t) 0x5422)
#define QCOMDL_USB_PID_T2B_SQUID_USB_DEBUG             ((uint16_t) 0x5423)

#define QCOMDL_USB_SERIAL_STRING_BUF_SIZE 256
#define QCOMDL_USB_PORT_STRING_BUF_SIZE 256

#define QCOMDL_USB_MAX_ADDRESSABLE_DEVICES 65535 // Maximum addressable number of usb devices

typedef uint8_t qcomdl_usb_string_t[QCOMDL_USB_SERIAL_STRING_BUF_SIZE];
typedef char qcomdl_usb_port_string_t[QCOMDL_USB_PORT_STRING_BUF_SIZE];

typedef struct {
    uint8_t bus;
    uint8_t port;
    uint16_t vid;
    uint16_t pid;
    qcomdl_usb_string_t serial;
    qcomdl_usb_port_string_t port_str;
} qcomdl_usb_device_descriptor_t;


typedef enum {
    QCOMDL_DEVICE_STATUS_USB_ERROR = -1,
    QCOMDL_DEVICE_STATUS_MULTIPLE_DEVICES_ERROR = -2,
    QCOMDL_DEVICE_STATUS_SUCCESS = 0,
    QCOMDL_DEVICE_STATUS_DEVICE_NOT_FOUND = 1,
} qcomdl_usb_device_status_t;

#define QCOMDL_USBIDENTIFIER(vid, pid) (((uint32_t)(vid) << 16) + (pid))
#define QCOMDL_USBIDENTIFIER_VID(usbident) ((uint16_t)((usbident) >> 16))
#define QCOMDL_USBIDENTIFIER_PID(usbident) ((uint16_t)((usbident) & 0xFFFF))

const char *qcomdl_usb_vid_str(uint16_t vid);

const char *qcomdl_usb_pid_str(uint16_t pid);

int qcomdl_usb_get_device_descriptor_info(libusb_device *usbdev, struct libusb_device_descriptor *desc, qcomdl_usb_device_descriptor_t *info_out);

// qcomdl_usb_get_device_info provides info on a single device and returns an error if multiple ones are present.
// allocation of device info is up to the caller (unlike qcomdl_usb_get_edl_device_list)
qcomdl_usb_device_status_t qcomdl_usb_get_device_info(qcomdl_usb_device_descriptor_t *dev_info, bool edl_only);

// qcomdl_usb_get_edl_device_list lists all devices present. use qcomdl_usb_free_device_list to free the device_list it allocates
ssize_t qcomdl_usb_get_device_list(qcomdl_usb_device_descriptor_t ***device_list, bool edl_only);
void qcomdl_usb_free_device_list(qcomdl_usb_device_descriptor_t **device_list);

bool qcomdl_usb_is_recognized_edl(uint16_t vid, uint16_t pid);
bool qcomdl_usb_is_recognized_squid(uint16_t vid, uint16_t pid);
