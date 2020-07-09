#include <stdlib.h>
#include <stdio.h>

#include <libusb.h>
#include <yaml.h>

#include "edl.h"
#include "qcomdl_build_info.h"
#include "qcomdl_log.h"
#include "qcomdl_usb.h"
#include "resource.h"

qcomdl_build_info_t *qcomdl_parse_build_info(qcomdl_resource_package_t *package)
{
    yaml_parser_t parser;
    yaml_event_t event;
    yaml_parser_initialize(&parser);

    // open the build info file
    qcomdl_resource_file_t *file = qcomdl_fopen(package, package->full_dir, BUILD_INFO_FILE_NAME, "r");
    if (!file) {
        qcomdl_log_error("Unable to open the build_info file\n");
        return NULL;
    }

    // the entire file will be read to a buffer
    char *file_buffer = malloc(file->size);
    if (!file_buffer) {
        qcomdl_log_error("Could create yaml file buffer.\n");
        return NULL;
    }

    qcomdl_build_info_t *build_info = calloc(1, sizeof(qcomdl_build_info_t));
    if (!build_info) {
        qcomdl_log_error("Unable to allocate qcomdl_build_info_t - %s\n", strerror(errno));
        free(file_buffer);
        return NULL;
    }

    // read the entire yaml file to initialize the parser
    size_t size_read = qcomdl_fread((void *)file_buffer, 1, file->size, file);
    if (size_read != file->size) {
        qcomdl_log_error("Did not read all of the yaml file.\n");
        goto yaml_error;
    }
    yaml_parser_set_input_string(&parser, (unsigned char *)file_buffer, size_read);

    // parse the scalar events, record chipset and product information
    do {
        if (!yaml_parser_parse(&parser, &event)) {
            qcomdl_log_error("Error parsing yaml.\n");
            goto yaml_error;
        }

        if (event.type == YAML_SCALAR_EVENT) {
            // retrieve the key
            char key[YAML_STRING_MAX];
            strncpy(key, (char *)event.data.scalar.value, YAML_STRING_MAX);

            // parse the next event and retrieve the value
            if (!yaml_parser_parse(&parser, &event)) {
                qcomdl_log_error("Error parsing yaml.\n");
                goto yaml_error;
            }

            if (event.type == YAML_SCALAR_EVENT) {
                if (strcmp(key, "chipset") == 0) {
                    strncpy(build_info->chipset_type, (char *)event.data.scalar.value, sizeof(build_info->chipset_type));
                }
                else if (strcmp(key, "product") == 0) {
                    strncpy(build_info->product_type, (char *)event.data.scalar.value, sizeof(build_info->product_type));
                }
            }
        }
    } while (event.type != YAML_NO_EVENT);

goto yaml_teardown;

yaml_error:
    free(build_info);
    build_info = NULL;

yaml_teardown:
    qcomdl_fclose(file);
    free(file_buffer);
    yaml_parser_delete(&parser);
    return build_info;
}

int qcomdl_build_matches_product(struct libusb_device_descriptor *usb_desc, qcomdl_build_info_t *build_info)
{
    // confirm that the connected device is compatible the the build provided
    switch (QCOMDL_USBIDENTIFIER(usb_desc->idVendor, usb_desc->idProduct)) {
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_BRAN_EDL):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_BRAN_SQUID_USER):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_BRAN_SQUID_USERDEBUG):
        {
            if ((strcmp(build_info->chipset_type, "msm8916_64") != 0) ||
                (strcmp(build_info->product_type, "bran")       != 0)) {
                return -ENODEV;
            }
            break;
        }
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_HODOR_EDL):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_HODOR_SQUID_USER):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_HODOR_SQUID_USERDEBUG):
        {
            if ((strcmp(build_info->chipset_type, "msm8916_64") != 0) ||
                (strcmp(build_info->product_type, "hodor")      != 0)) {
                return -ENODEV;
            }
            break;
        }
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_T2_EDL):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_T2_SQUID_USER):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_T2_SQUID_USERDEBUG):
        {
            if ((strcmp(build_info->chipset_type, "msm8916_64") != 0) ||
                (strcmp(build_info->product_type, "t2")         != 0)) {
                return -ENODEV;
            }
            break;
        }
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_X2B_BRAN_EDL):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_X2B_BRAN_SQUID_USER):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_X2B_BRAN_SQUID_USERDEBUG):
        {
            if ((strcmp(build_info->chipset_type, "sdm660_64") != 0) ||
                (strcmp(build_info->product_type, "bran")      != 0)) {
                return -ENODEV;
            }
            break;
        }
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_X2B_HODOR_EDL):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_X2B_HODOR_SQUID_USER):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_X2B_HODOR_SQUID_USERDEBUG):
        {
            if ((strcmp(build_info->chipset_type, "sdm660_64") != 0) ||
                (strcmp(build_info->product_type, "hodor")     != 0)) {
                return -ENODEV;
            }
            break;
        }
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_T2B_EDL):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_T2B_SQUID_USER):
        case QCOMDL_USBIDENTIFIER(QCOMDL_USB_VID_SQUID, QCOMDL_USB_PID_T2B_SQUID_USERDEBUG):
        {
            if ((strcmp(build_info->chipset_type, "sdm660_64") != 0) ||
                (strcmp(build_info->product_type, "t2")        != 0)) {
                return -ENODEV;
            }
            break;
        }
        default:
        {
            // an unknown USB identifier or an unfused device should not be a failure condition
            // maintain compatibility with these devices and allow a flashing attempt
            qcomdl_log_warning("Unknown Squid Device:\n"
                               "\tVID=0x%.4x\n"
                               "\tPID=0x%.4x\n"
                               "\tdesc=(%s - %s)\n",
                               usb_desc->idVendor,
                               usb_desc->idProduct,
                               qcomdl_usb_vid_str(usb_desc->idVendor),
                               qcomdl_usb_pid_str(usb_desc->idProduct));
        }
    }

    return 0;
}
