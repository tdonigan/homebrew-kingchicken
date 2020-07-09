#include "edl.h"
#include "resource.h"

#define YAML_STRING_MAX 256
#define BUILD_INFO_FILE_NAME "build_info.yml"

struct qcomdl_build_info {
    char chipset_type[YAML_STRING_MAX];
    char product_type[YAML_STRING_MAX];
};

typedef struct qcomdl_build_info qcomdl_build_info_t;

/*
 * Parses the build info file
 *
 * @param  file_path    build info file path
 * @return              build info structure
 */
qcomdl_build_info_t *qcomdl_parse_build_info(qcomdl_resource_package_t *package);

/*
 * Determines if the build and connected prouduct are compatible
 *
 * @param  usb_desc     libusb_device_descriptor providing the VID/PID of the device
 * @param  build_info   qcomdl_build_info_t providing the chipset and product of the build
 * @return              error code, 0 for success
 */
int qcomdl_build_matches_product(struct libusb_device_descriptor *usb_desc, qcomdl_build_info_t *build_info);
