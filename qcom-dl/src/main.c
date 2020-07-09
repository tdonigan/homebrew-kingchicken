// Copyright © 2015-2017 Square, Inc. All rights reserved.

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <libgen.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <libusb.h>

#include "edl.h"
#include "sahara.h"
#include "firehose.h"
#include "qcomdl_build_info.h"
#include "qcomdl_log.h"
#include "qcomdl_usb.h"

// Windows "sleep" function is capitalized and takes milliseconds, because windows!
#if defined(_WIN32) || defined(__CYGWIN__)
#define sleep_func(sec) Sleep((sec) * 1000)
#else
#define sleep_func(sec) sleep(sec)
#endif

static struct {
    qcomdl_log_level_t loglevel;
    int usb_loglevel; // see LIBUSB_LOG_LEVEL_*
    char image_path[PATH_MAX]; // path to directory containing built/flashable image files and xml
    const char *firehose_bin; // filename of firehose executable
    const char *program_xml; // filename of program.xml file
    const char *patch_xml; // filename of patch.xml file
    int firehose_verbose; // enable extra logging from target
    int firehose_payload_sz; // autonegotiated, this is the initial value proposed during negotiation
    int firehose_program_read_back_verify; // set to 1 for read_back_verify on each <progam> command. This is slow
    int firehose_skip_write;
    bool firehose_erase; // toggle erasing flash before writing to it
    bool info_only;  // toggle just printing sahara info and resetting the device
    bool sha256_digests;  // perform a sha256 for each <program> command after programming completes
    bool usb_info;  // toggle usb device query
    bool list;  // toggle listing
    bool percent_progress; // toggle whether to display percent progress
    bool ignore_tty;  // ignore whether stdout is a tty for output purposes
    bool vip;  // toggle Validated Image Programming
    const char *vip_xml;   // filename to use for vip messages xml configuration
    const char *vip_digest_table;  // filename to use for vip signed digest table
    const char *vip_chained_digests;  // filename to use for vip chained digests
    bool firehose_rpmb_erase;  // toggle erasing RPMB flash
    bool verify_vip;  // toggle VIP verification
    int bus; // bus of device to program
    const char *port; // port of device to program
} s_args = {
    .loglevel = QCOMDL_LOG_LEVEL_WARNING,
    .usb_loglevel = LIBUSB_LOG_LEVEL_WARNING,
    .firehose_bin = NULL,
    .program_xml = FIREHOSE_DEFAULT_PROGRAM_XML_FILENAME,
    .patch_xml = FIREHOSE_DEFAULT_PATCH_XML_FILENAME,
    .firehose_payload_sz = FIREHOSE_DEFAULT_PAYLOAD_SIZE,
    .firehose_verbose = 0,
    .firehose_program_read_back_verify = 0,
    .firehose_skip_write = 0,
    .firehose_erase = true,
    .info_only = false,
    .sha256_digests = false,
    .list = false,
    .vip = false,
    .vip_xml = FIREHOSE_DEFAULT_VIP_XML_FILENAME,
    .vip_digest_table = FIREHOSE_DEFAULT_DIGEST_TABLE_FILENAME,
    .vip_chained_digests = FIREHOSE_DEFAULT_CHAINED_DIGESTS_FILENAME,
    .percent_progress = true,
    .ignore_tty = false,
    .firehose_rpmb_erase = false,
    .verify_vip = false,
    .bus = -1,
    .port = NULL,
};

static char *progname = NULL;


static const char *option_flags = "f:p:P:DeEisUlvqtuVSMTChrb:O:";


static void usage(FILE *outf)
{
    fprintf(outf, "usage: %s [-%s] <zipfile or path/to/images>\n", basename(progname), option_flags);
    fprintf(outf, "  Options (all apply both in Validated and Unvalidated modes\n");
    fprintf(outf, "    -f, --firehose-bin=<FILE>  Firehose loader filename\n");
    fprintf(outf, "                                 Non-VIP Defaults: %s\n", FIREHOSE_DEFAULT_BIN_APQ8039);
    fprintf(outf, "                                                   %s\n", FIREHOSE_DEFAULT_BIN_SDA660);
    fprintf(outf, "                                 VIP Defaults:     %s\n", FIREHOSE_DEFAULT_VIP_BIN_APQ8039);
    fprintf(outf, "                                                   %s\n", FIREHOSE_DEFAULT_VIP_BIN_SDA660);
    fprintf(outf, "    -i, --info-only            Display Sahara debug info and exit. Other options/args ignored\n");
    fprintf(outf, "    -v, --verbose              Increase qcom-dl logging verbosity (use multiple times for increased effect)\n");
    fprintf(outf, "    -q, --quiet                Disable percent progress output\n");
    fprintf(outf, "    -t, --ignore-tty           Ignore whether stdout is a tty for output purposes\n");
    fprintf(outf, "    -l, --list                 List connected devices and exit. Other options/args ignored. Overrides -i\n");
    fprintf(outf, "    -U, --usb-query            Query for a connected SQUID or EDL device. Other options/args ignored. Overrides -i\n");
    fprintf(outf, "    -u, --usb-verbose          Increase USB logging verbosity (use multiple times for increased effect)\n");
    fprintf(outf, "    -V, --version              Print version and exit\n");
    fprintf(outf, "\n");

    fprintf(outf, "  Unvalidated Image Programming Options (Ignored when VIP mode is enabled with -S):\n");
    fprintf(outf, "    -p, --program-xml=<FILE>   Program xml filename. (Default: %s)\n", FIREHOSE_DEFAULT_PROGRAM_XML_FILENAME);
    fprintf(outf, "    -P, --patch-xml=<FILE>     Patch xml filename. (Default: %s)\n", FIREHOSE_DEFAULT_PATCH_XML_FILENAME);
    fprintf(outf, "    -D, --dry-run              Dry run using SkipWrite=1 on program.xml. (patch xml is also skipped)\n");
    fprintf(outf, "    -e, --erase                Erase flash before writing. This is the default.\n");
    fprintf(outf, "    -E, --no-erase             Disable erasing flash before writing.\n");
    fprintf(outf, "    -s, --sha256digests        Perform a sha256 digest for each <program> command. (Default: disabled)\n");
    fprintf(outf, "    -r, --rpmb-erase           Erase RPMB flash before writing.\n");
    fprintf(outf, "\n");

    fprintf(outf, "  Validated Image Programming (VIP) Options (Ignored when -S is not specified)\n");
    fprintf(outf, "    -S, --vip                  Enable Validated Image Programming (VIP) with signed image digests\n");
    fprintf(outf, "    -M, --vip-messages-xml     VIP messages xml filename (Default: %s)\n", FIREHOSE_DEFAULT_VIP_XML_FILENAME);
    fprintf(outf, "    -T, --vip-digest-table     VIP Digest Table filename (Default: %s)\n", FIREHOSE_DEFAULT_DIGEST_TABLE_FILENAME);
    fprintf(outf, "    -C, --vip-chained-digests  VIP Chained Digests filename (Default: %s)\n", FIREHOSE_DEFAULT_CHAINED_DIGESTS_FILENAME);
    fprintf(outf, "        --verify-vip           Verify a VIP image but do not flash it\n");
    fprintf(outf, "\n");

    fprintf(outf, "  Device Selection\n");
    fprintf(outf, "    -b, --bus=<BUS>            Bus of device to flash (must be specified with port)\n");
    fprintf(outf, "    -O, --port=<PORT>          Port of device to flash (must be specified with bus)\n");
    fprintf(outf, "    -h, --help                 Display this help message\n");
    fprintf(outf, "\n");

    fprintf(outf, "Notes:\n");
    fprintf(outf, "  * Alternate file Options are relative to images path\n");
    fprintf(outf, "  * Images filenames in the program and VIP xml are also relative to images path\n");
}


static struct option longopts[] = {
    { "firehose-bin", required_argument,  NULL,   'f' },
    { "program-xml",  required_argument,  NULL,   'p' },
    { "patch-xml",    required_argument,  NULL,   'P' },
    { "dry-run",      no_argument,        NULL,   'D' },
    { "erase",        no_argument,        NULL,   'e' },
    { "no-erase",     no_argument,        NULL,   'E' },
    { "info-only",    no_argument,        NULL,   'i' },
    { "sha256",       no_argument,        NULL,   's' },
    { "list",         no_argument,        NULL,   'l' },
    { "verbose",      no_argument,        NULL,   'v' },
    { "quiet",        no_argument,        NULL,   'q' },
    { "ignore-tty",   no_argument,        NULL,   't' },
    { "usb-verbose",  no_argument,        NULL,   'u' },
    { "version",      no_argument,        NULL,   'V' },
    { "vip",          no_argument,        NULL,   'S' },
    { "vip-messages-xml", required_argument, NULL, 'M' },
    { "vip-digest-table", required_argument, NULL, 'T' },
    { "vip-chained-digests", required_argument, NULL, 'C'},
    { "help",         no_argument,        NULL,   'h' },
    { "rpmb-erase",   no_argument,        NULL,   'r' },
    { "verify-vip",   no_argument,        NULL,   1 },
    { "bus",          required_argument,  NULL,   'b' },
    { "port",         required_argument,  NULL,   'O' },
    { NULL, 0, NULL, 0 }
};


static int parse_arguments(int argc, char **argv)
{
    const char *firehose_bin_arg = NULL;

    int flag;
    while ((flag = getopt_long(argc, argv, option_flags, longopts, NULL)) != -1) {
        switch (flag) {
            case 'f': {
                firehose_bin_arg = optarg;
                break;
            }

            case 'p': {
                s_args.program_xml = optarg;
                break;
            }

            case 'P': {
                s_args.patch_xml = optarg;
                break;
            }

            case 'D': {
                s_args.firehose_skip_write = 1;
                break;
            }

            case 'e': {
                s_args.firehose_erase = true;
                break;
            }

            case 'E': {
                s_args.firehose_erase = false;
                break;
            }

            case 'i': {
                s_args.info_only = true;
                break;
            }

            case 's': {
                s_args.sha256_digests = true;
                break;
            }

            case 'U': {
                s_args.usb_info = true;
                break;
            }

            case 'l': {
                s_args.list = true;
                break;
            }

            case 'v': {
                s_args.loglevel++;
                break;
            }

            case 'q': {
                s_args.percent_progress = false;
                break;
            }

            case 't': {
                s_args.ignore_tty = true;
                break;
            }

            case 'u': {
                s_args.usb_loglevel++;
                break;
            }

            case 'V': {
                printf("qcom-dl v%s\n", qcomdl_version_string());
                printf("Copyright (c) 2015-2017 Square, Inc. All rights reserved\n");
                return EXIT_FAILURE;
            }

            case 'S': {
                s_args.vip = true;
                break;
            }

            case 'M': {
                s_args.vip_xml = optarg;
                break;
            }

            case 'T': {
                s_args.vip_digest_table = optarg;
                break;
            }

            case 'C': {
                s_args.vip_chained_digests = optarg;
                break;
            }

            case 'r': {
                s_args.firehose_rpmb_erase = true;
                break;
            }

            case 1: {
                s_args.verify_vip = true;
                break;
            }

            case 'b': {
                s_args.bus = atoi(optarg);
                break;
            }

            case 'O': {
                s_args.port = optarg;
                break;
            }

            default:
            case 'h': {
                usage(stderr);
                return EXIT_FAILURE;
            }
        }
    }

    // return early without additional argument handling and checks if -i, -U, or -l were specified
    if (s_args.info_only || s_args.usb_info || s_args.list) {
        return EXIT_SUCCESS;
    }

    // Allow overriding firehose_bin with the cmd-line arg
    if (firehose_bin_arg) {
        s_args.firehose_bin = firehose_bin_arg;
    }

    if ((argc - optind) != 1) {
        usage(stderr);
        return EXIT_FAILURE;
    }

    strncpy(s_args.image_path, argv[optind], (sizeof(s_args.image_path)-1));
    size_t image_path_len = strlen(s_args.image_path);

    // strip trailing DIRSEP characters from image path
    while ((image_path_len > 1) && (s_args.image_path[image_path_len - 1] == DIRSEP)) {
        s_args.image_path[image_path_len - 1] = 0;
        image_path_len--;
    }

    return EXIT_SUCCESS;
}


static bool total_progress_percent(int current_percent, void *ctx)
{
    qcomdl_log(QCOMDL_LOG_LEVEL_NONE, "\r  ... %i%% complete", current_percent);
    qcomdl_log_flush();
    return true;
}


static bool file_progress_start_sectors_from_file(const char *file, size_t file_sectors, void *ctx)
{
    qcomdl_log_info("Transferring %zu sectors for file: %s\n", file_sectors, file);
    return true;
}

#if !defined(_WIN32)
static bool file_progress_sent_file_sectors(const char *file, size_t sectors_written, void *ctx)
{
    qcomdl_log(QCOMDL_LOG_LEVEL_INFO, "\r  ... %zu sectors sent", sectors_written);
    qcomdl_log_flush();
    return true;
}
#endif


static bool file_progress_finished_file_sectors(const char *file, int result, size_t sectors_written, void *ctx)
{
    const char *status = (result == 0)? "succeeded" : "failed";
    if (s_args.ignore_tty || qcomdl_log_isatty()) {
        qcomdl_log(QCOMDL_LOG_LEVEL_INFO, "\r");
    }
    qcomdl_log_info("File transfer %s for %s (%zu file sectors sent)\n", status, file, sectors_written);
    qcomdl_log_flush();
    return true;
}

static int do_usb_device_info()
{
    /* NOTE: do not change the output for this even slightly without
     * checking with bran-update first. The output parameters are
     * expected to be one per-line and delimited by '=' */
    qcomdl_usb_device_descriptor_t info;
    int r = qcomdl_usb_get_device_info(&info, false);
    if (r == QCOMDL_DEVICE_STATUS_SUCCESS) {
        printf("Bus=%u\n"
               "Port=%u\n"
               "VID=0x%.4x\n"
               "PID=0x%.4x\n"
               "serial=%s\n"
               "desc=(%s - %s)\n",
               info.bus,
               info.port,
               info.vid,
               info.pid,
               info.serial,
               qcomdl_usb_vid_str(info.vid),
               qcomdl_usb_pid_str(info.pid));
        return 0;
    } else if (r == QCOMDL_DEVICE_STATUS_DEVICE_NOT_FOUND) {
        qcomdl_log_error("Device not found\n");
    }
    return -1;
}


static void do_device_list()
{
    qcomdl_usb_device_descriptor_t **dev_list = NULL;
    ssize_t count = qcomdl_usb_get_device_list(&dev_list, false);
    qcomdl_log_info("Listing devices\n");
    if (count > 0) {
        for (ssize_t i = 0; i < count; i++) {
            printf("  Bus=%u Port=%s VID=0x%.4x/PID=0x%.4x serial=%s (%s - %s)\n",
                   dev_list[i]->bus,
                   dev_list[i]->port_str,
                   dev_list[i]->vid,
                   dev_list[i]->pid,
                   dev_list[i]->serial,
                   qcomdl_usb_vid_str(dev_list[i]->vid),
                   qcomdl_usb_pid_str(dev_list[i]->pid));
        }
    }
    qcomdl_usb_free_device_list(dev_list);
}


static edl_connection_t *do_edl_connect(int bus, const char *port)
{
    if ((s_args.bus != -1) && (s_args.port != NULL)) {
        return edl_connect_bus_and_port_path((uint8_t)s_args.bus, s_args.port);
    } else {
        return edl_connect();
    }
}


static void do_sahara_info(sahara_connection_t *sahara)
{
    qcomdl_log_level_t level = QCOMDL_LOG_LEVEL_NONE;
    qcomdl_log(level, "Retrieving device info\n");
    pbl_info_t pbl_info;
    if (sahara_device_info(sahara, &pbl_info) == 0) {
        qcomdl_log(level, "  SerialNumber: 0x%08x\n", pbl_info.serial);
        qcomdl_log(level, "  MSM_HW_ID: 0x%08x\n", pbl_info.msm_id);
        qcomdl_log(level, "  SBL SW Version: 0x%08x\n", pbl_info.pbl_sw);
        qcomdl_log(level, "  OEM_PK_HASH: ");
        for (size_t i = 0; i < sizeof(pbl_info.pk_hash); i++) {
            qcomdl_log(level, "%02x", pbl_info.pk_hash[i]);
        }
        qcomdl_log(level, "\n");
    } else {
        qcomdl_log_warning("Could not retrieve device information, proceeding to attempt loading firmware anyway\n");
    }
}

int main(int argc, char **argv)
{
    int exit_code = EXIT_FAILURE;
    edl_connection_t *edl_conn = NULL;
    sahara_connection_t *sahara = NULL;
    firehose_connection_t *fh_conn = NULL;
    qcomdl_resource_package_t *package = NULL;
    char firehose_bin_path[PATH_MAX];
    qcomdl_build_info_t *build_info = NULL;

    progname = argv[0];

    int parseret = parse_arguments(argc, argv);
    if (parseret != 0) {
        return parseret;
    }

    int rc = qcomdl_init();
    if (rc != 0) {
        return EXIT_FAILURE;
    }

    qcomdl_log_set_output(stdout);
    qcomdl_log_set_level(s_args.loglevel);
    qcomdl_set_usb_loglevel(s_args.usb_loglevel);

    // handle non-flashing commands
    if (s_args.list) {
        do_device_list();
        exit_code = EXIT_SUCCESS;
        goto teardown_qcomdl;
    }

    if (s_args.usb_info) {
        int info_ret = do_usb_device_info();
        if (info_ret == 0) {
            exit_code = EXIT_SUCCESS;
        }
        goto teardown_qcomdl;
    }

    if (s_args.info_only) {
        edl_conn = do_edl_connect(s_args.bus, s_args.port);
        if (!edl_conn) {
            goto teardown_qcomdl;
        }
        sahara = sahara_connect(edl_conn);
        if (!sahara) {
            goto teardown_edl;
        }
        do_sahara_info(sahara);
        exit_code = EXIT_SUCCESS;
        goto teardown_sahara;
    }

    // initialize the resource subsystem
    package = qcomdl_resource_package_open(s_args.image_path);
    if (!package) {
        qcomdl_log(QCOMDL_LOG_LEVEL_ERROR, "Failed to open '%s': %s\n", s_args.image_path, strerror(errno));
        goto teardown_qcomdl;
    }

    // if a firehose_bin wasn't specified, try and find an appropriate one
    rc = qcomdl_determine_firehose_path(package, s_args.firehose_bin, s_args.vip, (char *)firehose_bin_path, (sizeof(firehose_bin_path)-1));
    if (rc != 0) {
        qcomdl_log_error("Could not locate a firehose binary in '%s'\n", s_args.image_path);
        goto teardown_resource;
    }

    // check that program & patch XMLs are present
    if (qcomdl_resource_package_file_exists(package, package->img_dir, s_args.program_xml) != 0) {
        qcomdl_log_error("Program XML does not exist at '%s'\n", s_args.program_xml);
        goto teardown_resource;
    }
    if (qcomdl_resource_package_file_exists(package, package->img_dir, s_args.patch_xml) != 0) {
        qcomdl_log_error("Patch XML does not exist at '%s'\n", s_args.patch_xml);
        goto teardown_resource;
    }

    // validate VIP resources if we're going to program it
    if (s_args.vip || s_args.verify_vip) {
        if (qcomdl_resource_package_file_exists(package, package->img_dir, s_args.vip_xml) != 0) {
            qcomdl_log_error("VIP XML does not exist at '%s'\n", s_args.vip_xml);
            goto teardown_resource;
        }
        if (qcomdl_resource_package_file_exists(package, package->img_dir, s_args.vip_digest_table) != 0) {
            qcomdl_log_error("VIP digest table does not exist at '%s'\n", s_args.vip_digest_table);
            goto teardown_resource;
        }

        if (qcomdl_resource_package_file_exists(package, package->img_dir, s_args.vip_chained_digests) != 0) {
            qcomdl_log_error("VIP chained digests do not exist at '%s'\n", s_args.vip_chained_digests);
            goto teardown_resource;
        }
    }

    // handle one more non-flashing command
    if (s_args.verify_vip) {
        int r = firehose_verify_vip(package,
                                    s_args.vip_xml,
                                    s_args.vip_digest_table,
                                    s_args.vip_chained_digests);
        if (r == 0) {
            qcomdl_log(QCOMDL_LOG_LEVEL_NONE, "VIP image \"%s\" has been successfully verified!\n", s_args.image_path);
            exit_code = EXIT_SUCCESS;
        }
        goto teardown_resource;
    }

    // establish EDL connection
    edl_conn = do_edl_connect(s_args.bus, s_args.port);
    if (!edl_conn) {
        goto teardown_resource;
    }

    // check if the build info file is found, not finding this file should not prevent flashing
    if (qcomdl_resource_package_file_exists(package, package->full_dir, BUILD_INFO_FILE_NAME) == 0) {
        // retrieve the build chipset and product info from the build info file
        build_info = qcomdl_parse_build_info(package);
        if (build_info) {
            // retrieve the vid and pid from the connected device
            libusb_device *usb_device = libusb_get_device(edl_conn->usb_dev);
            if (!usb_device) {
                qcomdl_log_error("Could not find a connected usb device after EDL connection.\n");
                goto teardown_build_info;
            }
            struct libusb_device_descriptor usb_desc;
            if (libusb_get_device_descriptor(usb_device, &usb_desc) != LIBUSB_SUCCESS) {
                qcomdl_log_error("Could not retrieve USB device descriptor.\n");
                goto teardown_build_info;
            }

            // print a warning if build and product types do not align, a mismatch will not prevent flashing
            // allowing for changes to the build_info structure without blocking device flashing
            if (qcomdl_build_matches_product(&usb_desc, build_info) != 0) {
                qcomdl_log_warning("Mismatched build and connected device\n"
                                   "\tConnected Device VID=0x%0.4x\n"
                                   "\tConnected Device PID=0x%0.4x\n"
                                   "\tConnected Product=(%s - %s)\n"
                                   "\tBuild Expected Chipset=%s\n"
                                   "\tBuild Expected Product=%s\n",
                                   usb_desc.idVendor,
                                   usb_desc.idProduct,
                                   qcomdl_usb_vid_str(usb_desc.idVendor),
                                   qcomdl_usb_pid_str(usb_desc.idProduct),
                                   build_info->chipset_type,
                                   build_info->product_type);
            }
        }
        else {
            // issues parsing the build_info file should not be a failure condition
            qcomdl_log_warning("Could not parse the build info file.\n");
        }
    }

    // establish Sahara connection
    sahara = sahara_connect(edl_conn);
    if (!sahara) {
        goto teardown_build_info;
    }

    // print information about the DUT
    do_sahara_info(sahara);

    // upload firehose binary
    qcomdl_log(QCOMDL_LOG_LEVEL_NONE, "Uploading firehose binary via Sahara\n");
    rc = sahara_upload(sahara, package, firehose_bin_path);
    if (rc) {
        goto teardown_sahara;
    }
    rc = sahara_done(sahara);
    if (rc) {
        goto teardown_sahara;
    }
    sahara_connection_free(sahara);
    qcomdl_log_info("Sahara finished... waiting 3 seconds for firehose to come up\n");
    sleep_func(3);

    ssize_t total_image_sectors = 0;
    if (s_args.vip) {
        total_image_sectors = firehose_total_image_sectors_vip(package, s_args.vip_xml);
    } else {
        total_image_sectors = firehose_total_image_sectors_non_vip(package, s_args.program_xml);
    }
    if (total_image_sectors < 0) {
        qcomdl_log_error("There was an error calculating the size of the image\n");
        goto teardown_build_info;
    } else {
        qcomdl_log(QCOMDL_LOG_LEVEL_NONE, "Calculated image sectors: %zi (%s)\n", total_image_sectors, s_args.image_path);
    }

    qcomdl_log(QCOMDL_LOG_LEVEL_NONE, "Initializing Firehose\n");
    fh_conn = firehose_connect(edl_conn);
    if (!fh_conn) {
        qcomdl_log_error("couldn't initialize a firehose connection\n");
        goto teardown_build_info;
    }

    if (s_args.loglevel >= QCOMDL_LOG_LEVEL_INFO) {
        // At INFO loglevel and above per-file progess is automatically enabled because
        // percent display won't display well interleaved with other info messages
        s_args.percent_progress = false;
    }

    if (s_args.percent_progress) {
        if (s_args.ignore_tty || qcomdl_log_isatty()) {
            struct firehose_percent_progress_api percent_progress_api = {
                .total_image_sectors = (size_t)total_image_sectors,
                .handle_progress_percent = total_progress_percent,
            };
            firehose_register_percent_progress_handlers(fh_conn, &percent_progress_api, NULL);
        }
    } else {
        struct firehose_file_progress_api file_progress_api = {
            .handle_start_sectors_from_file = file_progress_start_sectors_from_file,
            .handle_sent_file_sectors = NULL,
            .handle_finished_sectors_from_file = file_progress_finished_file_sectors,
        };

#if !defined(_WIN32)
        if (s_args.ignore_tty || qcomdl_log_isatty()) {
            file_progress_api.handle_sent_file_sectors = file_progress_sent_file_sectors;
        }
#endif

        firehose_register_file_progress_handlers(fh_conn, &file_progress_api, NULL);
    }

    int fh_ret = -1;
    if (s_args.vip) {
        qcomdl_log(QCOMDL_LOG_LEVEL_NONE, "Programming the device using Validated Image Programming (VIP)\n");
        fh_ret = firehose_vip(fh_conn, package, s_args.vip_xml, s_args.vip_digest_table, s_args.vip_chained_digests);
    } else {
        qcomdl_log(QCOMDL_LOG_LEVEL_NONE, "Programming the device with an unvalidated image\n");
        fh_conn->cfg.SkipWrite = s_args.firehose_skip_write;
        fh_ret = firehose_non_vip(fh_conn,
                                  package,
                                  s_args.program_xml,
                                  s_args.patch_xml,
                                  s_args.firehose_erase,
                                  s_args.firehose_program_read_back_verify,
                                  s_args.sha256_digests,
                                  FIREHOSE_DEFAULT_RESET_DELAY_SECS,
                                  s_args.firehose_rpmb_erase);
    }

    if (fh_ret == 0) {
        qcomdl_log(QCOMDL_LOG_LEVEL_NONE, "Programming finished successfully\n");
        exit_code = EXIT_SUCCESS;
    } else {
        qcomdl_log(QCOMDL_LOG_LEVEL_NONE, "Programming failed with errors!\n");
        goto teardown_firehose;
    }

teardown_firehose:
    firehose_connection_free(fh_conn);
    // If firehose is connected, sahara was already torn down.
    goto teardown_build_info;
teardown_sahara:
    sahara_connection_free(sahara);
teardown_build_info:
    if (build_info) {
        free(build_info);
    }
teardown_edl:
    if (edl_disconnect(edl_conn) != 0) {
        exit_code = EXIT_FAILURE;
    }
teardown_resource:
    // Some subcommands don't instantiate a resource package.
    if (package) {
        qcomdl_resource_package_free(package);
    }
teardown_qcomdl:
    qcomdl_teardown();
    return exit_code;
}
