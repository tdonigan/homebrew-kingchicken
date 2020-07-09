// Copyright © 2015-2017 Square, Inc. All rights reserved.

#include <stdbool.h>
#include <libusb.h>
#include <libxml/parser.h>
#include <stdint.h>
#include <string.h>

#include "qcomdl_usb.h"
#include "qcomdl.h"
#include "qcomdl_log.h"
#include "edl.h"

#ifndef QCOMDL_VERSION
#define QCOMDL_VERSION "[version missing on debugging build]"
#endif


static bool s_qcomdl_initialized;

const char *qcomdl_version_string()
{
    return QCOMDL_VERSION;
}

int qcomdl_init()
{
    if (s_qcomdl_initialized) {
        qcomdl_log_debug("qcomdl is already initialized. Doing nothing\n");
        return 0;
    }

    qcomdl_log_debug("Initializing libusb\n");
    int rc = libusb_init(NULL);
    if (rc != LIBUSB_SUCCESS) {
        qcomdl_log_error("Failed to initialize libusb: %s\n", libusb_strerror(rc));
        return -1;
    }

    qcomdl_log_set_output(stdout);

    // Set log level defaults (can be overidden later)

    // qcomdl loglevel is debug by default since the python bindings are primarily used for testing/debugging
    qcomdl_log_set_level(QCOMDL_LOG_LEVEL_DEBUG);

    // debug loglevel from libusb is very verbose, settle for INFO
    qcomdl_set_usb_loglevel(LIBUSB_LOG_LEVEL_INFO);

    // initialize libxml2
    LIBXML_TEST_VERSION;

    s_qcomdl_initialized = true;
    return 0;
}

void qcomdl_teardown()
{
    if (!s_qcomdl_initialized) {
        qcomdl_log_warning("EDL is not initialized. Doing nothing\n");
        return;
    }

    xmlCleanupParser();

    qcomdl_log_debug("Teardown libusb\n");
    libusb_exit(NULL);
    s_qcomdl_initialized = false;
}

void qcomdl_set_usb_loglevel(int lvl)
{
#if LIBUSB_API_VERSION >= 0x01000106
    // Note: Per libusb.h in libusb 1.0.22 (where this change was made):
    // If libusb was compiled without any message logging, this
    // function does nothing: you'll never get any messages.
    libusb_set_option(NULL, LIBUSB_OPTION_LOG_LEVEL, lvl);
#else
    libusb_set_debug(NULL, lvl);
#endif
}


