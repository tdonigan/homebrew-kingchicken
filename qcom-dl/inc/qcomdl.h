// Copyright © 2015-2017 Square, Inc. All rights reserved.

#pragma once

#include <qcomdl_usb.h>

#if defined(_WIN32) || defined(__CYGWIN__)
    #define sleep_func(sec) Sleep((sec) * 1000)
    #define DIRSEP '\\'
#else
    #include <unistd.h>
    #define sleep_func(sec) sleep(sec)
    #define DIRSEP '/'
#endif

#if !defined(QCOMDL_STATIC)
    #if defined(_WIN32) || defined(__CYGWIN__)
        #if defined (QCOMDL_BUILDING_DLL)
            // define dllexport and dllimport macros
            #ifndef QCOMDL_API
                #define QCOMDL_API __declspec(dllexport)
            #endif
        #else
            #ifndef QCOMDL_API
                #define QCOMDL_API __declspec(dllimport)
            #endif
        #endif

    #elif defined(__APPLE__) || defined(__linux__) || defined(__unix__)
        #if __GNUC__ >= 4
            // GCC 4 has unique keywords for showing/hiding symbols
            // the same keyword is used for both import and export
            #define QCOMDL_API __attribute__ ((__visibility__("default")))
            #define QCOMDL_API __attribute__ ((__visibility__("default")))
        #else
            #define QCOMDL_API
            #define QCOMDL_API
        #endif

    #else
        #error "Unsupported OS"
    #endif
#else
    // static build doesn't need import/export macros
    #define QCOMDL_API
    #define QCOMDL_API
#endif

QCOMDL_API
const char *qcomdl_version_string(void);

QCOMDL_API
int qcomdl_init(void);

QCOMDL_API
void qcomdl_teardown(void);

QCOMDL_API
void qcomdl_set_usb_loglevel(int lvl);
