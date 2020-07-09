// Copyright © 2015-2017 Square, Inc. All rights reserved.

#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include "qcomdl_log.h"


static FILE *qcomdl_log_output = NULL;

static qcomdl_log_level_t qcomdl_log_level = QCOMDL_LOG_LEVEL_NONE;

#ifdef __ANDROID__
#include <log/log.h>

static int android_logging_enabled = 0;

static const char *android_logging_tag = "qcomdl";

static void qcomdl_log_android(qcomdl_log_level_t level, const char *msg, va_list args)
{
    if (! android_logging_enabled) {
        return;
    }

    int android_priority = ANDROID_LOG_UNKNOWN;

    switch (level) {

        case QCOMDL_LOG_LEVEL_ERROR:
        {
            android_priority = ANDROID_LOG_ERROR;
            break;
        }

        case QCOMDL_LOG_LEVEL_WARNING:
        {
            android_priority = ANDROID_LOG_WARN;
            break;
        }

        case QCOMDL_LOG_LEVEL_INFO:
        {
            android_priority = ANDROID_LOG_INFO;
            break;
        }

        case QCOMDL_LOG_LEVEL_DEBUG:
        {
            android_priority = ANDROID_LOG_DEBUG;
            break;
        }

        case QCOMDL_LOG_LEVEL_VERBOSE_DEBUG:
        {
            android_priority = ANDROID_LOG_VERBOSE;
            break;
        }

        case QCOMDL_LOG_LEVEL_NONE:
        default:
        {
            android_priority = ANDROID_LOG_UNKNOWN;
            break;
        }
    }

    LOG_PRI_VA(android_priority, android_logging_tag, msg, args);
}

void qcomdl_log_set_android_logging_tag(const char *log_tag)
{
    android_logging_tag = log_tag;
}

void qcomdl_log_set_android_logging(int enabled)
{
    android_logging_enabled = enabled;
}

#endif

void qcomdl_log_set_output(FILE *out)
{
    qcomdl_log_output = out;
}


void qcomdl_log_set_level(qcomdl_log_level_t level)
{
    qcomdl_log_level = level;
}


qcomdl_log_level_t qcomdl_log_get_level()
{
    return qcomdl_log_level;
}

FILE *qcomdl_log_get_output()
{
    return qcomdl_log_output;
}


void qcomdl_log(qcomdl_log_level_t level, const char *msg, ...)
{
    if ((!qcomdl_log_output) || (qcomdl_log_level < level)) {
        return;
    }
    va_list args;
    va_start(args, msg);
    vfprintf(qcomdl_log_output, msg, args);

#ifdef __ANDROID__
    qcomdl_log_android(level, msg, args);
#endif

    va_end(args);
}


int qcomdl_log_isatty()
{
    if (!qcomdl_log_output) {
        return 0;
    }
    return isatty(fileno(qcomdl_log_output));
}


int qcomdl_log_flush()
{
    if (!qcomdl_log_output) {
        return 0;
    }
    return fflush(qcomdl_log_output);
}
