// Copyright © 2015-2017 Square, Inc. All rights reserved.

#pragma once

#include <stdio.h>
#include <errno.h>

typedef enum {
    QCOMDL_LOG_LEVEL_NONE = 0,
    QCOMDL_LOG_LEVEL_ERROR,
    QCOMDL_LOG_LEVEL_WARNING,
    QCOMDL_LOG_LEVEL_INFO,
    QCOMDL_LOG_LEVEL_DEBUG,
    QCOMDL_LOG_LEVEL_VERBOSE_DEBUG,
} qcomdl_log_level_t;


void qcomdl_log_set_output(FILE *out);
void qcomdl_log_set_level(qcomdl_log_level_t level);
FILE *qcomdl_log_get_output(void);
qcomdl_log_level_t qcomdl_log_get_level(void);

int qcomdl_log_isatty(void);
int qcomdl_log_flush(void);

#ifdef __ANDROID__
void qcomdl_log_set_android_logging_tag(const char *log_tag);
void qcomdl_log_set_android_logging(int enabled);
#endif

#if !defined(_WIN32)
__attribute__ ((format (printf, 2, 3)))
#endif
void qcomdl_log(qcomdl_log_level_t level, const char *msg, ...);

#if defined(DEBUG)
#define _qcomdl_log_wrap(lvl, lstr, msg, args...) qcomdl_log((lvl), lstr " (%s) " msg, __func__, ##args)
#else
#define _qcomdl_log_wrap(lvl, lstr, msg, args...) qcomdl_log((lvl), lstr " " msg, ##args)
#endif

#define qcomdl_log_verbose_debug(msg, args...) _qcomdl_log_wrap(QCOMDL_LOG_LEVEL_VERBOSE_DEBUG, "[debug]", msg, ##args)
#define qcomdl_log_debug(msg, args...) _qcomdl_log_wrap(QCOMDL_LOG_LEVEL_DEBUG, "[debug]", msg, ##args)
#define qcomdl_log_info(msg, args...) _qcomdl_log_wrap(QCOMDL_LOG_LEVEL_INFO, "[info] ", msg, ##args)
#define qcomdl_log_warning(msg, args...) _qcomdl_log_wrap(QCOMDL_LOG_LEVEL_WARNING, "[warning]", msg, ##args)
#define qcomdl_log_error(msg, args...) _qcomdl_log_wrap(QCOMDL_LOG_LEVEL_ERROR, "[!ERROR]", msg, ##args)
#define qcomdl_log_perror(msg) qcomdl_log_error("%s - %s\n", (msg), strerror(errno))
