// Copyright © 2018 Square, Inc. All rights reserved.

// Overview
// ========
// This is a resource abstraction layer for qcom-dl to allow POSIX-style
// file operations with a variety of backends.
//
// The initial implementation provides backends for POSIX and ZIP libraries.
//
// Functionality is implemented by replacing FILE * with qcomdl_resource_t *
// which contains an identifier that determines which backend to use as well
// as backend-specific information about the file being accessed.
//
// Notes
// =====
//  - Wherever possible, POSIX function prototypes and return values are maintained
//  - fwrite is not implemented since qcom-dl does not need it for most operations
//    and it is not supported by the zip backend

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <zip.h>
#include <limits.h>

enum qcomdl_resource_package_type {
    QDL_PKGTYPE_INVALID = 0,
    QDL_PKGTYPE_DIR,
    QDL_PKGTYPE_ZIP,
    QDL_PKGTYPE_MAX,
};

struct qcomdl_resource_package {
    enum qcomdl_resource_package_type type;

    // common
    char img_dir [PATH_MAX]; // the flashable directory
    char full_dir[PATH_MAX]; // the full directory

    // PKGTYPE_ZIP
    zip_t *zip_archive;
};

typedef struct qcomdl_resource_package qcomdl_resource_package_t;

struct qcomdl_resource_file {
    struct qcomdl_resource_package *package;

    // common
    char *filename;
    uint64_t size;

    // PKGTYPE_DIR
    FILE *file;

    // PKGTYPE_ZIP
    zip_file_t *zip_file;
    zip_int64_t pos;
};

typedef struct qcomdl_resource_file qcomdl_resource_file_t;

/*
 * Determines what resource backend to use based on the supplied path, and
 * initializes the appropriate initial state for that backend.
 *
 * @param  path  base path for resources, may be a directory name or zipfile
 * @return       pointer to package struct on success, NULL on failure
 */
qcomdl_resource_package_t *qcomdl_resource_package_open(const char *path);

/*
 * Releases internal resource backend data.
 *
 * @param  package  package to free
 */
void qcomdl_resource_package_free(qcomdl_resource_package_t *package);

/*
 * Indicates whether or not the resource package is a zipfile
 *
 * @return  1 if package is a zipfile, 0 if not
 */
int qcomdl_resource_package_is_zip(qcomdl_resource_package_t *package);

/*
 * Opens a file from the resource package, follows fopen(3)
 *
 * @param  package   package to open from
 * @param  dir       directory within the package
 * @param  filename  file path to open
 * @param  mode      what mode to open file in, only 'r' or 'rb' are valid for zip files
 * @return           pointer to a resource on success, NULL on error
 */
qcomdl_resource_file_t *qcomdl_fopen(qcomdl_resource_package_t *package, const char *dir, const char *filename, const char *mode);

/*
 * Reads data from a resource file, follows fread(3)
 *
 * @param  ptr     recipient for data
 * @param  size    size of item to read
 * @param  nitems  number of items to read
 * @param  file    resource file to read
 * @return         number of items read
 */
size_t qcomdl_fread(void *ptr, size_t size, size_t nitems, qcomdl_resource_file_t *file);

/*
 * Closes out a resource handle, follows fclose(3)
 *
 * @param  file  the resource to close and deallocate
 * @return       0 on success, EOF on failure and errno is set
 */
int qcomdl_fclose(qcomdl_resource_file_t *file);

/*
 * Seeks to position in the resource, follows fseek(3)
 *
 * Note: when seeking backwards on a resource in a zipfile, the resource is
 *       closed and then re-opened and seek to the requested position. This
 *       is a limitation of libzip
 *
 * @param  file    context to seek
 * @param  offset  offset to seek to
 * @param  whence  one of SEEK_SET, SEEK_CUR, or SEEK_END to indicate how to seek
 * @return         current offset on success, -1 on failure and errno is set
 */
int qcomdl_fseek(qcomdl_resource_file_t *file, long offset, int whence);

/*
 * Seeks to position in the resource, follows fseeko(3)
 *
 * Note: when seeking backwards on a resource in a zipfile, the resource is
 *       closed and then re-opened and seek to the requested position. This
 *       is a limitation of libzip
 *
 * @param  file    context to seek
 * @param  offset  offset to seek to
 * @param  whence  one of SEEK_SET, SEEK_CUR, or SEEK_END to indicate how to seek
 * @return         current offset on success, -1 on failure and errno is set
 */
int qcomdl_fseeko(qcomdl_resource_file_t *file, off_t offset, int whence);

/*
 * Fetches the current position of the resource context, follows ftell(3)
 *
 * @param  file  context to query for its position
 * @return       position on success, -1 on failure and errno is set
 */
long qcomdl_ftell(qcomdl_resource_file_t *file);

/*
 * Fetches the current position of the resource context, follows ftello(3)
 *
 * @param  file  context to query for its position
 * @return       position on success, -1 on failure and errno is set
 */
off_t qcomdl_ftello(qcomdl_resource_file_t *file);

/*
 * Indicates whether the resource is at end-of-file, follows feof(3)
 *
 * @param  file  the resource to test
 * @return       non-zero if at end-of-file, 0 otherwise
 */
int qcomdl_feof(qcomdl_resource_file_t *file);

/*
 * Indicated whether the resource is in an error state, follows ferror(3)
 *
 * @param  file  the resource to test
 * @return       non-zero if in an error state, 0 otherwise
 */
int qcomdl_ferror(qcomdl_resource_file_t *file);

/*
 * Returns the size of the resource
 *
 * @param  file  context to query for size
 * @param  size  pointer to uint64_t to receive file size
 * @return       0 on success, -1 on error and errno is set
 */
int qcomdl_resource_get_size(qcomdl_resource_file_t *file, uint64_t *size);

/*
 * Sets 'size' parameter to the size of the file indicated by filename
 *
 * @param  package   resource package to query within
 * @param  dir       directory within the package
 * @param  filename  name of file to query size for
 * @param  size      pointer to uint64_t to receive file size
 * @return           0 on success, -1 on error and errno is set
 */
int qcomdl_resource_package_get_size(qcomdl_resource_package_t *package, const char *dir, const char *filename, uint64_t *size);

/*
 * Check to see if a file exists and is accessible
 *
 * If the backend is a filesystem, access(2) is used, otherwise test to see if the
 * requested file is present inside the Zip archive
 *
 * @param  package   resource package to query within
 * @param  dir       directory within the package
 * @param  filename  path to file to check
 * @return           0 on success, -1 on error and errno is set
 */
int qcomdl_resource_package_file_exists(qcomdl_resource_package_t *package, const char *dir, const char *filename);

/*
 * Determine the firehose path from a zip package/flashable folder
 *
 * @param  package            resource package to query within
 * @param  firehose_filename  firehose binary name
 * @param  is_vip             Boolean to check for a VIP/non VIP firehose binary
 * @param  path_out           Returned location of firehose binary in package
 * @param  path_len           Max Length of path_out
 * @return                    0 on success, -1 on error
 */

int qcomdl_determine_firehose_path(qcomdl_resource_package_t *package, const char *firehose_filename, bool is_vip, char *path_out, uint32_t path_len);
