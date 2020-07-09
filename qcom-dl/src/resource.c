#include <errno.h>
#include <inttypes.h>
#include <resource.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <qcomdl.h>
#include <firehose.h>
#include <limits.h>

#include "qcomdl_log.h"

static const char *resource_type_names[] = {
    "QDL_PKGTYPE_INVALID",
    "QDL_PKGTYPE_DIR",
    "QDL_PKGTYPE_ZIP",
    "QDL_PKGTYPE_MAX",
};

static const char *get_resource_type_name(enum qcomdl_resource_package_type type) {
    if (type > QDL_PKGTYPE_MAX) {
        return "<invalid value>";
    }

    return resource_type_names[type];
}

static int join_path(const char *dir_name, const char *file_name, char path_out[PATH_MAX])
{
    int r;
    if (strlen(dir_name) == 0) {
        // allow relative paths to stay relative paths
        r = snprintf(path_out, PATH_MAX-1, "%s", file_name);
    } else {
        r = snprintf(path_out, PATH_MAX-1, "%s%c%s", dir_name, DIRSEP, file_name);
    }
    if (r < 0) {
        qcomdl_log_error("sprintf error\n");
        return -1;
    } else if (r >= (PATH_MAX-1)) {
        qcomdl_log_error("Path too long for file: %s%c%s\n", dir_name, DIRSEP, file_name);
        return -1;
    } else {
        return 0;
    }
}

static int qcomdl_resolve_directory_location(const char *path, qcomdl_resource_package_t *package) {
    // determine which directory path was provided.
    // search for the full directory, and full/flashable directories.
    char full_path[PATH_MAX];
    char full_flashable_path[PATH_MAX];
    char flashable_path[PATH_MAX];

    if (join_path(path, "full", full_path) != 0) {
        qcomdl_log_error("Error creating full path\n");
        return -ENAMETOOLONG;
    }
    if (join_path(full_path, "flashable", full_flashable_path) != 0) {
        qcomdl_log_error("Error creating full flashable path\n");
        return -ENAMETOOLONG;
    }
    if (join_path(path, "flashable", flashable_path) != 0) {
        qcomdl_log_error("Error creating flashable path\n");
        return -ENAMETOOLONG;
    }

    struct stat info_full_flashable_path;
    struct stat info_flashable;

    // check if the product directory was provided
    if ((stat(full_flashable_path, &info_full_flashable_path) == 0) &&
        (info_full_flashable_path.st_mode & S_IFDIR)) {

        strncpy(package->img_dir, full_flashable_path, (sizeof(package->img_dir) - 1));
        package->img_dir[sizeof(package->img_dir) - 1] = '\0';

        strncpy(package->full_dir, full_path, (sizeof(package->full_dir) - 1));
        package->full_dir[sizeof(package->full_dir) - 1] = '\0';

    // check if the full directory was provided
    } else if ((stat(flashable_path, &info_flashable) == 0) &&
                (info_flashable.st_mode & S_IFDIR)) {

        strncpy(package->img_dir, flashable_path, (sizeof(package->img_dir) - 1));
        package->img_dir[sizeof(package->img_dir) - 1] = '\0';

        strncpy(package->full_dir, path, (sizeof(package->full_dir) - 1));
        package->full_dir[sizeof(package->full_dir) - 1] = '\0';

    // otherwise assume the flashable directory was provided
    } else {

        strncpy(package->img_dir, path, (sizeof(package->img_dir) - 1));
        package->img_dir[sizeof(package->img_dir) - 1] = '\0';
    }

    return 0;
}

qcomdl_resource_package_t *qcomdl_resource_package_open(const char *path) {
    qcomdl_resource_package_t *package;
    struct stat info;
    int ret;

    if (!path) {
        qcomdl_log_error("%s: null path passed as argument\n", __FUNCTION__);
        abort();
    }

    // allocate package struct
    package = calloc(1, sizeof(qcomdl_resource_package_t));
    if (!package) {
        qcomdl_log_perror("calloc");
        return NULL;
    }

    // allow path of "" (so that fopen and co. resolve filename as either relative or absolute)
    if (strlen(path) == 0) {
        package->type = QDL_PKGTYPE_DIR;
        if (qcomdl_resolve_directory_location(path, package) != 0) {
            qcomdl_log_error("Unable to resolve directory locations.\n");
            goto err;
        }
        return package;
    }

    // check what our path points to
    ret = stat(path, &info);
    if (ret != 0) {
        qcomdl_log_perror("stat");
        goto err;
    }

    if (info.st_mode & S_IFREG) {
        // do we have a zip file?
        if (strcmp(".zip", path + strlen(path) - 4)) {
            // we have a file that isn't a .zip
            qcomdl_log_error("'%s' is not a ZIP file!", path);
            goto err;
        }

        // make sure that we can read from the file
        if (access(path, R_OK) != 0) {
            qcomdl_log_perror("access");
            goto err;
        }

        // populate package->zip_archive
        int int_error;
        package->zip_archive = zip_open(path, ZIP_RDONLY, &int_error);
        if (!package->zip_archive) {
            zip_error_t ze_error;
            zip_error_init_with_code(&ze_error, int_error);
            qcomdl_log_error("Failed to open ZIP archive at '%s': %s",
                             path, zip_error_strerror(&ze_error));
            zip_error_fini(&ze_error);
            goto err;
        }

        // populate common members
        package->type = QDL_PKGTYPE_ZIP;
        if (join_path("full", "flashable", package->img_dir)) {
            qcomdl_log_error("Failed constructing path of image directory within ZIP archive\n");
            goto err;
        }
        strncpy(package->full_dir, "full", (sizeof(package->full_dir) - 1));

    } else if (info.st_mode & S_IFDIR) {
        // we've got a directory, populate common members
        package->type = QDL_PKGTYPE_DIR;

        if (qcomdl_resolve_directory_location(path, package) != 0) {
            qcomdl_log_error("Unable to resolve directory locations.\n");
            goto err;
        }

    } else {
        // we have something else, we don't care what it is
        qcomdl_log_error("'%s' is not a regular file or a directory!", path);
        goto err;
    }

    return package;

err:
    free(package);
    return NULL;
}

void qcomdl_resource_package_free(qcomdl_resource_package_t *package) {
    if (!package) {
        qcomdl_log_error("%s: null package passed as argument\n", __FUNCTION__);
        abort();
    }

    if (package->type == QDL_PKGTYPE_ZIP) {
        zip_close(package->zip_archive);
    }
    free(package);
}

static char * _convert_path_for_libzip(const char *filename) {
    char *new_filename = strdup(filename);
    if (!new_filename) {
        return NULL;
    }
#if defined(_WIN32) || defined(__CYGWIN__)
    char *sep;

    while ((sep = strchr(new_filename, '\\'))) {
        *sep = '/';
    }
#endif
    return new_filename;
}

static int open_zip_entry(qcomdl_resource_file_t *file, const char *filename, const char *mode) {
    qcomdl_resource_package_t *package = file->package;

    // check to make sure that the mode is 'r' or 'rb' and nothing else
    if (strcmp(mode, "r") != 0 && strcmp(mode, "rb") != 0) {
        qcomdl_log_error("%s: invalid mode '%s'\n", __FUNCTION__, mode);
        return -1;
    }

    char *libzip_path = _convert_path_for_libzip(filename);
    if (!libzip_path) {
        return -1;
    }
    file->filename = libzip_path;

    // open zip file entry
    file->zip_file = zip_fopen(package->zip_archive, libzip_path, ZIP_FL_ENC_GUESS);
    if (!file->zip_file) {
        qcomdl_log_error("%s: zip_fopen failed with error '%s'\n", __FUNCTION__,
                         zip_strerror(package->zip_archive));
        goto err_zip_fopen;
    }

    // get uncompressed file size
    struct zip_stat stats;
    zip_stat_init(&stats);

    int ret = zip_stat(package->zip_archive, libzip_path, ZIP_FL_ENC_GUESS, &stats);
    if (ret != 0) {
        qcomdl_log_error("%s: zip_stat failed with error '%s'\n", __FUNCTION__,
                         zip_strerror(package->zip_archive));
        goto err_zip_stat;
    }
    if (stats.valid & ZIP_STAT_SIZE) {
        file->size = stats.size;
    } else {
        qcomdl_log_error("%s: uncompressed size field in stats was invalid\n", __FUNCTION__);
        abort();
    }

    return 0;
err_zip_stat:
    zip_fclose(file->zip_file);
err_zip_fopen:
    free(file->filename);
    file->filename = NULL;
    return -1;
}

qcomdl_resource_file_t *qcomdl_fopen(qcomdl_resource_package_t *package, const char *dir, const char *filename, const char *mode) {
    qcomdl_resource_file_t *file;
    char path[PATH_MAX];

    if (!package || !filename || !mode) {
        qcomdl_log_error("%s: null package/filename/mode passed as argument\n", __FUNCTION__);
        abort();
    }

    if (join_path(dir, filename, path)) {
        qcomdl_log_error("%s: failed constructing path to file\n", __FUNCTION__);
        return NULL;
    }

    file = calloc(1, sizeof(qcomdl_resource_file_t));
    if (!file) {
        return NULL;
    }
    file->package = package;

    if (package->type == QDL_PKGTYPE_ZIP) {
        int ret = open_zip_entry(file, path, mode);
        if (ret != 0) {
            goto err_teardown_struct;
        }
    }

    if (package->type == QDL_PKGTYPE_DIR) {
        file->file = fopen(path, mode);
        if (!file->file) {
            goto err_teardown_struct;
        }
        file->filename = strdup(filename);
        if (!file->filename) {
            goto err_teardown_file;
        }

        struct stat st;
        if (stat(path, &st) != 0) {
            qcomdl_log_perror("stat");
            goto err_teardown_filename;
        }

        file->size = (uint64_t)st.st_size;
    }

    return file;

err_teardown_filename:
    free(file->filename);
err_teardown_file:
    fclose(file->file);
err_teardown_struct:
    free(file);
    return NULL;
}

size_t qcomdl_fread(void *ptr, size_t size, size_t nitems, qcomdl_resource_file_t *file) {
    if (!file) {
        qcomdl_log_error("%s: null file passed as argument\n", __FUNCTION__);
        abort();
    }

    if (file->package->type == QDL_PKGTYPE_ZIP) {
        zip_int64_t res = zip_fread(file->zip_file, ptr, size * nitems);
        if (res < 0) {
            return 0;
        }
        if ((unsigned long long)res > (SIZE_MAX)) {
            qcomdl_log_error("%s: zip_fread returned greater value than size_t max\n", __FUNCTION__);
            return 0;
        }

        // for fseek / ftell
        file->pos += (zip_uint64_t)res;

        // return number of items read
        if ((res % (zip_int64_t)size) != 0) {
            qcomdl_log_warning("%s: zip_fread read a non size multiple of bytes: %"PRIi64" / %li\n", __FUNCTION__, res, size);
        }
        return (size_t)res / size;
    }

    if (file->package->type == QDL_PKGTYPE_DIR) {
        return fread(ptr, size, nitems, file->file);
    }

    // any other type is an error
    qcomdl_log_error("%s: invalid type %d (%s)\n", __FUNCTION__, file->package->type,
            get_resource_type_name(file->package->type));
    abort();
}

int qcomdl_fclose(qcomdl_resource_file_t *file) {
    if (!file) {
        qcomdl_log_error("%s: null file passed as argument\n", __FUNCTION__);
        abort();
    }

    if (file->package->type == QDL_PKGTYPE_ZIP) {
        int rc = zip_fclose(file->zip_file);
        free(file->filename);
        free(file);
        return rc;
    }

    if (file->package->type == QDL_PKGTYPE_DIR) {
        int rc = fclose(file->file);
        free(file->filename);
        free(file);
        return rc;
    }

    // any other type is an error
    qcomdl_log_error("%s: invalid type %d (%s)\n", __FUNCTION__, file->package->type,
            get_resource_type_name(file->package->type));
    abort();
}

static int emulate_zip_fseek(qcomdl_resource_file_t *file, long offset, int whence) {
    // libzip does not support fseek on compressed files:
    // https://libzip.org/documentation/zip_fseek.html
    // therefore, we must emulate it

    qcomdl_resource_package_t *package = file->package;
    zip_int64_t req_pos;

    switch (whence) {
        case SEEK_SET:
            if (offset < 0) {
                offset = 0;
            }

            req_pos = offset;

            // shortcut if we're already there
            if (req_pos == file->pos) {
                return 0;
            }
            break;
        case SEEK_CUR:
            req_pos = file->pos + offset;
            break;
        case SEEK_END:
            file->pos = (zip_int64_t)file->size;
            return 0;
        default:
            qcomdl_log_error("%s: invalid value %d for whence\n", __FUNCTION__, whence);
            abort();
    };

    if ((uint64_t)req_pos > file->size) {
        qcomdl_log_error("%s: attempt to seek past the end of a file\n", __FUNCTION__);
        return -1;
    }

    // if we've already read past the requested position, re-set the file
    if (req_pos < file->pos) {
        zip_fclose(file->zip_file);
        file->zip_file = zip_fopen(package->zip_archive, file->filename, ZIP_FL_ENC_GUESS);
        if (!file->zip_file) {
            qcomdl_log_error("%s: zip_fopen failed with error '%s'\n", __FUNCTION__,
                    zip_strerror(package->zip_archive));
            // the internal file is now in an inconsistent state
            abort();
        }
        file->pos = 0;
    }

    // do a dummy read to seek us to the right position
    zip_uint64_t len = (zip_uint64_t)req_pos - (zip_uint64_t)file->pos;
    if (len <= 0) {
        qcomdl_log_error("%s: attempt to seek to a negative absolute calculated position %"PRIi64"\n",
                         __FUNCTION__, len);
        // hitting this should be impossible given the above rewind check
        abort();
    }

    void *temp = malloc(len);
    if (!temp) {
        qcomdl_log_error("%s: could not allocate temp buffer of %"PRIu64" bytes\n", __FUNCTION__, len);
        // the internal file is now in an inconsistent state
        abort();
    }

    zip_int64_t ret = zip_fread(file->zip_file, temp, len);
    if (ret == -1) {
        qcomdl_log_error("%s: zip_fread failed with error '%s'\n", __FUNCTION__,
                zip_file_strerror(file->zip_file));
        free(temp);
        // the internal file is now in an inconsistent state
        abort();
    }
    free(temp);

    // update our internal position
    file->pos += ret;

    return 0;
}

int qcomdl_fseek(qcomdl_resource_file_t *file, long offset, int whence) {
    if (!file) {
        qcomdl_log_error("%s: null file passed as argument\n", __FUNCTION__);
        abort();
    }

    if (file->package->type == QDL_PKGTYPE_ZIP) {
        return emulate_zip_fseek(file, offset, whence);
    }

    if (file->package->type == QDL_PKGTYPE_DIR) {
        return fseek(file->file, offset, whence);
    }

    // any other type is an error
    qcomdl_log_error("%s: invalid type %d (%s)\n", __FUNCTION__, file->package->type,
            get_resource_type_name(file->package->type));
    abort();
}

int qcomdl_fseeko(qcomdl_resource_file_t *file, off_t offset, int whence) {
    return qcomdl_fseek(file, offset, whence);
}

long qcomdl_ftell(qcomdl_resource_file_t *file) {
    if (!file) {
        qcomdl_log_error("%s: null file passed as argument\n", __FUNCTION__);
        abort();
    }

    if (file->package->type == QDL_PKGTYPE_ZIP) {
        return file->pos;
    }

    if (file->package->type == QDL_PKGTYPE_DIR) {
        return ftell(file->file);
    }

    qcomdl_log_error("%s: invalid type %d (%s)\n", __FUNCTION__, file->package->type,
            get_resource_type_name(file->package->type));
    abort();
}

off_t qcomdl_ftello(qcomdl_resource_file_t *file) {
    if (!file) {
        qcomdl_log_error("%s: null file passed as argument\n", __FUNCTION__);
        abort();
    }

    if (file->package->type == QDL_PKGTYPE_ZIP) {
        return file->pos;
    }

    if (file->package->type == QDL_PKGTYPE_DIR) {
        return ftello(file->file);
    }

    qcomdl_log_error("%s: invalid type %d (%s)\n", __FUNCTION__, file->package->type,
            get_resource_type_name(file->package->type));
    abort();
}

int qcomdl_feof(qcomdl_resource_file_t *file) {
    if (!file) {
        qcomdl_log_error("%s: null file passed as argument\n", __FUNCTION__);
        abort();
    }

    if (file->package->type == QDL_PKGTYPE_DIR) {
        return feof(file->file);
    }

    if (file->package->type == QDL_PKGTYPE_ZIP) {
        return ((zip_uint64_t)file->pos >= file->size);
    }

    // any other type is an error
    qcomdl_log_error("%s: invalid type %d (%s)\n", __FUNCTION__, file->package->type,
            get_resource_type_name(file->package->type));
    abort();
}

int qcomdl_ferror(qcomdl_resource_file_t *file) {
    if (!file) {
        qcomdl_log_error("%s: null file passed as argument\n", __FUNCTION__);
        abort();
    }

    if (file->package->type == QDL_PKGTYPE_ZIP) {
        zip_error_t *err = zip_file_get_error(file->zip_file);
        if (err->zip_err != ZIP_ER_OK) {
            zip_error_fini(err);
            return 1;
        }
        zip_error_fini(err);
        return 0;
    }

    if (file->package->type == QDL_PKGTYPE_DIR) {
        return ferror(file->file);
    }

    // any other type is an error
    qcomdl_log_error("%s: invalid type %d (%s)\n", __FUNCTION__, file->package->type,
            get_resource_type_name(file->package->type));
    abort();
}

int qcomdl_resource_get_size(qcomdl_resource_file_t *file, uint64_t *size) {
    if (!file || !size) {
        qcomdl_log_error("%s: null file/size passed as argument\n", __FUNCTION__);
        abort();
    }

    if (file->package->type == QDL_PKGTYPE_DIR ||
            file->package->type == QDL_PKGTYPE_ZIP) {
        *size = file->size;
        return 0;
    }

    // any other type is an error
    qcomdl_log_error("%s: invalid type %d (%s)\n", __FUNCTION__, file->package->type,
            get_resource_type_name(file->package->type));
    abort();
}

int qcomdl_resource_package_get_size(qcomdl_resource_package_t *package, const char *dir, const char *filename, uint64_t *size) {
    struct stat st;
    char path[PATH_MAX];

    if (!package || !filename || !size) {
        qcomdl_log_error("%s: null package/filename/size passed as argument\n", __FUNCTION__);
        abort();
    }

    if (join_path(dir, filename, path)) {
        qcomdl_log_error("%s: failed constructing path to file\n", __FUNCTION__);
        return -1;
    }

    if (package->type == QDL_PKGTYPE_ZIP) {
        struct zip_stat stats;
        char *libzip_path = _convert_path_for_libzip(path);
        if (!libzip_path) {
            qcomdl_log_error("%s: failed to convert filename '%s'\n", __FUNCTION__,
                             filename);
            return -1;
        }

        zip_stat_init(&stats);
        int ret = zip_stat(package->zip_archive, libzip_path, ZIP_FL_ENC_GUESS, &stats);
        free(libzip_path);

        if (ret != 0) {
            qcomdl_log_error("%s: zip_stat failed with error '%s'\n", __FUNCTION__,
                             zip_strerror(package->zip_archive));
            return -1;
        }

        if (stats.valid & ZIP_STAT_SIZE) {
            *size = stats.size;
            return 0;
        } else {
            qcomdl_log_error("%s: uncompressed size field in stats was invalid\n",
                             __FUNCTION__);
            return -1;
        }
    }

    if (package->type == QDL_PKGTYPE_DIR) {
        if (stat(path, &st) != 0) {
            qcomdl_log_error("%s: cannot stat %s - %s\n", __FUNCTION__,
                             filename, strerror(errno));
            return -1;
        }

        *size = (uint64_t)st.st_size;
        return 0;
    }

    // any other type is an error
    qcomdl_log_error("%s: invalid type %d (%s)\n", __FUNCTION__, package->type,
            get_resource_type_name(package->type));
    abort();
}

int qcomdl_resource_package_file_exists(qcomdl_resource_package_t *package, const char *dir, const char *filename) {
    char path[PATH_MAX];

    if (!package || !filename) {
        qcomdl_log_error("%s: null package/filename passed as argument\n", __FUNCTION__);
        abort();
    }

    if (join_path(dir, filename, path)) {
        qcomdl_log_error("%s: failed constructing path to file\n", __FUNCTION__);
        return -1;
    }

    if (package->type == QDL_PKGTYPE_ZIP) {
        char *libzip_path = _convert_path_for_libzip(path);
        if (!libzip_path) {
            return -1;
        }

        zip_int64_t ret = zip_name_locate(package->zip_archive, libzip_path, ZIP_FL_ENC_GUESS);
        if (ret >= 0) {
            free(libzip_path);
            return 0;
        } else {
            qcomdl_log_warning("%s: zip_name_locate failed with error '%s'\n",
                    __FUNCTION__, zip_strerror(package->zip_archive));
            free(libzip_path);
            return -1;
        }
    }

    if (package->type == QDL_PKGTYPE_DIR) {
        return access(path, F_OK);
    }

    // any other type is an error
    qcomdl_log_error("%s: invalid type %d (%s)\n", __FUNCTION__, package->type,
            get_resource_type_name(package->type));
    abort();
}

int qcomdl_determine_firehose_path(qcomdl_resource_package_t *package, const char *firehose_filename, bool is_vip, char *path_out, uint32_t path_len)
{
    if (!package) {
        qcomdl_log_error("%s: null package passed as argument\n", __FUNCTION__);
        abort();
    }

    // if the user specified a filename, return its constructed path
    if (firehose_filename && strlen(firehose_filename) > 0) {
        strncpy(path_out, firehose_filename, path_len - 1);
        path_out[path_len - 1] = '\0';
        if (qcomdl_resource_package_file_exists(package, package->img_dir, path_out) == 0) {
            return 0;
        } else {
            path_out = "\0";
            return -1;
        }
    }

    // try each chipset to see what exists
    strncpy(path_out, (is_vip ? FIREHOSE_DEFAULT_VIP_BIN_APQ8039 :
            FIREHOSE_DEFAULT_BIN_APQ8039), path_len - 1);
    path_out[path_len - 1] = '\0';
    if (qcomdl_resource_package_file_exists(package, package->img_dir, path_out) == 0) {
        return 0;
    }

    strncpy(path_out, (is_vip ? FIREHOSE_DEFAULT_VIP_BIN_SDA660 :
            FIREHOSE_DEFAULT_BIN_SDA660), path_len - 1);
    path_out[path_len - 1] = '\0';
    if (qcomdl_resource_package_file_exists(package, package->img_dir, path_out) == 0) {
        return 0;
    }

    // we didn't find one
    *path_out = '\0';
    return -1;
}
