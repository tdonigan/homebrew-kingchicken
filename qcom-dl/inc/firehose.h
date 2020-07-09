// Copyright © 2015-2017 Square, Inc. All rights reserved.

#pragma once

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <libusb.h>

#include <edl.h>
#include <qcomdl.h>
#include "resource.h"

#define FIREHOSE_MAX_CONFIG_TRIES 2
#define FIREHOSE_SECTOR_SIZE 512

// This is the max payload size supported by EDL on the 8939 chip
// another value may be attempted, but it will end up negotiating this
// value anyway if it is higher or lower.
#define FIREHOSE_DEFAULT_PAYLOAD_SIZE 16384
#define FIREHOSE_MAX_MBN_DIGESTS 54

#define FIREHOSE_DIGEST_SIZE 32
#define FIREHOSE_MAX_DIGEST_TABLE_COUNT (INT_MAX / FIREHOSE_DIGEST_SIZE)
#define FIREHOSE_DEFAULT_DIGEST_TABLE_SIZE (FIREHOSE_DIGEST_SIZE * 256)
#define FIREHOSE_DEFAULT_DIGEST_TABLE_FILENAME "signed_digest_table.mbn"
#define FIREHOSE_DEFAULT_CHAINED_DIGESTS_FILENAME "chained_digests.bin"

#define FIREHOSE_DEFAULT_PROGRAM_XML_FILENAME "rawprogram_unsparse.xml"
#define FIREHOSE_DEFAULT_PATCH_XML_FILENAME "patch0.xml"
#define FIREHOSE_DEFAULT_VIP_XML_FILENAME "vip_commands.xml"

#define FIREHOSE_DEFAULT_BIN_APQ8039 "prog_emmc_firehose_8936.mbn"
#define FIREHOSE_DEFAULT_VIP_BIN_APQ8039 "validated_emmc_firehose_8936.mbn"

#define FIREHOSE_DEFAULT_BIN_SDA660 "prog_emmc_ufs_firehose_Sdm660_ddr.elf"
#define FIREHOSE_DEFAULT_VIP_BIN_SDA660 "validated_emmc_ufs_firehose_Sdm660_ddr.elf"

#define FIREHOSE_DEFAULT_PCT_LOGGING_GRANULARITY 10
// When flashing completes, we send a reset command with a 2 second delay (on the DUT side)
// This is to give libusb adequate time to tear down all its internal structures and pending
// queued transactions cleanly before the device disappears on USB.
#define FIREHOSE_DEFAULT_RESET_DELAY_SECS 2



struct firehose_configuration {
    // Response timeout for firehose commands
    unsigned int timeout;

    // The number of tries on a given configuration
    int tries;

    /* The following fields are not explicitly documented */

    // Seen in QFIL captures as MemoryName="eMMC" from both host and target
    char *MemoryName;

    // TargetName - Seen in QFIL captures as
    //  TargetName="8x26" from Host
    //  TargetName="8936" from Target
    char *TargetName;

    // ZlpAwareHost - seen in QFIL captures as ZlpAwareHost="1"
    // "zero-length-packet aware host" We should send this.
    int ZlpAwareHost;

    // SkipStorageInit - seen in QFIL captures as SkipStorageInit="0"
    int SkipStorageInit;

    // MinVersionSupported
    int MinVersionSupported;

    // Version
    int Version;

    /* Fields documented in "80-NG319-1 Firehose Protocol.pdf" from here on */

    // AckRawDataEveryNumPackets
    // Causes the target to send an ACK after every "Num" RAW DATA packets has been sent
    // This can be used to throttle the host or get periodic feedback on very large file transfers.
    int AckRawDataEveryNumPackets;

    // SkipWrite
    // Causes the target to skip writing the data to disk. Allows you to benchmark the performance of USB
    int SkipWrite;

    // AlwaysValidate -  Causes the validation operation to occur on every data packet.
    // (note: VIP is not enabled by this)
    // This is used to see the impact of validation (hashing) without needing to enable secure boot
    int AlwaysValidate;

    // Verbose - causes the target to send many more logs to the host
    int Verbose;

    // MaxDigestTableSizeInBytes - Used with VIP; indicates maximum size of the Digest table, i.e. 8KB
    int MaxDigestTableSizeInBytes;

    // Maximum RAW DATA payload size supported to be received by target, must be multiple of 512
    int MaxPayloadSizeToTargetInBytes;


    /* Fields only responded by Target -> Host from here on */

    // MaxPayloadSizeToTargetInBytesSupported - Target may report a higher payload size than specified
    // by the Host if it is supported. Host may then send a configuration command to use this size.
    int MaxPayloadSizeToTargetInBytesSupported;

    // Maximum RAW DATA payload size that will be sent from target. (also multiple of 512?)
    int MaxPayloadSizeFromTargetInBytes;

    // MaxXMLSizeInBytes - seen in QFIL Captures, not documented
    int MaxXMLSizeInBytes;
};


// firehose_file_progress_api:
// This api specifies callback interfaces to get progress information about image uploads as they
// are occuring on a per file basis.
// See firehose_register_file_progress_handlers for info on how they to set them and an opaque
// user context which will be passed to them whenever any are called.
// The use of the API as well as all of the handlers are "optional", that is they may be set to NULL
// in which case nothing will get called.
struct firehose_file_progress_api {
    // handle_start_sectors_from_file is called by firehose_program_file() or under the hood
    // in both vip and non-vip modes for each file as uploading of that file commences.
    // The callback receives the name of the file along with the number of expected sectors
    // If this returns false, it causes the transfer to be interrupted with an error.
    bool (*handle_start_sectors_from_file)(const char *file, size_t file_sectors, void *ctx);

    // handle_sent_file_sectors is called by firehose_program_file() or under the hood
    // in both vip and non-vip modes during the image and receives the current filename
    // and the number of sectors that have been written for that chunk. This one gets called alot.
    // If this returns false, it causes the transfer to be interrupted with an error.
    bool (*handle_sent_file_sectors)(const char *file, size_t sectors_written, void *ctx);

    // handle_finshed_sectors_from_file is called by firehose_program_file() or under the hood
    // in both vip and non-vip modes when a file upload completes and includes the
    // result of the image upload (non-zero for failure) and the total number of sectors sent.
    //
    // If this returns false, it causes the transfer to be interrupted with an error.
    bool (*handle_finished_sectors_from_file)(const char *file, int result, size_t total_sectors_written, void *ctx);
};


// firehose_total__progress_api
// This api specifies callback interfaces to get progress information about image uploads
// represented as a percentage of the total image transfer.
// The use of the API as well as all of the handlers are "optional", that is they may be set to NULL
// in which case nothing will get called.
//
// See firehose_register_percent_progress_handlers for how to set the callback
//
// Note: the percent progress api is currently implemented on top of the file progress API. This means
// the two are also currently mutually exclusive.
struct firehose_percent_progress_api {
    // The following fields are set internally by firehose_register_percent_progress_handlers
    // and they should not be set by callers
    void *_internal_ctx;
    int _internal_last_percent;
    size_t _internal_total_progess_sectors;
    size_t _internal_last_file_sectors_written;

    // When calling firehose_register_percent_progress_handlers the caller must set
    // total_image_sectors in the struct to the correct value in order to base percentage
    // calculations off of it.
    size_t total_image_sectors;

    // handle_progess_percent receives a callback containing a value between 0 and 100. If the
    // handler returns false, the transfer will be interrupted with an error.
    bool (*handle_progress_percent)(int current_percent, void *ctx);
};


struct firehose_connection {
    libusb_device_handle *usb_dev;
    struct firehose_configuration cfg;
    char *memory_name;
    char *target_name;

    bool vip_enabled; // this is set internally by firehose_vip() and should not be set by callers

    qcomdl_resource_file_t *vip_chained_digests_file;
    size_t vip_digests_chunk_left;
    size_t vip_total_packet_count;

    struct firehose_file_progress_api file_progress_handlers;
    void *file_progress_ctx;

    struct firehose_percent_progress_api percent_progress_handlers;
    void *percent_progress_ctx;
};

typedef struct firehose_connection firehose_connection_t;


#pragma mark Configuration Command Attribute Constants

extern QCOMDL_API const u_char *firehoseAttrCfgAckRawDataEveryNumPackets;
extern QCOMDL_API const u_char *firehoseAttrCfgAlwaysValidate;
extern QCOMDL_API const u_char *firehoseAttrCfgMaxDigestTableSizeInBytes;
extern QCOMDL_API const u_char *firehoseAttrCfgMaxPayloadSizeFromTargetInBytes;
extern QCOMDL_API const u_char *firehoseAttrCfgMaxPayloadSizeToTargetInBytes;
extern QCOMDL_API const u_char *firehoseAttrCfgMaxPayloadSizeToTargetInBytesSupported;
extern QCOMDL_API const u_char *firehoseAttrCfgMaxXMLSizeInBytes;
extern QCOMDL_API const u_char *firehoseAttrCfgMemoryName;
extern QCOMDL_API const u_char *firehoseAttrCfgMinVersionSupported;
extern QCOMDL_API const u_char *firehoseAttrCfgSkipStorageInit;
extern QCOMDL_API const u_char *firehoseAttrCfgSkipWrite;
extern QCOMDL_API const u_char *firehoseAttrCfgTargetName;
extern QCOMDL_API const u_char *firehoseAttrCfgVerbose;
extern QCOMDL_API const u_char *firehoseAttrCfgVersion;
extern QCOMDL_API const u_char *firehoseAttrCfgZlpAwareHost;


#pragma mark Program Command Attribute Constants

extern QCOMDL_API const u_char *firehoseAttrProgFilename;
extern QCOMDL_API const u_char *firehoseAttrProgLabel;
extern QCOMDL_API const u_char *firehoseAttrProgSectorSizeInBytes;
extern QCOMDL_API const u_char *firehoseAttrProgNumPartitionSectors;
extern QCOMDL_API const u_char *firehoseAttrProgStartSector;
extern QCOMDL_API const u_char *firehoseAttrProgPhysicalPartitionNum;
extern QCOMDL_API const u_char *firehoseAttrProgReadBackVerify;


#pragma mark Erase Command Attribute Constants

extern QCOMDL_API const u_char *firehoseAttrEraseStorageDrive;


#pragma mark GetStorageInfo Command Attribute Constants

extern const u_char *firehoseAttrGetStorageInfoPhysicalPartitionNum;


#pragma mark Poke/Peek Command Attribute Constants

extern const u_char *firehoseAttrPeekPokeSizeInBytes;
extern const u_char *firehoseAttrPeekPokeAddress64;
extern const u_char *firehoseAttrPeekPokeValue;


#pragma mark Patch Command Attribute Constants

extern QCOMDL_API const u_char *firehoseAttrPatchSectorSizeInBytes;
extern QCOMDL_API const u_char *firehoseAttrPatchByteOffset;
extern QCOMDL_API const u_char *firehoseAttrPatchSizeInBytes;
extern QCOMDL_API const u_char *firehoseAttrPatchFilename;
extern QCOMDL_API const u_char *firehoseAttrPatchPhysicalPartitionNum;
extern QCOMDL_API const u_char *firehoseAttrPatchStartSector;
extern QCOMDL_API const u_char *firehoseAttrPatchValue;
extern QCOMDL_API const u_char *firehoseAttrPatchWhat;


#pragma mark Firehose connection/disconnection tasks

QCOMDL_API
firehose_connection_t *firehose_connect(edl_connection_t *edl_conn);

QCOMDL_API
void firehose_connection_free(firehose_connection_t *conn);


#pragma mark Firehose command tasks

QCOMDL_API
int firehose_send_command(firehose_connection_t *conn, uint8_t *xml, int xml_size);

QCOMDL_API
int firehose_ping(firehose_connection_t *conn);

QCOMDL_API
int firehose_configure(firehose_connection_t *conn);

QCOMDL_API
int firehose_setbootablestoragedrive(firehose_connection_t *conn, int value);

QCOMDL_API
int firehose_erase(firehose_connection_t *conn, int storagedrive);

QCOMDL_API
int firehose_rpmb_erase(firehose_connection_t *conn);

QCOMDL_API
int firehose_power(firehose_connection_t *conn, char *value, int delay_secs);

QCOMDL_API
int firehose_getstorageinfo(firehose_connection_t *conn, int partition_num);

QCOMDL_API
int firehose_peek(firehose_connection_t *conn, uint64_t addr64, size_t size_in_bytes);

QCOMDL_API
int firehose_poke(firehose_connection_t *conn, uint64_t addr64, size_t size_in_bytes, uint64_t value);

QCOMDL_API
int firehose_benchmark(firehose_connection_t *conn, int trials, unsigned int timeout_msec);

QCOMDL_API
int firehose_program(firehose_connection_t *conn,
                     qcomdl_resource_package_t *package,
                     const char *filename,
                     u_char *start_sector,
                     u_char *physical_partition_number,
                     int read_back_verify);

QCOMDL_API
int firehose_getsha256digest(firehose_connection_t *conn,
                             int num_partition_sectors,
                             u_char *start_sector,
                             u_char *physical_partition_number);

QCOMDL_API
int firehose_patch(firehose_connection_t *conn,
                   u_char *byte_offset,
                   u_char *physical_partition_number,
                   u_char *size_in_bytes,
                   u_char *start_sector,
                   u_char *value,
                   u_char *what);

QCOMDL_API
int firehose_program_from_file(firehose_connection_t *conn, qcomdl_resource_package_t *package, const char *program_xml_path, int read_back_verify);

QCOMDL_API
int firehose_getsha256digests_from_file(firehose_connection_t *conn, qcomdl_resource_package_t *package, const char *program_xml_path);

QCOMDL_API
int firehose_patch_from_file(firehose_connection_t *conn, qcomdl_resource_package_t *package, const char *patch_xml_path);

QCOMDL_API
int firehose_non_vip(firehose_connection_t *fh_conn,
                     qcomdl_resource_package_t *package,
                     const char *program_xml,
                     const char *patch_xml,
                     bool do_erase,
                     bool read_back_verify,
                     bool do_sha256,
                     int reset_delay,
                     bool do_rpmb_erase);

QCOMDL_API
int firehose_vip(firehose_connection_t *conn,
                 qcomdl_resource_package_t *package,
                 const char *vip_xml,
                 const char *digest_table,
                 const char *chained_digests);

QCOMDL_API
int firehose_register_file_progress_handlers(firehose_connection_t *conn, const struct firehose_file_progress_api *handlers, void *user_ctx);

QCOMDL_API
int firehose_register_percent_progress_handlers(firehose_connection_t *conn, const struct firehose_percent_progress_api *handlers, void *user_ctx);


QCOMDL_API
ssize_t firehose_total_image_sectors_vip(qcomdl_resource_package_t *package, const char *vip_xml);

QCOMDL_API
ssize_t firehose_total_image_sectors_non_vip(qcomdl_resource_package_t *package, const char *program_xml);

QCOMDL_API
int firehose_verify_vip(qcomdl_resource_package_t *package,
                        const char *vip_xml,
                        const char *digest_table,
                        const char *chained_digests);
