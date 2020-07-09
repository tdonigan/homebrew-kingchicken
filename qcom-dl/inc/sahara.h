// Copyright © 2015-2017 Square, Inc. All rights reserved.

#pragma once

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <libusb.h>

#include <qcomdl.h>
#include <edl.h>
#include "resource.h"

// See Qualcomm document 80-N1008-1 for Sahara Protocol Details
#define SAHARA_MAX_CMD_PACKET_SIZE 16384

#define DLOAD_DEBUG_STRLEN_BYTES 20


// Status of all image transfers
typedef enum
{
    SAHARA_MODE_IMAGE_TX_PENDING  = 0x0,
    SAHARA_MODE_IMAGE_TX_COMPLETE = 0x1,
    SAHARA_MODE_MEMORY_DEBUG      = 0x2,
    SAHARA_MODE_COMMAND           = 0x3,

    // place all new commands above this
    SAHARA_MODE_LAST,
    SAHARA_MODE_MAX = 0x7FFFFFFF
} boot_sahara_mode;


// Sahara command IDs
typedef enum
{
    SAHARA_NO_CMD_ID          = 0x00,
    SAHARA_HELLO_ID           = 0x01, // sent from target to host
    SAHARA_HELLO_RESP_ID      = 0x02, // sent from host to target
    SAHARA_READ_DATA_ID       = 0x03, // sent from target to host
    SAHARA_END_IMAGE_TX_ID    = 0x04, // sent from target to host
    SAHARA_DONE_ID            = 0x05, // sent from host to target
    SAHARA_DONE_RESP_ID       = 0x06, // sent from target to host
    SAHARA_RESET_ID           = 0x07, // sent from host to target
    SAHARA_RESET_RESP_ID      = 0x08, // sent from target to host
    SAHARA_MEMORY_DEBUG_ID    = 0x09, // sent from target to host
    SAHARA_MEMORY_READ_ID     = 0x0A, // sent from host to target
    SAHARA_CMD_READY_ID       = 0x0B, // sent from target to host
    SAHARA_CMD_SWITCH_MODE_ID = 0x0C, // sent from host to target
    SAHARA_CMD_EXEC_ID        = 0x0D, // sent from host to target
    SAHARA_CMD_EXEC_RESP_ID   = 0x0E, // sent from target to host
    SAHARA_CMD_EXEC_DATA_ID   = 0x0F, // sent from host to target
    SAHARA_64_BITS_MEMORY_DEBUG_ID = 0x10, // sent from target to host
    SAHARA_64_BITS_MEMORY_READ_ID = 0x11, // sent from host to target
    SAHARA_64_BITS_READ_DATA_ID = 0x12, // sent from target to host (found in emmcdl.win but not sbl)

    // place all new commands above this
    SAHARA_LAST_CMD_ID,
    SAHARA_MAX_CMD_ID             = 0x7FFFFFFF // To ensure 32-bits wide
} boot_sahara_cmd_id;


// Status codes for Sahara
typedef enum
{
    // Success
    SAHARA_STATUS_SUCCESS =                     0x00,

    // Invalid command received in current state
    SAHARA_NAK_INVALID_CMD =                    0x01,

    // Protocol mismatch between host and target
    SAHARA_NAK_PROTOCOL_MISMATCH =              0x02,

    // Invalid target protocol version
    SAHARA_NAK_INVALID_TARGET_PROTOCOL =        0x03,

    // Invalid host protocol version
    SAHARA_NAK_INVALID_HOST_PROTOCOL =          0x04,

    // Invalid packet size received
    SAHARA_NAK_INVALID_PACKET_SIZE =            0x05,

    // Unexpected image ID received
    SAHARA_NAK_UNEXPECTED_IMAGE_ID =            0x06,

    // Invalid image header size received
    SAHARA_NAK_INVALID_HEADER_SIZE =            0x07,

    // Invalid image data size received
    SAHARA_NAK_INVALID_DATA_SIZE =              0x08,

    // Invalid image type received
    SAHARA_NAK_INVALID_IMAGE_TYPE =             0x09,

    // Invalid tranmission length
    SAHARA_NAK_INVALID_TX_LENGTH =              0x0A,

    // Invalid reception length
    SAHARA_NAK_INVALID_RX_LENGTH =              0x0B,

    // General transmission or reception error
    SAHARA_NAK_GENERAL_TX_RX_ERROR =            0x0C,

    // Error while transmitting READ_DATA packet
    SAHARA_NAK_READ_DATA_ERROR =                0x0D,

    // Cannot receive specified number of program headers
    SAHARA_NAK_UNSUPPORTED_NUM_PHDRS =          0x0E,

    // Invalid data length received for program headers
    SAHARA_NAK_INVALID_PDHR_SIZE =              0x0F,

    // Multiple shared segments found in ELF image
    SAHARA_NAK_MULTIPLE_SHARED_SEG =            0x10,

    // Uninitialized program header location
    SAHARA_NAK_UNINIT_PHDR_LOC =                0x11,

    // Invalid destination address
    SAHARA_NAK_INVALID_DEST_ADDR =              0x12,

    // Invalid data size receieved in image header
    SAHARA_NAK_INVALID_IMG_HDR_DATA_SIZE =      0x13,

    // Invalid ELF header received
    SAHARA_NAK_INVALID_ELF_HDR =                0x14,

    // Unknown host error received in HELLO_RESP
    SAHARA_NAK_UNKNOWN_HOST_ERROR =             0x15,

    // Timeout while receiving data
    SAHARA_NAK_TIMEOUT_RX =                     0x16,

    // Timeout while transmitting data
    SAHARA_NAK_TIMEOUT_TX =                     0x17,

    // Invalid mode received from host
    SAHARA_NAK_INVALID_HOST_MODE =              0x18,

    // Invalid memory read access
    SAHARA_NAK_INVALID_MEMORY_READ =            0x19,

    // Host cannot handle read data size requested
    SAHARA_NAK_INVALID_DATA_SIZE_REQUEST =      0x1A,

    // Memory debug not supported
    SAHARA_NAK_MEMORY_DEBUG_NOT_SUPPORTED =     0x1B,

    // Invalid mode switch
    SAHARA_NAK_INVALID_MODE_SWITCH =            0x1C,

    // Failed to execute command
    SAHARA_NAK_CMD_EXEC_FAILURE =               0x1D,

    // Invalid parameter passed to command execution
    SAHARA_NAK_EXEC_CMD_INVALID_PARAM =         0x1E,

    // Unsupported client command received
    SAHARA_NAK_EXEC_CMD_UNSUPPORTED =           0x1F,

    // Invalid client command received for data response
    SAHARA_NAK_EXEC_DATA_INVALID_CLIENT_CMD =   0x20,

    // Failed to authenticate hash table
    SAHARA_NAK_HASH_TABLE_AUTH_FAILURE =        0x21,

    // Failed to verify hash for a given segment of ELF image
    SAHARA_NAK_HASH_VERIFICATION_FAILURE =      0x22,
    
    // Failed to find hash table in ELF image
    SAHARA_NAK_HASH_TABLE_NOT_FOUND =           0x23,
    
    // Place all new error codes above this
    SAHARA_NAK_LAST_CODE,
    
    SAHARA_NAK_MAX_CODE = 0x7FFFFFFF // To ensure 32-bits wide
} boot_sahara_status;


// Executable commands when target is in command mode
typedef enum
{
    SAHARA_EXEC_CMD_NOP              = 0x00,
    SAHARA_EXEC_CMD_SERIAL_NUM_READ  = 0x01,
    SAHARA_EXEC_CMD_MSM_HW_ID_READ   = 0x02,
    SAHARA_EXEC_CMD_OEM_PK_HASH_READ = 0x03,
    SAHARA_EXEC_CMD_SWITCH_DMSS      = 0x04,
    SAHARA_EXEC_CMD_SWITCH_STREAMING = 0x05,
    SAHARA_EXEC_CMD_READ_DEBUG_DATA  = 0x06,
    SAHARA_EXEC_CMD_GET_SOFTWARE_VERSION_SBL = 0x07, // This value is from emmcdl.win source (not found in sbl)

    // place all new commands above this
    SAHARA_EXEC_CMD_LAST,
    SAHARA_EXEC_CMD_MAX = 0x7FFFFFFF
} boot_sahara_exec_cmd_id;


typedef struct __attribute__((packed))
{
    uint32_t command;                 // command ID
    uint32_t length;                  // packet length incl command and length
} sahara_packet_header;


// HELLO command packet type - sent from target to host
//   indicates start of protocol on target side
typedef struct __attribute__((packed))
{
    sahara_packet_header header;
    uint32_t version;                 // target protocol version number
    uint32_t version_supported;       // minimum protocol version number supported on target
    uint32_t target_cmd_pkt_length;   // maximum packet size supported for command packets
    uint32_t mode;                    // expected mode of target operation
    uint32_t reserved0;               // reserved field
    uint32_t reserved1;               // reserved field
    uint32_t reserved2;               // reserved field
    uint32_t reserved3;               // reserved field
    uint32_t reserved4;               // reserved field
    uint32_t reserved5;               // reserved field
} sahara_packet_hello;


// HELLO_RESP command packet type - sent from host to target
//   response to hello, protocol version running on host and status sent
typedef struct __attribute__((packed))
{
    sahara_packet_header header;
    uint32_t version;                 // host protocol version number
    uint32_t version_supported;       // minimum protocol version number supported on host
    uint32_t status;                  // OK or error condition
    uint32_t mode;                    // mode of operation for target to execute
    uint32_t reserved0;               // reserved field
    uint32_t reserved1;               // reserved field
    uint32_t reserved2;               // reserved field
    uint32_t reserved3;               // reserved field
    uint32_t reserved4;               // reserved field
    uint32_t reserved5;               // reserved field
} sahara_packet_hello_resp;


// READ_DATA command packet type - sent from target to host
//   sends data segment offset and length to be read from current host
//   image file
typedef struct __attribute__((packed))
{
    sahara_packet_header header;
    uint32_t image_id;                // ID of image to be transferred
    uint32_t data_offset;             // offset into image file to read data from
    uint32_t data_length;             // length of data segment to be retreived from image file
} sahara_packet_read_data;

typedef struct __attribute__((packed))
{
    sahara_packet_header header;
    uint64_t image_id;                // ID of image to be transferred
    uint64_t data_offset;             // offset into image file to read data from
    uint64_t data_length;             // length of data segment to be retreived from image file
} sahara_packet_64_bit_read_data;


// END_IMAGE_TX command packet type - sent from target to host
//   indicates end of a single image transfer and status of transfer
typedef struct __attribute__((packed))
{
    sahara_packet_header header;
    uint32_t image_id;                // ID of image to be transferred
    uint32_t status;                  // OK or error condition
} sahara_packet_end_image_tx;


// DONE packet type - sent from host to target
//   indicates end of single image transfer
typedef struct __attribute__((packed))
{
    sahara_packet_header header;
} sahara_packet_done;


// DONE_RESP packet type - sent from target to host
//   indicates end of all image transfers
typedef struct __attribute__((packed))
{
    sahara_packet_header header;
    uint32_t image_tx_status;         // indicates if all images have been transferred
    // 0 = IMAGE_TX_PENDING
    // 1 = IMAGE_TX_COMPLETE
} sahara_packet_done_resp;


// RESET packet type - sent from host to target
//   indicates to target to reset
typedef struct __attribute__((packed))
{
    sahara_packet_header header;
} sahara_packet_reset;


// RESET_RESP packet type - sent from target to host
//   indicates to host that target has reset
typedef struct __attribute__((packed))
{
    sahara_packet_header header;
} sahara_packet_reset_resp;


// MEMORY_DEBUG packet type - sent from target to host
//   sends host the location and length of memory region table
typedef struct __attribute__((packed))
{
    sahara_packet_header header;
    uint32_t memory_table_addr;       // location of memory region table
    uint32_t memory_table_length;     // length of memory table
} sahara_packet_memory_debug;

typedef struct __attribute__((packed))
{
    sahara_packet_header header;
    uint64_t memory_table_addr;       // location of memory region table
    uint64_t memory_table_length;     // length of memory table
} sahara_packet_64_bit_memory_debug;


// Debug structure for 32 and 64 bit memory regions.
// This is the structure of entries in the memory region table
// located at the address in the Sahara memory debug packet.
// The Sahara doc does not properly include these. It could be
// because they are chipset specific?
typedef struct __attribute__((packed))
{
    uint32_t save_pref;
    uint32_t mem_base;
    uint32_t length;
    char desc[DLOAD_DEBUG_STRLEN_BYTES];
    char filename[DLOAD_DEBUG_STRLEN_BYTES];
} dload_debug_type;

typedef struct __attribute__((packed))
{
    uint64_t save_pref;
    uint64_t mem_base;
    uint64_t length;
    char desc[DLOAD_DEBUG_STRLEN_BYTES];
    char filename[DLOAD_DEBUG_STRLEN_BYTES];
} dload_64_bit_debug_type;


// MEMORY_READ packet type - sent from host to target
//   sends memory address and length to read from target memory
typedef struct __attribute__((packed))
{
    sahara_packet_header header;
    uint32_t memory_addr;             // memory location to read from
    uint32_t memory_length;           // length of data to send
} sahara_packet_memory_read;

typedef struct __attribute__((packed))
{
    sahara_packet_header header;
    uint64_t memory_addr;             // memory location to read from
    uint64_t memory_length;           // length of data to send
} sahara_packet_64_bit_memory_read;


// CMD_READY packet type - sent from target to host
//   indicates to host that target is ready to accept commands
typedef struct __attribute__((packed))
{
    sahara_packet_header header;
} sahara_packet_cmd_ready;


// CMD_SWITCH_MODE packet type - sent from host to target
//   indicates to target to switch modes
typedef struct __attribute__((packed))
{
    sahara_packet_header header;
    uint32_t mode;                    // mode of operation for target to execute
} sahara_packet_cmd_switch_mode;


// CMD_EXEC packet type - sent from host to target
//   indicates to target to execute given client_command
typedef struct __attribute__((packed))
{
    sahara_packet_header header;
    uint32_t client_command;          // command ID for target Sahara client to execute
} sahara_packet_cmd_exec;


// CMD_EXEC_RESP packet type - sent from host to target
//   indicates to host that target has successfully executed command
//     and length of data response
typedef struct __attribute__((packed))
{
    sahara_packet_header header;
    uint32_t client_command;          // command ID for target Sahara client to execute
    uint32_t resp_length;             // length of response returned from command execution
} sahara_packet_cmd_exec_resp;


// CMD_EXEC_DATA packet type - sent from target to host
//   indicates that host is ready to receive data after command execution
typedef struct __attribute__((packed))
{
    sahara_packet_header header;
    uint32_t client_command;          // command ID for target Sahara client to execute
} sahara_packet_cmd_exec_data;


// Used to return data for the sahara_device_info function
typedef struct {
    uint32_t serial;
    uint32_t msm_id;
    uint8_t pk_hash[32];
    uint32_t pbl_sw;
} pbl_info_t;


struct sahara_connection {
    libusb_device_handle *usb_dev;

    int host_state; // Used to track state in the host state machine

    // max packet length and current mode from target's hello
    uint32_t target_cmd_pkt_length; // Note: It's not clear how this is supposed to be used
    uint32_t target_current_mode;

    // Memory table and length are captured by the handler for
    // memory debug commands. The target indicates the
    // location of regions that should be captured in case
    // of a crash.
    void *memory_table;
    uint64_t memory_table_length;

    // Stored by the state machine to indicate the cmd_exec_resp data size
    // the target reports
    uint32_t target_cmd_exec_resp_length;

    // The program file handle should be opened, read-only while uploading
    // the flash programmer. It should be set to NULL at all other times.
    qcomdl_resource_file_t *program_file;

    // Indicates whether the target expects 64-bit variants of certain commands
    bool target_is_64bit;

    uint8_t packet_buffer[SAHARA_MAX_CMD_PACKET_SIZE];
};


typedef struct sahara_connection sahara_connection_t;

QCOMDL_API
sahara_connection_t *sahara_connect(edl_connection_t *edl_conn);

QCOMDL_API
void sahara_connection_free(sahara_connection_t *sahara_conn);

QCOMDL_API
int sahara_device_reset(sahara_connection_t *conn);

QCOMDL_API
int sahara_device_info(sahara_connection_t *conn, pbl_info_t *pbl_info);

QCOMDL_API
int sahara_read_debug_data(sahara_connection_t *conn, uint8_t **data_buf, int *data_buf_size);

QCOMDL_API
int sahara_upload(sahara_connection_t *conn, qcomdl_resource_package_t *package, const char *firehose_path);

QCOMDL_API
int sahara_enter_memory_debug(sahara_connection_t *conn);

QCOMDL_API
int sahara_memory_dump_table(sahara_connection_t *conn, const char *outdir);

QCOMDL_API
int sahara_memory_read_to_file(sahara_connection_t *conn, uint64_t addr, uint64_t length, const char *outpath);

QCOMDL_API
int sahara_memory_read(sahara_connection_t *conn, uint64_t addr, uint64_t len, uint8_t **buf_out, size_t *buf_out_size);

QCOMDL_API
int sahara_done(sahara_connection_t *conn);

