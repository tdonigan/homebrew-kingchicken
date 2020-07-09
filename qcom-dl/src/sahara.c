// Copyright © 2015-2017 Square, Inc. All rights reserved.

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>

#include "edl.h"
#include "qcomdl_log.h"
#include "resource.h"
#include "sahara.h"

#define SAHARA_XFER_TIMEOUT_MS 1000 // 1 sec

// A maximum sane length for memory read requests in diagnostic mode
#define SAHARA_MAX_MEMORY_READ_LENGTH 0x100000 // 1mb

typedef enum {
    SAHARA_HANDLER_RESULT_ERROR = -1,
    SAHARA_HANDLER_RESULT_CONTINUE,
    SAHARA_HANDLER_RESULT_BREAK,
} sahara_handler_result;


enum sahara_host_state {
    SAHARA_STATE_ENTRY,
    SAHARA_STATE_EXIT,

    /*
     WAIT_HELLO - The host waits for the target to initiate the protocol. Once the Hello is
     received and the protocol version validated, the host sends a Hello Response with “success”
     status. If the host receives an invalid packet (or any other packet), it sends a Reset packet to
     the target. It also sends a Reset packet if the target protocol version is not compatible with the
     host.
     */
    SAHARA_STATE_WAIT_HELLO,
    SAHARA_STATE_RECV_HELLO,

    /*
     WAIT_COMMAND – If the host receives a Read Data packet, it reads and transfers data
     from the corresponding image in a data packet. If the host receives an End of Image Transfer
     packet with “success” status, it sends a Done packet. If the host receives a Command Ready
     packet, it enters the Command sequence. If the host receives a Memory Debug packet, it
     enters the Memory Debug sequence. If the host receives an invalid command (or any other
     command), it sends a Reset packet. It also sends a Reset packet if it receives an End of Image
     Transfer packet with an error code.
     */
    SAHARA_STATE_WAIT_COMMAND,
    SAHARA_STATE_RECV_COMMAND,

    /*
     WAIT_DONE_RESP – The host waits for a Done Response. If all images have not been
     transferred, the host waits for another Hello packet. If all images have been transferred, the
     host exits the protocol. If the host receives an invalid command (or any other command), it
     sends a Reset packet.
     */
    SAHARA_STATE_WAIT_DONE_RESP,
    SAHARA_STATE_RECV_DONE_RESP,

    /*
     WAIT_RESET_RESP – After the host sends a Reset packet, it waits for the target to send a
     Reset Response. If the host receives a Reset Response, it exits the protocol. If the host
     receives an invalid command (or any other command), it sends another Reset packet.
     */
    SAHARA_STATE_WAIT_RESET_RESP,
    SAHARA_STATE_RECV_RESET_RESP,

    /*
     WAIT_MEMORY_TABLE – Once the host sends a Memory Read packet to read the
     memory debug table, it waits for a Raw Data packet with the contents of the table.
     */
    SAHARA_STATE_WAIT_MEMORY_TABLE,
    SAHARA_STATE_RECV_MEMORY_TABLE,

    /*
     WAIT_MEMORY_REGION – After receiving the memory debug table, the host repeatedly
     sends Memory Read packets to dump each memory region from the target. Once all the
     memory regions are received, it sends either a Reset command or Command Switch Mode
     command to the target.
     */
    SAHARA_STATE_WAIT_MEMORY_REGION,
    SAHARA_STATE_RECV_MEMORY_REGION,

    /*
     WAIT_CMD_EXEC_RESP – After receiving the Command Ready packet, the host proceeds
     to execute a series of client commands by sending Command Execute packets to the target.
     Once all commands have been executed and the corresponding data received, the host can
     switch the mode of the target and re-initiate the protocol by waiting for a Hello packet. If the
     host receives invalid raw data or an End of Image Transfer packet, it sends a Reset packet.
     */
    SAHARA_STATE_WAIT_CMD_EXEC_RESP,
    SAHARA_STATE_RECV_CMD_EXEC_RESP,

    /*
     IMAGE_TX_* - These states are used during image file transfer (uploading the flash programmer)
     */
    SAHARA_STATE_IMAGE_TX_IN_PROGRESS,
    SAHARA_STATE_IMAGE_TX_SUCCESS,
    SAHARA_STATE_IMAGE_TX_FAILURE,
};


static int sahara_process_packets(sahara_connection_t *conn);


#pragma mark Private Helpers

struct xfer_ctx {
    bool pending;
    int transferred;
    const char *direction;
};

static void LIBUSB_CALL bulk_cb(struct libusb_transfer *transfer)
{
    struct xfer_ctx *ctx = transfer->user_data;
    if (!ctx) {
        qcomdl_log_error("no context supplied to libusb transfer callback\n");
        return;
    }

    if (transfer->status == LIBUSB_TRANSFER_COMPLETED) {
        ctx->transferred = transfer->actual_length;
    } else {
        qcomdl_log_error("%s (0x%x) transfer status: (%i) %s\n", ctx->direction, transfer->endpoint, transfer->status, libusb_error_name((int) transfer->status));
    }
    ctx->pending = false;
}


// We implement our own bulk_xfer to avoid some of the state assumptions made by libusb_bulk_transfer
// regarding when read or writes are permissible.
static int bulk_xfer(libusb_device_handle *usb_dev, void *buf, int buf_size, unsigned char endpoint)
{
    const char *direction = "[unknown direction]";
    if (endpoint == EDL_ENDPOINT_BULK_IN) {
        direction = "IN";
    } else if (endpoint == EDL_ENDPOINT_BULK_OUT) {
        direction = "OUT";
    }

    struct xfer_ctx ctx = {.pending = true, .transferred = -1, .direction = direction};
    struct libusb_transfer *xfer = libusb_alloc_transfer(0);
    if (!xfer) {
        qcomdl_log_error("unable to allocate a libusb transfer\n");
        return -1;
    }

    libusb_fill_bulk_transfer(xfer,
                              usb_dev,
                              endpoint,
                              buf,
                              buf_size,
                              bulk_cb,
                              &ctx,
                              SAHARA_XFER_TIMEOUT_MS);

    int r = libusb_submit_transfer(xfer);
    if (r != LIBUSB_SUCCESS) {
        qcomdl_log_error("unable to submit %s transfer: (%i) %s\n", direction, r, libusb_strerror(r));
        libusb_free_transfer(xfer);
        return -1;
    }

    while (ctx.pending) {
        r = libusb_handle_events(NULL);

        if (r != LIBUSB_SUCCESS) {
            qcomdl_log_error("libusb handle event error for %s transfer: (%i) %s\n", direction, r, libusb_strerror(r));
            break;
        }
    }

    libusb_free_transfer(xfer);
    return ctx.transferred;
}


static int read_bulk(libusb_device_handle *usb_dev, void *buf, int buf_size)
{
    return bulk_xfer(usb_dev, buf, buf_size, EDL_ENDPOINT_BULK_IN);
}


static int write_bulk(libusb_device_handle *usb_dev, void *buf, int buf_size)
{
    return bulk_xfer(usb_dev, buf, buf_size, EDL_ENDPOINT_BULK_OUT);
}


static const char *sahara_strerror(uint32_t status)
{
    switch (status) {
        case SAHARA_STATUS_SUCCESS:                     return "Success";
        case SAHARA_NAK_INVALID_CMD:                    return "Invalid command received in current state";
        case SAHARA_NAK_PROTOCOL_MISMATCH:              return "Protocol mismatch between host and target";
        case SAHARA_NAK_INVALID_TARGET_PROTOCOL:        return "Invalid target protocol version";
        case SAHARA_NAK_INVALID_HOST_PROTOCOL:          return "Invalid host protocol version";
        case SAHARA_NAK_INVALID_PACKET_SIZE:            return "Invalid packet size received";
        case SAHARA_NAK_UNEXPECTED_IMAGE_ID:            return "Unexpected image ID received";
        case SAHARA_NAK_INVALID_HEADER_SIZE:            return "Invalid image header size received";
        case SAHARA_NAK_INVALID_DATA_SIZE:              return "Invalid image data size received";
        case SAHARA_NAK_INVALID_IMAGE_TYPE:             return "Invalid image type received";
        case SAHARA_NAK_INVALID_TX_LENGTH:              return "Invalid tranmission length";
        case SAHARA_NAK_INVALID_RX_LENGTH:              return "Invalid reception length";
        case SAHARA_NAK_GENERAL_TX_RX_ERROR:            return "General transmission or reception error";
        case SAHARA_NAK_READ_DATA_ERROR:                return "Error while transmitting READ_DATA packet";
        case SAHARA_NAK_UNSUPPORTED_NUM_PHDRS:          return "Cannot receive specified number of program headers";
        case SAHARA_NAK_INVALID_PDHR_SIZE:              return "Invalid data length received for program headers";
        case SAHARA_NAK_MULTIPLE_SHARED_SEG:            return "Multiple shared segments found in ELF image";
        case SAHARA_NAK_UNINIT_PHDR_LOC:                return "Uninitialized program header location";
        case SAHARA_NAK_INVALID_DEST_ADDR:              return "Invalid destination address";
        case SAHARA_NAK_INVALID_IMG_HDR_DATA_SIZE:      return "Invalid data size receieved in image header";
        case SAHARA_NAK_INVALID_ELF_HDR:                return "Invalid ELF header received";
        case SAHARA_NAK_UNKNOWN_HOST_ERROR:             return "Unknown host error received in HELLO_RESP";
        case SAHARA_NAK_TIMEOUT_RX:                     return "Timeout while receiving data";
        case SAHARA_NAK_TIMEOUT_TX:                     return "Timeout while transmitting data";
        case SAHARA_NAK_INVALID_HOST_MODE:              return "Invalid mode received from host";
        case SAHARA_NAK_INVALID_MEMORY_READ:            return "Invalid memory read access";
        case SAHARA_NAK_INVALID_DATA_SIZE_REQUEST:      return "Host cannot handle read data size requested";
        case SAHARA_NAK_MEMORY_DEBUG_NOT_SUPPORTED:     return "Memory debug not supported";
        case SAHARA_NAK_INVALID_MODE_SWITCH:            return "Invalid mode switch";
        case SAHARA_NAK_CMD_EXEC_FAILURE:               return "Failed to execute command";
        case SAHARA_NAK_EXEC_CMD_INVALID_PARAM:         return "Invalid parameter passed to command execution";
        case SAHARA_NAK_EXEC_CMD_UNSUPPORTED:           return "Unsupported client command received";
        case SAHARA_NAK_EXEC_DATA_INVALID_CLIENT_CMD:   return "Invalid client command received for data response";
        case SAHARA_NAK_HASH_TABLE_AUTH_FAILURE:        return "Failed to authenticate hash table";
        case SAHARA_NAK_HASH_VERIFICATION_FAILURE:      return "Failed to verify hash for a given segment of ELF image";
        case SAHARA_NAK_HASH_TABLE_NOT_FOUND:           return "Failed to find hash table in ELF image";
        default:                                        return "[unknown]";
    }
}


static const char *sahara_get_packet_id_string(uint32_t command)
{
    switch (command) {
        case SAHARA_NO_CMD_ID:                  return "NO_CMD";
        case SAHARA_HELLO_ID:                   return "HELLO";
        case SAHARA_HELLO_RESP_ID:              return "HELLO_RESP";
        case SAHARA_READ_DATA_ID:               return "READ_DATA";
        case SAHARA_END_IMAGE_TX_ID:            return "END_IMAGE_TX";
        case SAHARA_DONE_ID:                    return "DONE";
        case SAHARA_DONE_RESP_ID:               return "DONE_RESP";
        case SAHARA_RESET_ID:                   return "RESET";
        case SAHARA_RESET_RESP_ID:              return "RESET_RESP";
        case SAHARA_MEMORY_DEBUG_ID:            return "MEMORY_DEBUG";
        case SAHARA_MEMORY_READ_ID:             return "MEMORY_READ";
        case SAHARA_CMD_READY_ID:               return "CMD_READY";
        case SAHARA_CMD_SWITCH_MODE_ID:         return "CMD_SWITCH_MODE";
        case SAHARA_CMD_EXEC_ID:                return "CMD_EXEC";
        case SAHARA_CMD_EXEC_RESP_ID:           return "CMD_EXEC_RESP";
        case SAHARA_CMD_EXEC_DATA_ID:           return "CMD_EXEC_DATA";
        case SAHARA_64_BITS_MEMORY_DEBUG_ID:    return "64_BITS_MEMORY_DEBUG";
        case SAHARA_64_BITS_MEMORY_READ_ID:     return "64_BITS_MEMORY_READ";
        case SAHARA_64_BITS_READ_DATA_ID:       return "64_BITS_READ_DATA";
        default:                                return "[unknown]";
    }
}


static const char *sahara_get_mode_string(uint32_t mode)
{
    switch (mode) {
        case SAHARA_MODE_IMAGE_TX_PENDING:      return "IMAGE_TX_PENDING";
        case SAHARA_MODE_IMAGE_TX_COMPLETE:     return "IMAGE_TX_COMPLETE";
        case SAHARA_MODE_MEMORY_DEBUG:          return "MEMORY_DEBUG";
        default:                                return "[unknown]";
    }
}


static const char *sahara_get_state_string(int state)
{
    switch (state) {
        case SAHARA_STATE_ENTRY:                return "ENTRY";
        case SAHARA_STATE_EXIT:                 return "EXIT";

        case SAHARA_STATE_WAIT_HELLO:           return "WAIT_HELLO";
        case SAHARA_STATE_WAIT_COMMAND:         return "WAIT_COMMAND";
        case SAHARA_STATE_WAIT_DONE_RESP:       return "WAIT_DONE_RESP";
        case SAHARA_STATE_WAIT_RESET_RESP:      return "WAIT_RESET_RESP";
        case SAHARA_STATE_WAIT_MEMORY_TABLE:    return "WAIT_MEMORY_TABLE";
        case SAHARA_STATE_WAIT_MEMORY_REGION:   return "WAIT_MEMORY_REGION";
        case SAHARA_STATE_WAIT_CMD_EXEC_RESP:   return "WAIT_CMD_EXEC_RESP";

        case SAHARA_STATE_RECV_HELLO:           return "RECV_HELLO";
        case SAHARA_STATE_RECV_COMMAND:         return "RECV_COMMAND";
        case SAHARA_STATE_RECV_DONE_RESP:       return "RECV_DONE_RESP";
        case SAHARA_STATE_RECV_RESET_RESP:      return "RECV_RESET_RESP";
        case SAHARA_STATE_RECV_MEMORY_TABLE:    return "RECV_MEMORY_TABLE";
        case SAHARA_STATE_RECV_MEMORY_REGION:   return "RECV_MEMORY_REGION";
        case SAHARA_STATE_RECV_CMD_EXEC_RESP:   return "RECV_CMD_EXEC_RESP";

        case SAHARA_STATE_IMAGE_TX_IN_PROGRESS: return "IMAGE_TX_IN_PROGRESS";
        case SAHARA_STATE_IMAGE_TX_SUCCESS:     return "IMAGE_TX_SUCCESS";
        case SAHARA_STATE_IMAGE_TX_FAILURE:     return "IMAGE_TX_FAILURE";

        default:                                return "[unknown]";
    }
}


static int sahara_read_data(sahara_connection_t *conn, uint32_t client_cmd, uint8_t *buf, int buf_len)
{
    sahara_packet_cmd_exec exe_req = {
        .header = {.command = SAHARA_CMD_EXEC_ID, .length = sizeof(sahara_packet_cmd_exec)},
        .client_command = client_cmd,
    };

    int len = write_bulk(conn->usb_dev, &exe_req, sizeof(exe_req));
    if (len != sizeof(exe_req)) {
        qcomdl_log_error("could not send read data command\n");
        return -1;
    }

    conn->host_state = SAHARA_STATE_WAIT_CMD_EXEC_RESP;
    if ((sahara_process_packets(conn) != 0) || (conn->host_state != SAHARA_STATE_RECV_CMD_EXEC_RESP)) {
        return -1;
    }

    sahara_packet_cmd_exec_data exe_data_req = {
        .header = {.command = SAHARA_CMD_EXEC_DATA_ID, .length = sizeof(sahara_packet_cmd_exec_data)},
        .client_command = client_cmd,
    };

    len = write_bulk(conn->usb_dev, &exe_data_req, sizeof(exe_data_req));
    if (len != sizeof(exe_data_req)) {
        return -1;
    }

    return read_bulk(conn->usb_dev, buf, buf_len);
}


static int sahara_hello_response_to_mode(sahara_connection_t *conn, uint32_t mode)
{
    if (!conn) {
        qcomdl_log_error("conn argument must not be null\n");
        return -1;
    }

    sahara_packet_hello_resp hello_rsp = {
        .header = {.command = SAHARA_HELLO_RESP_ID, .length = sizeof(sahara_packet_hello)},
        .version = 2,
        .version_supported = 1,
        .status = SAHARA_STATUS_SUCCESS,
        .mode = mode,
    };

    int len = write_bulk(conn->usb_dev, &hello_rsp, (int)sizeof(hello_rsp));
    if (len != (int)sizeof(hello_rsp)) {
        qcomdl_log_error("Cannot write hello response to device: len=%i\n", len);
        return -1;
    }

    return 0;
}


static int sahara_mode_switch(sahara_connection_t *conn, uint32_t mode)
{
    qcomdl_log_debug("Sending Sahara mode switch command to mode: %s(%u)\n", sahara_get_mode_string(mode), mode);

    sahara_packet_cmd_switch_mode cmd_switch_mode = {
        .header = {.command = SAHARA_CMD_SWITCH_MODE_ID, .length = sizeof(sahara_packet_cmd_switch_mode)},
        .mode = mode,
    };

    int len = write_bulk(conn->usb_dev, &cmd_switch_mode, sizeof(cmd_switch_mode));
    if (len != sizeof(cmd_switch_mode)) {
        qcomdl_log_error("could not send switch mode command\n");
        return -1;
    }

    conn->host_state = SAHARA_STATE_WAIT_HELLO;
    if (((sahara_process_packets(conn) != 0)) ||
        (conn->host_state != SAHARA_STATE_RECV_HELLO)) {
        qcomdl_log_error("Unable to get hello response from mode switch - left in state %s(%i)\n",
                    sahara_get_state_string(conn->host_state),
                    conn->host_state);
        return -1;
    }

    if (conn->target_current_mode != mode) {
        qcomdl_log_error("Expected hello request for mode=%u but got %u instead\n", mode, conn->target_current_mode);
        return -1;
    }

    return 0;
}


static int send_file_data(sahara_connection_t *conn, uint64_t offset, uint64_t length)
{
    if (!conn->program_file) {
        qcomdl_log_error("Cannot send file data to target - program file not ready\n");
        return -1;
    }

    if (offset > LONG_MAX) {
        qcomdl_log_error("read_data_offset too large: %"PRIu64" > %li\n", offset, LONG_MAX);
        return -1;
    }

    if (length == 0) {
        qcomdl_log_error("target sent read_data_len of zero?\n");
        return -1;
    }

    if (qcomdl_fseek(conn->program_file, (long)offset, SEEK_SET) != 0) {
        qcomdl_log_error("fseek to offset %"PRIu64" failed - %s\n", offset, strerror(errno));
        return -1;
    }

    uint8_t *tmpbuf = calloc(1, (size_t)length);
    if (!tmpbuf) {
        qcomdl_log_error("calloc: %s\n", strerror(errno));
        return -1;
    }

    size_t rl = qcomdl_fread(tmpbuf, 1, (size_t)length, conn->program_file);
    if (rl != length) {
        qcomdl_log_error("Failed to read %"PRIu64" chunk from file (only got %zu)\n", length, rl);
        free(tmpbuf);
        return -1;
    }

    int sent_len = write_bulk(conn->usb_dev, tmpbuf, (int)length);
    if (sent_len != (int)length) {
        qcomdl_log_error("Failed to write data to device: len=%i\n", sent_len);
        free(tmpbuf);
        return -1;
    }

    free(tmpbuf);
    return 0;
}


static int sahara_read_memory_table(sahara_connection_t *conn, uint64_t addr, uint64_t length)
{
    uint8_t *buf = NULL;
    size_t buf_size = 0;
    qcomdl_log_debug("Reading target's memory table\n");
    if (sahara_memory_read(conn, addr, length, &buf, &buf_size) != 0) {
        qcomdl_log_error("There was an error reading the target's memory table\n");
        return -1;
    }

    if (conn->memory_table) {
        free(conn->memory_table);
    }

    conn->memory_table = (void*)buf;
    conn->memory_table_length = length;

    return 0;
}


static int sahara_memory_dump_table_region(sahara_connection_t *conn, const char *outdir, const char *desc, const char *filename, uint64_t addr, uint64_t length)
{
    char outpath[PATH_MAX];

    // being paranoid...
    // sanitize the filename to remove directory slash characters
    char filename_safe[DLOAD_DEBUG_STRLEN_BYTES];
    memcpy(filename_safe, filename, sizeof(filename_safe));

    // force a null terminator
    filename_safe[DLOAD_DEBUG_STRLEN_BYTES-1] = 0;
    char *p = strpbrk(filename_safe, "/\\");
    while (p) {
        *p = '_';
        p = strpbrk(p, "/\\");
    }

    qcomdl_log_info("Dumping memory table entry labeled \"%s\"\n", desc);
    snprintf(outpath, sizeof(outpath), "%s%c%s", outdir, DIRSEP, filename_safe);
    return sahara_memory_read_to_file(conn, addr, length, outpath);
}


static int sahara_memory_dump_table_32(sahara_connection_t *conn, const char *outdir)
{
    if ((!conn->memory_table) || (!conn->memory_table_length)) {
        qcomdl_log_error("No 32-bit memory regions are currently captured from target\n");
        return -1;
    }

    size_t count = (size_t)conn->memory_table_length / sizeof(dload_debug_type);
    dload_debug_type *region = conn->memory_table;
    for (; count > 0; count--, region++) {
        if (sahara_memory_dump_table_region(conn, outdir, region->desc, region->filename, region->mem_base, region->length) != 0) {
            return -1;
        }
    }

    return 0;
}


static int sahara_memory_dump_table_64(sahara_connection_t *conn, const char *outdir)
{
    if ((!conn->memory_table) || (!conn->memory_table_length)) {
        qcomdl_log_error("No 32-bit memory regions are currently captured from target\n");
        return -1;
    }

    size_t count = (size_t)conn->memory_table_length / sizeof(dload_64_bit_debug_type);
    dload_64_bit_debug_type *region = conn->memory_table;
    for (; count > 0; count--, region++) {
        if (sahara_memory_dump_table_region(conn, outdir, region->desc, region->filename, region->mem_base, region->length) != 0) {
            return -1;
        }
    }

    return 0;
}


#pragma mark Packet Handlers

/*
   These macros are for consistent log messages and checks across all packet handlers. One reason
   these are macros is to enable logging of the function that emits the error in debug builds.
   They will cause errors if the packet handler return values and arguments don't follow the form:

       sahara_handler_result <func>(sahara_connection_t *conn, uint8_t *packet, int packet_size)
*/

#define log_unexpected_packet_state(packet_id) \
    qcomdl_log_error("Received unexpected %s packet while in %s state\n", \
                sahara_get_packet_id_string(packet_id), \
                sahara_get_state_string(conn->host_state))


#define do_packet_size_check(expected_id, expected_len) \
    sahara_packet_header *__pkt_hdr = (void*)packet; \
    if ((uint32_t)packet_size != (expected_len)) { \
        qcomdl_log_error("%s packet data length size mismatch: (expected)%zu != (actual)%i\n",\
                    sahara_get_packet_id_string(expected_id), \
                    (expected_len), \
                    packet_size); \
        return SAHARA_HANDLER_RESULT_ERROR; \
    } \
    if (__pkt_hdr->length != (expected_len)) { \
        qcomdl_log_error("%s packet data header length size mismatch: (expected)%zu != (actual)%u\n", \
                    sahara_get_packet_id_string(expected_id), \
                    (expected_len), \
                    __pkt_hdr->length); \
        return SAHARA_HANDLER_RESULT_ERROR; \
    }


static sahara_handler_result handle_hello_packet(sahara_connection_t *conn, uint8_t *packet, int packet_size)
{
    do_packet_size_check(SAHARA_HELLO_ID, sizeof(sahara_packet_hello));

    sahara_packet_hello *hello_pkt = (void*)packet;
    qcomdl_log_debug("Target sent HELLO with mode %s(%u), version %u, version_supported %u, target_cmd_pkt_length %u\n",
                sahara_get_mode_string(hello_pkt->mode),
                hello_pkt->mode,
                hello_pkt->version,
                hello_pkt->version_supported,
                hello_pkt->target_cmd_pkt_length);

    if ((conn->host_state != SAHARA_STATE_WAIT_HELLO) &&
        (conn->host_state != SAHARA_STATE_WAIT_COMMAND)) {
        log_unexpected_packet_state(SAHARA_HELLO_ID);
        return SAHARA_HANDLER_RESULT_ERROR;
    }

    // TODO: Version compatibility check?

    conn->host_state = SAHARA_STATE_RECV_HELLO;
    conn->target_cmd_pkt_length = hello_pkt->target_cmd_pkt_length;
    conn->target_current_mode = hello_pkt->mode;

    return SAHARA_HANDLER_RESULT_BREAK;
}


static sahara_handler_result handle_memory_debug_packet(sahara_connection_t *conn, uint8_t *packet, int packet_size)
{
    do_packet_size_check(SAHARA_MEMORY_DEBUG_ID, sizeof(sahara_packet_memory_debug));

    sahara_packet_memory_debug *mem_debug_pkt = (void*)packet;
    qcomdl_log_debug("Target sent MEMORY_DEBUG with memory table address=0x%x length=0x%x\n",
                mem_debug_pkt->memory_table_addr,
                mem_debug_pkt->memory_table_length);

    if ((conn->host_state != SAHARA_STATE_WAIT_MEMORY_TABLE) &&
        (conn->host_state != SAHARA_STATE_WAIT_COMMAND)) {
        log_unexpected_packet_state(SAHARA_MEMORY_DEBUG_ID);
        return SAHARA_HANDLER_RESULT_ERROR;
    }

    if ((!mem_debug_pkt->memory_table_length) || ((mem_debug_pkt->memory_table_length % sizeof(dload_debug_type)) != 0)) {
        qcomdl_log_error("Zero/unaligned size for memory table: 0x%x\n", mem_debug_pkt->memory_table_length);
        return SAHARA_HANDLER_RESULT_ERROR;
    }

    conn->host_state = SAHARA_STATE_RECV_MEMORY_TABLE;
    conn->target_is_64bit = false;

    if (sahara_read_memory_table(conn, mem_debug_pkt->memory_table_addr, mem_debug_pkt->memory_table_length) != 0) {
        return SAHARA_HANDLER_RESULT_ERROR;
    } else {
        return SAHARA_HANDLER_RESULT_BREAK;
    }
}


static sahara_handler_result handle_64_bit_memory_debug_packet(sahara_connection_t *conn, uint8_t *packet, int packet_size)
{
    do_packet_size_check(SAHARA_64_BITS_MEMORY_DEBUG_ID, sizeof(sahara_packet_64_bit_memory_debug));

    sahara_packet_64_bit_memory_debug *mem_debug_pkt_64 = (void*)packet;
    qcomdl_log_debug("Target sent 64_BITS_MEMORY_DEBUG with memory table address=0x%"PRIx64" length=0x%"PRIx64"\n",
                mem_debug_pkt_64->memory_table_addr,
                mem_debug_pkt_64->memory_table_length);

    if ((conn->host_state != SAHARA_STATE_WAIT_MEMORY_TABLE) &&
        (conn->host_state != SAHARA_STATE_WAIT_COMMAND)) {
        log_unexpected_packet_state(SAHARA_64_BITS_MEMORY_DEBUG_ID);
        return SAHARA_HANDLER_RESULT_ERROR;
    }

    conn->host_state = SAHARA_STATE_RECV_MEMORY_TABLE;
    conn->target_is_64bit = true;

    if (sahara_read_memory_table(conn, mem_debug_pkt_64->memory_table_addr, mem_debug_pkt_64->memory_table_length) != 0) {
        return SAHARA_HANDLER_RESULT_ERROR;
    } else {
        return SAHARA_HANDLER_RESULT_BREAK;
    }
}


static sahara_handler_result handle_read_data_packet(sahara_connection_t *conn, uint8_t *packet, int packet_size)
{
    do_packet_size_check(SAHARA_READ_DATA_ID, sizeof(sahara_packet_read_data));

    if (conn->host_state != SAHARA_STATE_IMAGE_TX_IN_PROGRESS) {
        log_unexpected_packet_state(SAHARA_READ_DATA_ID);
        return SAHARA_HANDLER_RESULT_ERROR;
    }

    sahara_packet_read_data *read_pkt = (void*)packet;
    if (send_file_data(conn, read_pkt->data_offset, read_pkt->data_length) == 0) {
        return SAHARA_HANDLER_RESULT_CONTINUE;
    } else {
        return SAHARA_HANDLER_RESULT_ERROR;
    }
}


static sahara_handler_result handle_read_data64_packet(sahara_connection_t *conn, uint8_t *packet, int packet_size)
{
    do_packet_size_check(SAHARA_64_BITS_READ_DATA_ID, sizeof(sahara_packet_64_bit_read_data));

    if (conn->host_state != SAHARA_STATE_IMAGE_TX_IN_PROGRESS) {
        log_unexpected_packet_state(SAHARA_64_BITS_READ_DATA_ID);
        return SAHARA_HANDLER_RESULT_ERROR;
    }

    sahara_packet_64_bit_read_data *read_pkt = (void*)packet;
    if (send_file_data(conn, read_pkt->data_offset, read_pkt->data_length) == 0) {
        return SAHARA_HANDLER_RESULT_CONTINUE;
    } else {
        return SAHARA_HANDLER_RESULT_ERROR;
    }
}


static sahara_handler_result handle_end_image_tx_packet(sahara_connection_t *conn, uint8_t *packet, int packet_size)
{
    do_packet_size_check(SAHARA_END_IMAGE_TX_ID, sizeof(sahara_packet_end_image_tx));

    sahara_packet_end_image_tx *end_tx_pkt = (void*)packet;
    qcomdl_log_debug("Target sent END_IMAGE_TX with status = (%u) %s\n", end_tx_pkt->status, sahara_strerror(end_tx_pkt->status));

    if ((conn->host_state != SAHARA_STATE_IMAGE_TX_IN_PROGRESS) &&
        (conn->host_state != SAHARA_STATE_WAIT_COMMAND)) {
        log_unexpected_packet_state(SAHARA_END_IMAGE_TX_ID);
        return SAHARA_HANDLER_RESULT_ERROR;
    }

    if (end_tx_pkt->status == SAHARA_STATUS_SUCCESS) {
        conn->host_state = SAHARA_STATE_IMAGE_TX_SUCCESS;
        return SAHARA_HANDLER_RESULT_BREAK;
    } else {
        qcomdl_log_error("END_IMAGE_TX returned an error from target: (%u) %s\n",
                    end_tx_pkt->status,
                    sahara_strerror(end_tx_pkt->status));
        conn->host_state = SAHARA_STATE_IMAGE_TX_FAILURE;
        return SAHARA_HANDLER_RESULT_ERROR;
    }
}


static sahara_handler_result handle_done_resp_packet(sahara_connection_t *conn, uint8_t *packet, int packet_size)
{
    do_packet_size_check(SAHARA_DONE_RESP_ID, sizeof(sahara_packet_done_resp));

    if (conn->host_state != SAHARA_STATE_WAIT_DONE_RESP) {
        log_unexpected_packet_state(SAHARA_DONE_RESP_ID);
        return SAHARA_HANDLER_RESULT_ERROR;
    }

    conn->host_state = SAHARA_STATE_RECV_DONE_RESP;

    sahara_packet_done_resp *done_pkt = (void*)packet;
    qcomdl_log_debug("Target sent DONE_RESP with image_tx_status=%u\n", done_pkt->image_tx_status);

    if (done_pkt->image_tx_status == SAHARA_STATUS_SUCCESS) {
        return SAHARA_HANDLER_RESULT_BREAK;
    } else if (done_pkt->image_tx_status == 1) {
        // According to the doc 80-N1008-1 Sahara Protocol Spec,
        // The target can respond with 'pending', indicating it expects more images
        // We don't currently support it.
        ///
        // APT-2991: on SD660 the value appears to be inverted and so we should just skip this?
        return SAHARA_HANDLER_RESULT_BREAK;
    } else {
        qcomdl_log_error("Unexpected done response status: %u\n", done_pkt->image_tx_status);
        return SAHARA_HANDLER_RESULT_ERROR;
    }
}


static sahara_handler_result handle_reset_resp_packet(sahara_connection_t *conn, uint8_t *packet, int packet_size)
{
    do_packet_size_check(SAHARA_RESET_RESP_ID, sizeof(sahara_packet_reset_resp));

    if (conn->host_state != SAHARA_STATE_WAIT_RESET_RESP) {
        log_unexpected_packet_state(SAHARA_RESET_RESP_ID);
        return SAHARA_HANDLER_RESULT_ERROR;
    }

    conn->host_state = SAHARA_STATE_RECV_RESET_RESP;
    return SAHARA_HANDLER_RESULT_BREAK;
}


static sahara_handler_result handle_cmd_ready_packet(sahara_connection_t *conn, uint8_t *packet, int packet_size)
{
    do_packet_size_check(SAHARA_CMD_READY_ID, sizeof(sahara_packet_cmd_ready));

    qcomdl_log_debug("Target sent CMD_READY\n");

    if ((conn->host_state != SAHARA_STATE_WAIT_COMMAND) && (conn->host_state != SAHARA_STATE_WAIT_RESET_RESP)) {
        log_unexpected_packet_state(SAHARA_CMD_READY_ID);
        return SAHARA_HANDLER_RESULT_ERROR;
    }

    conn->host_state = SAHARA_STATE_RECV_COMMAND;
    return SAHARA_HANDLER_RESULT_BREAK;
}


static sahara_handler_result handle_cmd_exec_resp_packet(sahara_connection_t *conn, uint8_t *packet, int packet_size)
{
    do_packet_size_check(SAHARA_CMD_EXEC_RESP_ID, sizeof(sahara_packet_cmd_exec_resp));

    sahara_packet_cmd_exec_resp *rsp = (void*)packet;
    qcomdl_log_debug("Target sent CMD_EXEC_RSP with resp_length = %u\n", rsp->resp_length);

    if (conn->host_state != SAHARA_STATE_WAIT_CMD_EXEC_RESP) {
        log_unexpected_packet_state(SAHARA_CMD_EXEC_RESP_ID);
        return SAHARA_HANDLER_RESULT_ERROR;
    }

    conn->host_state = SAHARA_STATE_RECV_CMD_EXEC_RESP;
    conn->target_cmd_exec_resp_length = rsp->resp_length;

    return SAHARA_HANDLER_RESULT_BREAK;
}


# pragma mark Host State Machine

// Processes incoming sahara packets from the target and calls the corresponding packet handler.
// Effectively implements the Sahara host state machine outlined in the document:
//     80-N1008-1 J Sahara Protocol Specification
static int sahara_process_packets(sahara_connection_t *conn)
{
    while (conn->host_state != SAHARA_STATE_EXIT) {
        sahara_handler_result res = SAHARA_HANDLER_RESULT_ERROR;

        int length = read_bulk(conn->usb_dev, conn->packet_buffer, sizeof(conn->packet_buffer));
        if (length < 0) {
            // read error, already logged
            return -1;
        }

        if (!length) {
            qcomdl_log_error("No data recieved from target\n");
            return -1;
        }

        if (length < (int)sizeof(sahara_packet_header)) {
            qcomdl_log_error("Received a packet too small to be Sahara: %i bytes\n", length);
            return -1;
        }

        void *p = conn->packet_buffer;
        uint32_t packet_id = 0;
        memcpy(&packet_id, p, sizeof(packet_id));
        // qcomdl_log_debug("Received %s(%u) from target\n", sahara_get_packet_id_string(packet_id), packet_id);

        switch (packet_id) {
            case SAHARA_HELLO_ID: {
                res = handle_hello_packet(conn, conn->packet_buffer, length);
                break;
            }

            case SAHARA_MEMORY_DEBUG_ID: {
                res = handle_memory_debug_packet(conn, conn->packet_buffer, length);
                break;
            }

            case SAHARA_64_BITS_MEMORY_DEBUG_ID: {
                res = handle_64_bit_memory_debug_packet(conn, conn->packet_buffer, length);
                break;
            }

            case SAHARA_READ_DATA_ID: {
                res = handle_read_data_packet(conn, conn->packet_buffer, length);
                break;
            }

            case SAHARA_64_BITS_READ_DATA_ID: {
                res = handle_read_data64_packet(conn, conn->packet_buffer, length);
                break;
            }

            case SAHARA_END_IMAGE_TX_ID: {
                res = handle_end_image_tx_packet(conn, conn->packet_buffer, length);
                break;
            }

            case SAHARA_DONE_RESP_ID: {
                res = handle_done_resp_packet(conn, conn->packet_buffer, length);
                break;
            }

            case SAHARA_RESET_RESP_ID: {
                res = handle_reset_resp_packet(conn, conn->packet_buffer, length);
                break;
            }

            case SAHARA_CMD_READY_ID: {
                res = handle_cmd_ready_packet(conn, conn->packet_buffer, length);
                break;
            }

            case SAHARA_CMD_EXEC_RESP_ID: {
                res = handle_cmd_exec_resp_packet(conn, conn->packet_buffer, length);
                break;
            }

            default: {
                qcomdl_log_error("Received unrecognized packet id from target: %u\n", packet_id);
                res = SAHARA_HANDLER_RESULT_ERROR;
                break;
            }
        }

        if (res == SAHARA_HANDLER_RESULT_BREAK) {
            break;
        } else if (res == SAHARA_HANDLER_RESULT_CONTINUE) {
            continue;
        } else {
            // on errors, only send a reset if we aren't already in reset state
            if ((conn->host_state != SAHARA_STATE_WAIT_RESET_RESP) &&
                (conn->host_state != SAHARA_STATE_RECV_RESET_RESP)) {
                qcomdl_log_error("Sending reset command to target in response to error\n");
                conn->host_state = SAHARA_STATE_WAIT_RESET_RESP;
                sahara_device_reset(conn);
            }
            conn->host_state = SAHARA_STATE_EXIT;
            return -1;
        }
    }
    return 0;
}

#pragma mark Public Functions

sahara_connection_t *sahara_connect(edl_connection_t *edl_conn)
{
    if (!edl_conn) {
        qcomdl_log_error("Called with null argument for edl_conn\n");
        return NULL;
    }

    sahara_connection_t *sahara_conn = calloc(1, sizeof(sahara_connection_t));
    if (!sahara_conn) {
        qcomdl_log_error("Unable to allocate a Sahara connection - %s\n", strerror(errno));
        return NULL;
    }

    sahara_conn->usb_dev = edl_conn->usb_dev;
    sahara_conn->host_state = SAHARA_STATE_WAIT_HELLO;

    if (sahara_process_packets(sahara_conn) != 0) {
        qcomdl_log_error("Unable to read hello request from host, attempting a mode switch to prompt the target\n");

        if (sahara_mode_switch(sahara_conn, SAHARA_MODE_IMAGE_TX_PENDING) != 0) {
            sahara_connection_free(sahara_conn);
            return NULL;
        }
    }

    return sahara_conn;
}


void sahara_connection_free(sahara_connection_t *sahara_conn)
{
    if (sahara_conn && sahara_conn->memory_table) {
        free(sahara_conn->memory_table);
        sahara_conn->memory_table = NULL;
    }

    free(sahara_conn);
}


int sahara_device_info(sahara_connection_t *conn, pbl_info_t *pbl_info)
{
    if (!conn || !pbl_info) {
        qcomdl_log_error("Arguments conn and pbl_info must not be NULL\n");
        return -1;
    }

    memset(pbl_info, 0, sizeof(pbl_info_t));

    // put the device in command mode
    int rc = sahara_hello_response_to_mode(conn, SAHARA_MODE_COMMAND);
    if (rc != 0) {
        return rc;
    }

    conn->host_state = SAHARA_STATE_WAIT_COMMAND;
    if ((sahara_process_packets(conn) != 0) || (conn->host_state != SAHARA_STATE_RECV_COMMAND)) {
        return -1;
    }

    uint32_t tmp_word_buf[64];
    int read_len = sahara_read_data(conn, SAHARA_EXEC_CMD_SERIAL_NUM_READ, (uint8_t*)&tmp_word_buf, sizeof(tmp_word_buf));
    if (read_len >= (int)sizeof(uint32_t) && read_len < (int)sizeof(tmp_word_buf)) {
        pbl_info->serial = tmp_word_buf[0];
    } else {
        qcomdl_log_warning("Unable to read serial number: read_len=%i\n", read_len);
    }

    read_len = sahara_read_data(conn, SAHARA_EXEC_CMD_MSM_HW_ID_READ, (uint8_t*)&tmp_word_buf, sizeof(tmp_word_buf));
    if (read_len >= (int)(sizeof(uint32_t)*2) && read_len < (int)sizeof(tmp_word_buf)) {
        pbl_info->msm_id = tmp_word_buf[1];
    } else {
        qcomdl_log_warning("Unable to read MSM hardware ID: read_len=%i\n", read_len);
    }

    read_len = sahara_read_data(conn, SAHARA_EXEC_CMD_GET_SOFTWARE_VERSION_SBL, (uint8_t*)&tmp_word_buf, sizeof(tmp_word_buf));
    if (read_len >= (int)sizeof(uint32_t) && read_len < (int)sizeof(tmp_word_buf)) {
        pbl_info->pbl_sw = tmp_word_buf[0];
    } else {
        qcomdl_log_warning("Unable to read software version SBL: read_len=%i\n", read_len);
    }

    read_len = sahara_read_data(conn, SAHARA_EXEC_CMD_OEM_PK_HASH_READ, (uint8_t*)&tmp_word_buf, sizeof(tmp_word_buf));
    if ((read_len >= (int)sizeof(pbl_info->pk_hash)) && (read_len < (int)sizeof(tmp_word_buf))) {
        memcpy(pbl_info->pk_hash, tmp_word_buf, sizeof(pbl_info->pk_hash));
    } else {
        qcomdl_log_warning("Unable to read OEM PK hash: read_len=%i\n", read_len);
    }

    sahara_mode_switch(conn, SAHARA_MODE_IMAGE_TX_PENDING);

    return 0;
}


int sahara_read_debug_data(sahara_connection_t *conn, uint8_t **data_buf, int *data_buf_size)
{
    // put the device in command mode
    int rc = sahara_hello_response_to_mode(conn, SAHARA_MODE_COMMAND);
    if (rc != 0) {
        return rc;
    }

    conn->host_state = SAHARA_STATE_WAIT_COMMAND;
    if ((sahara_process_packets(conn) != 0) || (conn->host_state != SAHARA_STATE_RECV_COMMAND)) {
        return -1;
    }

    uint8_t tmp_buf[SAHARA_MAX_CMD_PACKET_SIZE];
    int read_len = sahara_read_data(conn, SAHARA_EXEC_CMD_READ_DEBUG_DATA, tmp_buf, sizeof(tmp_buf));

    sahara_mode_switch(conn, SAHARA_MODE_IMAGE_TX_PENDING);

    if (read_len > 0) {
        uint8_t *out = calloc(1, (size_t)read_len);
        if (!out) {
            qcomdl_log_error("Unable to allocate %i bytes - %s\n", read_len, strerror(errno));
            return -1;
        }
        memcpy(out, tmp_buf, (size_t)read_len);
        *data_buf = out;
        *data_buf_size = read_len;
        return 0;
    } else {
        qcomdl_log_error("Unable to read debug data: read_len=%i\n", read_len);
        return -1;
    }
}


int sahara_upload(sahara_connection_t *conn, qcomdl_resource_package_t *package, const char *firehose_path)
{
    if (!conn) {
        qcomdl_log_error("conn argument must not be null\n");
        return -1;
    }

    if ((conn->target_current_mode != SAHARA_MODE_IMAGE_TX_PENDING) &&
        (conn->target_current_mode != SAHARA_MODE_IMAGE_TX_COMPLETE)) {
        qcomdl_log_warning("Target came up in a mode that does not indicate it is ready for an image transfer: mode = %s(%u)\n",
                   sahara_get_mode_string(conn->target_current_mode),
                   conn->target_current_mode);
        if (sahara_mode_switch(conn, SAHARA_MODE_IMAGE_TX_PENDING) != 0) {
            return -1;
        }
    }

    qcomdl_log_info("Uploading firehose image via Sahara: %s\n", firehose_path);

    if (sahara_hello_response_to_mode(conn, SAHARA_MODE_IMAGE_TX_PENDING) != 0) {
        return -1;
    }

    conn->program_file = qcomdl_fopen(package, package->img_dir, firehose_path, "rb");
    if (!conn->program_file) {
        qcomdl_log_error("cannot open file: %s - %s\n", firehose_path, strerror(errno));
        return -1;
    }

    conn->host_state = SAHARA_STATE_IMAGE_TX_IN_PROGRESS;
    int ret = sahara_process_packets(conn);

    qcomdl_fclose(conn->program_file);

    if ((ret == 0) && (conn->host_state == SAHARA_STATE_IMAGE_TX_SUCCESS)) {
        qcomdl_log_info("Loaded flash program via Sahara successfully\n");
        return 0;
    } else {
        qcomdl_log_error("Failed to load flash program via Sahara\n");
        return -1;
    }

}


int sahara_enter_memory_debug(sahara_connection_t *conn)
{
    if (!conn) {
        qcomdl_log_error("conn argument must not be null\n");
        return -1;
    }

    if (conn->target_current_mode != SAHARA_MODE_MEMORY_DEBUG) {
        qcomdl_log_warning("Target came up in a mode that does not indicate it is ready for memory debugging: mode = %s (%u)\n",
                   sahara_get_mode_string(conn->target_current_mode),
                   conn->target_current_mode);
        if (sahara_mode_switch(conn, SAHARA_MODE_MEMORY_DEBUG) != 0) {
            return -1;
        }
        return -1;
    }

    if (sahara_hello_response_to_mode(conn, SAHARA_MODE_MEMORY_DEBUG) != 0) {
        return -1;
    }

    conn->host_state = SAHARA_STATE_WAIT_MEMORY_TABLE;
    if (sahara_process_packets(conn) != 0) {
        return -1;
    }

    return 0;
}


int sahara_memory_dump_table(sahara_connection_t *conn, const char *outdir)
{
    if (!conn) {
        qcomdl_log_error("conn argument must not be null\n");
        return -1;
    }

    if (conn->target_current_mode != SAHARA_MODE_MEMORY_DEBUG) {
        qcomdl_log_error("Target is not currently in memory debug mode: current mode = %s(%u)\n",
                    sahara_get_mode_string(conn->target_current_mode),
                    conn->target_current_mode);
        return -1;
    }

    if (!outdir) {
        outdir = ".";
    }

    if (conn->target_is_64bit) {
        return sahara_memory_dump_table_64(conn, outdir);
    } else {
        return sahara_memory_dump_table_32(conn, outdir);
    }
}


int sahara_memory_read(sahara_connection_t *conn, uint64_t addr, uint64_t len, uint8_t **buf_out, size_t *buf_out_size)
{
    if (!conn) {
        qcomdl_log_error("conn argument must not be null\n");
        return -1;
    }

    if (!buf_out || !buf_out_size) {
        qcomdl_log_error("output arguments must not be null\n");
        return -1;
    }

    if (conn->target_current_mode != SAHARA_MODE_MEMORY_DEBUG) {
        qcomdl_log_error("Target is not currently in memory debug mode: current mode = %s(%u)\n",
                    sahara_get_mode_string(conn->target_current_mode),
                    conn->target_current_mode);
        return -1;
    }

    if (len > SAHARA_MAX_MEMORY_READ_LENGTH) {
        qcomdl_log_error("Specified memory read length is too large: 0x%"PRIx64" (hint, read 0x%x bytes or smaller at a time)\n", len, SAHARA_MAX_MEMORY_READ_LENGTH);
        return -1;
    }


    /*  Per Qualcomm's Sahara documentation
     If any error occurs on the target, an End of Image Transfer packet is sent with the corresponding
     error code. The host must distinguish the data sent from the target to recognize whether it is
     actual memory data or an End of Image Transfer packet. One way is to always request a memory
     length that does not equal the size of the End of Image Transfer packet.
     */
    bool is_end_image_tx_size = false;
    if (len == sizeof(sahara_packet_end_image_tx)) {
        qcomdl_log_info("Temporarily adjusting requested length since it is equal to sizeof(sahara_packet_end_image_tx)\n");
        len++;
        is_end_image_tx_size = true;
    }

    if (conn->target_is_64bit) {
        sahara_packet_64_bit_memory_read mem_read_64 = {
            .header = {.command = SAHARA_64_BITS_MEMORY_READ_ID, .length = sizeof(sahara_packet_64_bit_memory_read)},
            .memory_addr = addr,
            .memory_length = len,
        };
        /*
        qcomdl_log_debug("Sending 64bit memory read request: addr=0x%"PRIx64" length=0x%"PRIx64"\n",
                    mem_read_64.memory_addr,
                    mem_read_64.memory_length);
         */
        if (write_bulk(conn->usb_dev, &mem_read_64, sizeof(mem_read_64)) != sizeof(mem_read_64)) {
            qcomdl_log_error("Failed to write 64_bit_memory_read packet to target\n");
            return -1;
        }
    } else {
        if (addr > UINT32_MAX) {
            qcomdl_log_error("Invalid address for 32-bit memory read: 0x%"PRIx64" is greater than UINT32_MAX\n", addr);
            return -1;
        }
        sahara_packet_memory_read mem_read = {
            .header = {.command = SAHARA_MEMORY_READ_ID, .length = sizeof(sahara_packet_memory_read)},
            .memory_addr = (uint32_t)addr,
            .memory_length = (uint32_t)len,
        };
        /*
        qcomdl_log_debug("Sending memory read request: addr=0x%x length=0x%x\n",
                    mem_read.memory_addr,
                    mem_read.memory_length);
         */
        if (write_bulk(conn->usb_dev, &mem_read, sizeof(mem_read)) != sizeof(mem_read)) {
            qcomdl_log_error("Failed to write memory_read packet to target\n");
            return -1;
        }
    }

    uint8_t *tmpbuf = calloc(1, (size_t)len);
    if (!tmpbuf) {
        qcomdl_log_error("Cannot allocate %"PRIu64" bytes - %s\n", len, strerror(errno));
        return -1;
    }
    
    conn->host_state = SAHARA_STATE_WAIT_MEMORY_REGION;
    int readlen = read_bulk(conn->usb_dev, tmpbuf, (int)len);

    // qcomdl_log_debug("Got memory read response raw data: %i bytes\n", readlen);

    if (readlen < 0) {
        qcomdl_log_error("Read error - received negative read result: %i\n", readlen);
        free(tmpbuf);
        return -1;
    } else if (readlen == sizeof(sahara_packet_end_image_tx)) {
        // This should never happen except in cases of a Sahara
        // error because sleep_funcwe change the len above.
        qcomdl_log_error("Target responded with packet size equal to sizeof(sahara_packet_end_image_tx)\n");

        conn->host_state = SAHARA_STATE_WAIT_COMMAND;
        uint32_t *msgid_p = (void*)tmpbuf;
        uint32_t msg_id = *msgid_p;
        if (msg_id == SAHARA_END_IMAGE_TX_ID) {
            handle_end_image_tx_packet(conn, tmpbuf, readlen);
        }
        free(tmpbuf);
        sahara_device_reset(conn);
        return -1;
    } else if ((readlen > 0) && (readlen < (int)len)) {
        while (readlen < (int)len) {
            int readlen_rest = read_bulk(conn->usb_dev, (tmpbuf+readlen), ((int)len-readlen));
            // qcomdl_log_debug("Got memory read response raw data: %i bytes\n", readlen_rest);
            if (readlen_rest < 0) {
                qcomdl_log_error("Read error - received negative read result: %i\n", readlen_rest);
                free(tmpbuf);
                return -1;
            }
            readlen += readlen_rest;
        }
    } else if (readlen != (int)len) {
        qcomdl_log_error("Target did not respond with expected length of data: %i != %"PRIu64"\n", readlen, len);
        free(tmpbuf);
        return -1;
    }

    if (is_end_image_tx_size) {
        len--;
    }

    int ret = 0;

    if ((len % 512) == 0) {
        char empty[4];
        readlen = read_bulk(conn->usb_dev, empty, 0);
        if (readlen != 0) {
            qcomdl_log_error("Target didn't send us a ZLP\n");
            free(tmpbuf);
            return -1;
        }
    }

    conn->host_state = SAHARA_STATE_RECV_MEMORY_REGION;

    *buf_out = tmpbuf;
    *buf_out_size = (size_t)len;
    return ret;
}


int sahara_memory_read_to_file(sahara_connection_t *conn, uint64_t addr, uint64_t length, const char *outpath)
{
    qcomdl_log_debug("Dumping memory region addr=0x%"PRIx64" len=0x%"PRIx64" to %s\n", addr, length, outpath);

    FILE *f = fopen(outpath, "wb");
    if (!f) {
        qcomdl_log_error("Cannot create %s - %s", outpath, strerror(errno));
        return -1;
    }

    if ((conn->target_is_64bit) &&  (addr > UINT32_MAX)) {
        qcomdl_log_error("Invalid address for 32-bit memory read: 0x%"PRIx64" is greater than UINT32_MAX\n", addr);
        return -1;
    }

#if defined(_WIN32)
    int do_progress = 0; // the progress text causes a lot of slowness when building with MINGW
#else
    int do_progress = qcomdl_log_isatty();
#endif

    uint64_t total_written = 0;
    while (total_written < length) {
        uint64_t bytes_left = (length - total_written);
        uint64_t chunk_length = (bytes_left < SAHARA_MAX_MEMORY_READ_LENGTH)? bytes_left : SAHARA_MAX_MEMORY_READ_LENGTH;

        uint8_t *buf = NULL;
        size_t buf_size = 0;
        if (sahara_memory_read(conn, (addr + total_written), chunk_length, &buf, &buf_size) != 0) {
            qcomdl_log_error("Failed to read region: 0x%"PRIx64" - 0x%"PRIx64"\n", addr, (addr + length));
            fclose(f);
            return -1;
        }

        size_t written = fwrite(buf, 1, buf_size, f);
        free(buf);
        if (written != buf_size) {
            qcomdl_log_error("Error writing to %s - %s\n", outpath, strerror(errno));
            fclose(f);
            return -1;
        }

        total_written += written;

        if (do_progress) {
            qcomdl_log(QCOMDL_LOG_LEVEL_INFO, "\r ... 0x%08"PRIx64" / 0x%08"PRIx64" bytes transferred", total_written, length);
            qcomdl_log_flush();
        }
    }

    if (do_progress) {
        qcomdl_log(QCOMDL_LOG_LEVEL_INFO, "\n");
        qcomdl_log_flush();
    }

    fclose(f);
    return 0;
}


int sahara_done(sahara_connection_t *conn)
{
    qcomdl_log_debug("Sending Done packet to target\n");
    sahara_packet_header done_pkt = {
        .command = SAHARA_DONE_ID,
        .length = sizeof(sahara_packet_header),
    };

    int len = write_bulk(conn->usb_dev, &done_pkt, (int)sizeof(done_pkt));
    if (len != (int)sizeof(done_pkt)) {
        qcomdl_log_error("cannot send done packet: len=%i\n", len);
        return -1;
    }

    conn->host_state = SAHARA_STATE_WAIT_DONE_RESP;
    if ((sahara_process_packets(conn) != 0) || (conn->host_state != SAHARA_STATE_RECV_DONE_RESP)) {
        return -1;
    }

    return 0;
}


// Note - sahara device reset does not actually appear to bring the device
// back up in EDL mode. However it does effectively stop the sahara protocol.
// TODO -- determine if we even want to use this api. Firehose's <power> does
// the right thing, by contrast.
int sahara_device_reset(sahara_connection_t *conn)
{
    int max_tries = 3;

    sahara_packet_reset reset_req = {
        .header = {.command = SAHARA_RESET_ID, .length = sizeof(sahara_packet_header)},
    };

    conn->host_state = SAHARA_STATE_WAIT_RESET_RESP;
    for (int tries = 0; tries < max_tries; tries++) {
        qcomdl_log_debug("Sending Sahara RESET command (try %i out of %i)\n", tries+1, max_tries);

        int len = write_bulk(conn->usb_dev, &reset_req, sizeof(reset_req));
        if (len != sizeof(reset_req)) {
            qcomdl_log_error("There was an error sending the reset request\n");
            return -1;
        }

        conn->host_state = SAHARA_STATE_WAIT_RESET_RESP;
        if (sahara_process_packets(conn) != 0) {
            return -1;
        }

        if (conn->host_state == SAHARA_STATE_RECV_RESET_RESP) {
            return 0;
        }
        qcomdl_log_debug("No RESET response received after %i tries\n", tries+1);
    }

    qcomdl_log_debug("Giving up on getting a RESET response after %i tries\n", max_tries);

    return -1;
}
