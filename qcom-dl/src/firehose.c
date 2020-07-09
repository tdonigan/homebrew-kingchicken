// Copyright © 2015-2017 Square, Inc. All rights reserved.

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>
#include <ctype.h>
#include <assert.h>
#include <inttypes.h>

#include <libxml/parser.h>

#include "firehose.h"
#include "edl.h"
#include "qcomdl_log.h"
#include "resource.h"
#include "qcomdl_transport.h"
#include "sha256.h"

#define FIREHOSE_RESPONSE_BUF_SIZE 0x4000
#define FIREHOSE_DEFAULT_TRANSFER_TIMEOUT_MSEC (8 * 1000)
#define FIREHOSE_MIN_SHA256DIGEST_TIMEOUT_MSEC (10 * 1000)

#define MBN_VIP_IMAGE_ID 0x1a
#define MBN_VERSION_NUM 0x03

enum {
    FIREHOSE_ACK_STATE_CLEAR = 0,
    FIREHOSE_ACK_STATE_ACK,
    FIREHOSE_ACK_STATE_NAK,
    FIREHOSE_ACK_STATE_UNKNOWN,
};

typedef int (firehose_response_handler_t)(int ack_state, xmlNodePtr response, void *ctx);

struct mbn40_header
{
    uint32_t image_id;
    uint32_t header_vsn_num;
    uint32_t image_src;
    uint32_t image_dest_ptr;
    uint32_t image_size;
    uint32_t code_size;
    uint32_t signature_ptr;
    uint32_t signature_size;
    uint32_t cert_chain_ptr;
    uint32_t cert_chain_size;
};


struct firehose_request_context {
    const char *label;
    int ack_state;
    bool zlp_sent;
    qcomdl_xfer_ctx *req_xfer;
    qcomdl_xfer_ctx *rsp_xfer;
    bool error;
    xmlNodePtr *response_node_out;
    uint8_t rsp_buf[FIREHOSE_RESPONSE_BUF_SIZE];
};

typedef struct firehose_request_context firehose_request_context_t;

struct firehose_verify_vip_ctx {
    size_t num_digests_consumed;
    size_t num_mbn_digests;
    size_t max_digest_table_count;
    qcomdl_resource_file_t *mbn_digests;
    qcomdl_resource_file_t *chained_digests;
    sha256_digest cur_digest;
};

typedef struct firehose_verify_vip_ctx firehose_verify_vip_ctx_t;

const u_char *firehoseAttrCfgAckRawDataEveryNumPackets = (const u_char*)"AckRawDataEveryNumPackets";
const u_char *firehoseAttrCfgAlwaysValidate = (const u_char*)"AlwaysValidate";
const u_char *firehoseAttrCfgMaxDigestTableSizeInBytes = (const u_char*)"MaxDigestTableSizeInBytes";
const u_char *firehoseAttrCfgMaxPayloadSizeFromTargetInBytes = (const u_char*)"MaxPayloadSizeFromTargetInBytes";
const u_char *firehoseAttrCfgMaxPayloadSizeToTargetInBytes = (const u_char*)"MaxPayloadSizeToTargetInBytes";
const u_char *firehoseAttrCfgMaxPayloadSizeToTargetInBytesSupported = (const u_char*)"MaxPayloadSizeToTargetInBytesSupported";
const u_char *firehoseAttrCfgMaxXMLSizeInBytes = (const u_char*)"MaxXMLSizeInBytes";
const u_char *firehoseAttrCfgMemoryName = (const u_char*)"MemoryName";
const u_char *firehoseAttrCfgMinVersionSupported = (const u_char*)"MinVersionSupported";
const u_char *firehoseAttrCfgSkipStorageInit = (const u_char*)"SkipStorageInit";
const u_char *firehoseAttrCfgSkipWrite = (const u_char*)"SkipWrite";
const u_char *firehoseAttrCfgTargetName = (const u_char*)"TargetName";
const u_char *firehoseAttrCfgVerbose = (const u_char*)"Verbose";
const u_char *firehoseAttrCfgVersion = (const u_char*)"Version";
const u_char *firehoseAttrCfgZlpAwareHost = (const u_char*)"ZlpAwareHost";

const u_char *firehoseAttrPatchSectorSizeInBytes = (const u_char*)"SECTOR_SIZE_IN_BYTES";
const u_char *firehoseAttrPatchByteOffset = (const u_char*)"byte_offset";
const u_char *firehoseAttrPatchSizeInBytes = (const u_char*)"size_in_bytes";
const u_char *firehoseAttrPatchFilename = (const u_char*)"filename";
const u_char *firehoseAttrPatchPhysicalPartitionNum = (const u_char*)"physical_partition_number";
const u_char *firehoseAttrPatchStartSector = (const u_char*)"start_sector";
const u_char *firehoseAttrPatchValue = (const u_char*)"value";
const u_char *firehoseAttrPatchWhat = (const u_char*)"what";

const u_char *firehoseAttrEraseStorageDrive = (const u_char*)"StorageDrive";

const u_char *firehoseAttrGetStorageInfoPhysicalPartitionNum = (const u_char*)"physical_partition_number";

const u_char *firehoseAttrPeekPokeAddress64 = (const u_char*)"address64";
const u_char *firehoseAttrPeekPokeSizeInBytes = (const u_char*)"SizeInBytes";
const u_char *firehoseAttrPeekPokeValue = (const u_char*)"value";

const u_char *firehoseAttrProgFilename = (const u_char*)"filename";
const u_char *firehoseAttrProgLabel = (const u_char*)"label";
const u_char *firehoseAttrProgSectorSizeInBytes = (const u_char*)"SECTOR_SIZE_IN_BYTES";
const u_char *firehoseAttrProgNumPartitionSectors = (const u_char*)"num_partition_sectors";
const u_char *firehoseAttrProgStartSector = (const u_char*)"start_sector";
const u_char *firehoseAttrProgPhysicalPartitionNum = (const u_char*)"physical_partition_number";
const u_char *firehoseAttrProgReadBackVerify = (const u_char*)"read_back_verify";


#pragma mark Forward static declarations

static int vip_digest_chunk_advance(firehose_connection_t *conn);


#pragma mark Private (static) Functions

static uint8_t hex_nibble(uint8_t nib)
{
    nib = nib & 0xf;
    if (nib < 0xa) {
        return nib + 0x30;
    } else {
        return nib + 0x57;
    }
}

static int hex(const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len)
{
    if (!data) {
        qcomdl_log_error("Null hex data\n");
        return -1;
    }

    if (!out) {
        qcomdl_log_error("Null hex output\n");
        return -1;
    }

    if (out_len < (data_len * 2)) {
        qcomdl_log_error("hex output size too small for data\n");
        return -1;
    }

    for (size_t i=0; i < data_len; i++) {
        uint8_t n1 = hex_nibble((data[i] & 0xf0) >> 4);
        uint8_t n2 = hex_nibble((data[i] & 0x0f));
        *out = n1;
        out++;
        *out = n2;
        out++;
    }

    return 0;
}


static int8_t unhex_nibble(uint8_t hex_nib)
{
    hex_nib = (uint8_t)tolower((int) hex_nib);

    if (hex_nib >= '0' && hex_nib <= '9') {
        return (int8_t)(hex_nib - 0x30);
    } else if (hex_nib >= 'a' && hex_nib <= 'f') {
        return (int8_t)(hex_nib - 0x57);
    } else {
        return -1;
    }
}


static int unhex(const uint8_t *hex_str, uint8_t *out, int out_size)
{
    if (!hex_str) {
        qcomdl_log_error("Null hex string\n");
        return -1;
    }
    if (out_size < 2) {
        qcomdl_log_error("Negative/too-small output buffer size for unhexing: %i\n", out_size);
        return -1;
    }

    int i = 0;
    while ((i < out_size) && (hex_str[0]) && (hex_str[1])) {
        if (isspace(hex_str[0])) {
            hex_str ++;
            continue;
        }

        int8_t n1 = unhex_nibble(hex_str[0]);
        int8_t n2 = unhex_nibble(hex_str[1]);

        if ((n1 < 0) || (n2 < 0)) {
            qcomdl_log_error("Invalid hex value encountered: '%s'\n", hex_str);
            return -1;
        }

        uint8_t b = (uint8_t)(n1 << 4) + (n2 & 0xf);
        out[i] = b;
        i++;
        hex_str += 2;
    }

    return i;
}


static ssize_t file_sector_count(qcomdl_resource_package_t *package, const char *path)
{
    uint64_t size;
    int ret = qcomdl_resource_package_get_size(package, package->img_dir, path, &size);
    if (ret != 0) {
        qcomdl_log_perror(path);
        return -1;
    }
    ssize_t num_sectors = (size / FIREHOSE_SECTOR_SIZE);
    if (size % FIREHOSE_SECTOR_SIZE) {
        num_sectors++;
    }

    if ((num_sectors < 0) || (num_sectors > INT_MAX)) {
        qcomdl_log_error("Over/Underflow in num_sectors: %zi (calculated filesize:%"PRIu64" / sector_size:%i)\n", num_sectors, size, FIREHOSE_SECTOR_SIZE);
        return -1;
    }

    return num_sectors;
}


static bool wrap_percent_start_sectors_from_file(const char *file, size_t file_sectors, void *ctx)
{
    struct firehose_percent_progress_api *api = ctx;
    if (!ctx) {
        qcomdl_log_error("percentage start_sectors_from_file callback invoked without context\n");
        return false;
    }
    api->_internal_last_file_sectors_written = 0;
    return true;
}


static bool wrap_percent_sent_file_sectors(const char *file, size_t sectors_written, void *ctx)
{
    struct firehose_percent_progress_api *api = ctx;
    if (!ctx) {
        qcomdl_log_error("percentage percent_sent_file_sectors callback invoked without context\n");
        return false;
    }

    if (api->_internal_last_file_sectors_written > sectors_written) {
        qcomdl_log_error("percent callback found api->_internal_last_file_sectors_written(%zu) > sectors_written(%zu)\n", api->_internal_last_file_sectors_written, sectors_written);
        return false;
    }

    size_t change = sectors_written - api->_internal_last_file_sectors_written;
    api->_internal_last_file_sectors_written = sectors_written;
    api->_internal_total_progess_sectors += change;

    if (api->total_image_sectors == 0) {
        qcomdl_log_error("percent callback found total_image_sectors set to 0\n");
        return false;
    }

    int pct = (int)(((float)api->_internal_total_progess_sectors/(float)api->total_image_sectors) * 100.0f);
    if ((api->handle_progress_percent) && (pct > api->_internal_last_percent)) {
        if (! api->handle_progress_percent(pct, api->_internal_ctx)) {
            return false;
        }
    }
    api->_internal_last_percent = pct;
    return true;
}


static const char *get_xml_error(void)
{
    xmlErrorPtr err = xmlGetLastError();
    if (err) {
        return err->message;
    } else {
        return "[xml error is not set]";
    }
}

static xmlNodePtr get_root_data_node(xmlDocPtr doc)
{
    xmlNodePtr root_node = xmlDocGetRootElement(doc);
    if (root_node && strcmp((const char*)root_node->name, "data") == 0) {
        return root_node;
    } else {
        return NULL;
    }
}


static int get_ack_value(xmlNodePtr response)
{
    int ret = FIREHOSE_ACK_STATE_UNKNOWN;
    xmlChar *ack_value = xmlGetProp(response, (const xmlChar*)"value");
    if (ack_value) {
        qcomdl_log_debug("Received %s\n", ack_value);
        if (strcmp((const char*)ack_value, "ACK") == 0) {
            ret = FIREHOSE_ACK_STATE_ACK;
        } else if (strcmp((const char*)ack_value, "NAK") == 0) {
            ret = FIREHOSE_ACK_STATE_NAK;
        }
    }
    xmlFree(ack_value);

    return ret;
}


static void handle_log_message(xmlNodePtr msg_node)
{
    xmlChar *log_value = xmlGetProp(msg_node, (const xmlChar*)"value");
    if (log_value) {
        qcomdl_log(QCOMDL_LOG_LEVEL_INFO, "[target-log] %s\n", log_value);
    } else {
        qcomdl_log_info("Warning! received log message from target with no value.\n");
    }
    xmlFree(log_value);
}


static int handle_xml_message(xmlDocPtr doc, firehose_request_context_t *request_ctx)
{
    if (!doc) {
        return -1;
    }

    if (qcomdl_log_get_level() >= QCOMDL_LOG_LEVEL_VERBOSE_DEBUG) {
        qcomdl_log_verbose_debug("Received xml message:\n");
        FILE *out = qcomdl_log_get_output();
        xmlDocDump(out, doc);
        fprintf(out, "\n");
    }

    xmlNodePtr data_node = get_root_data_node(doc);
    if (!data_node) {
        qcomdl_log_error("Failed to get data node at root\n");
        return -1;
    }

    int ret = 0;
    bool got_response = false;
    for (xmlNodePtr cur = data_node->children; cur; cur = cur->next) {
        const char *msgtype = (const char *)cur->name;
        if (strcmp(msgtype, "log") == 0) {
            handle_log_message(cur);
        } else if (strcmp(msgtype, "response") == 0) {
            if (got_response) {
                qcomdl_log_error("multiple responses received in data envelope?\n");
                return -1;
            }

            if (!request_ctx) {
                qcomdl_log_error("Argument error, missing response without request context\n");
                return -1;
            }

            request_ctx->ack_state = get_ack_value(cur);
            if (request_ctx->response_node_out) {
                *request_ctx->response_node_out = cur;
            }

            got_response = true;
        } else if (strcmp(msgtype, "text") == 0) {
            /* SDM660 responses format their XML as such:

               <?xml version="1.0" encoding="UTF-8"?>
               <data>
               <response value="ACK"/>
               </data>

               Since this XML is now 'structured', there are 1-byte text
               nodes containing the newline character. Seen here between
               the end of the response node and the ending data node.
            */
            if (strlen((const char *)cur->content) == 1 && cur->content[0] == '\n') {
                continue;
            }

            xmlBufferPtr buffer = xmlBufferCreate();
            int size = xmlNodeDump(buffer, doc, cur, 0, 1);
            if (size > 0) {
                qcomdl_log(QCOMDL_LOG_LEVEL_WARNING, "Unexpected TEXT element with len %d: '%.*s' for parent node '%s'\n",
                           size, size, buffer->content, cur->parent->name);
            } else {
                qcomdl_log(QCOMDL_LOG_LEVEL_WARNING, "Unexpected TEXT element with invalid len %d: for parent node '%s'\n", size, cur->parent->name);
            }
            xmlBufferFree(buffer);
        } else {
            qcomdl_log_error("Unexpected message type: %s\n", msgtype);
            ret = -1;
        }
    }

    return ret;
}


static void firehose_cb_data_in(qcomdl_xfer_ctx *ctx) {
    firehose_request_context_t *req = qcomdl_xfer_get_user_data(ctx);
    if (!req) {
        qcomdl_log_error("Missing request context\n");
        abort();
    }

    qcomdl_xfer_status status = qcomdl_xfer_get_status(ctx);
    if (status == QCOMDL_XFER_CANCELLED) {
        return;
    }

    // TODO(EM) - Probably need to handle short reads flagged as LIBUSB_TRANSFER_OVERFLOW?

    if (status != QCOMDL_XFER_COMPLETED) {
        req->error = true;
        return;
    }

    int actual_length = qcomdl_xfer_get_actual_length(ctx);
    if (actual_length < 0) {
        qcomdl_log_error("Received negative length transfer? - label=%s length=%i\n", req->label, actual_length);
        return;
    }

    char *buffer = qcomdl_xfer_get_buffer(ctx);
    xmlDocPtr doc = xmlReadMemory(buffer, actual_length, NULL, NULL, 0);
    memset(buffer, 0, (size_t)qcomdl_xfer_get_buffer_length(ctx));

    if (!doc) {
        qcomdl_log_error("Failed to parse response xml label=%s (length=%i) - %s\n",
                         req->label, actual_length, get_xml_error());
        req->error = true;
        return;
    }

    handle_xml_message(doc, req);

    // free the doc only if the caller didn't want to retain the response
    // caller must free node->doc in this case
    if ((!req->response_node_out) || (!(*req->response_node_out))) {
        xmlFreeDoc(doc);
    }

    if (req->ack_state == FIREHOSE_ACK_STATE_CLEAR) {
        qcomdl_xfer_submit(req->rsp_xfer);
    }
}


static void firehose_cb_data_out(qcomdl_xfer_ctx *ctx) {
    firehose_request_context_t *req = qcomdl_xfer_get_user_data(ctx);
    if (!req) {
        qcomdl_log_error("Missing request context\n");
        abort();
    }

    qcomdl_xfer_status status = qcomdl_xfer_get_status(ctx);
    if (status == QCOMDL_XFER_CANCELLED) {
        qcomdl_log_debug("libusb request xfer label=%s cancelled\n", req->label);
        return;
    }

    // TODO(EM) - Probably need to handle short writes (doc'd as "overflows")?

    if (status != QCOMDL_XFER_COMPLETED) {
        req->error = true;
    }
}


static firehose_request_context_t *create_request(firehose_connection_t *conn, char *req_data, int req_size)
{
    if (!conn) {
        qcomdl_log_error("NULL conn argument\n");
        return NULL;
    }

    firehose_request_context_t *req = calloc(1, sizeof(firehose_request_context_t));
    if (!req) {
        qcomdl_log_error("Unable to allocate request_context structure\n");
        return NULL;
    }

    req->ack_state = FIREHOSE_ACK_STATE_CLEAR;
    req->error = false;
    req->label = __func__;

    memset(req->rsp_buf, 0, FIREHOSE_RESPONSE_BUF_SIZE);

    req->rsp_xfer = qcomdl_xfer_ctx_create(conn->usb_dev,
                                            EDL_ENDPOINT_BULK_IN,
                                            req->rsp_buf,
                                            (FIREHOSE_RESPONSE_BUF_SIZE),
                                            firehose_cb_data_in,
                                            req,
                                            conn->cfg.timeout,
                                            req->label);
    if (!req->rsp_xfer) {
        qcomdl_log_error("Unable to allocate libusb response transfer\n");
        free(req);
        return NULL;
    }

    if (req_data) {
        req->req_xfer = qcomdl_xfer_ctx_create(conn->usb_dev,
                                                EDL_ENDPOINT_BULK_OUT,
                                                req_data,
                                                req_size,
                                                firehose_cb_data_out,
                                                req,
                                                conn->cfg.timeout,
                                                req->label);
        if (!req->req_xfer) {
            qcomdl_log_error("Unable to allocate libusb request transfer\n");
            qcomdl_xfer_free(req->rsp_xfer);
            free(req);
            return NULL;
        }
    } else {
        // No request data
        req->req_xfer = NULL;
    }

    return req;
}



static void free_request(firehose_request_context_t *req)
{
    if (req) {
        if ((req->response_node_out) && *(req->response_node_out)) {
            xmlFreeDoc((*req->response_node_out)->doc);
        }
        if (req->rsp_xfer) {
            qcomdl_xfer_free(req->rsp_xfer);
            req->rsp_xfer = NULL;
        }
        if (req->req_xfer) {
            qcomdl_xfer_free(req->req_xfer);
            req->req_xfer = NULL;
        }
        free(req);
    }
}


static qcomdl_xfer_ctx *create_raw_transfer(firehose_connection_t *conn, uint8_t *data, int data_size, firehose_request_context_t *req)
{
    req->label = __func__;
    qcomdl_xfer_ctx *raw_xfer = qcomdl_xfer_ctx_create(conn->usb_dev,
                                                        EDL_ENDPOINT_BULK_OUT,
                                                        data,
                                                        data_size,
                                                        firehose_cb_data_out,
                                                        req,
                                                        conn->cfg.timeout,
                                                        req->label);
    if (!raw_xfer) {
        qcomdl_log_error("unable to allocate libusb raw transfer\n");
        return NULL;
    }

    return raw_xfer;
}


static int send_raw_transfer(firehose_connection_t *conn, qcomdl_xfer_ctx *raw_xfer, firehose_request_context_t *req)
{
    int submit_ret = qcomdl_xfer_submit(raw_xfer);
    if (submit_ret) {
        qcomdl_log_error("unable to submit raw_xfer\n");
        return -1;
    }

    while ((qcomdl_xfer_get_status(raw_xfer) == QCOMDL_XFER_PENDING) && (!req->error) && (req->ack_state == FIREHOSE_ACK_STATE_CLEAR)) {
        int r = qcomdl_xfer_poll();
        if (r) {
            qcomdl_log_error("Failed to poll for USB events\n");
            return -1;
        }
    }

    return 0;
}


static firehose_request_context_t *send_acked_request(firehose_connection_t *conn, char *request_data, int len, xmlNodePtr *response_node_out)
{
    if (!conn || !request_data) {
        qcomdl_log_error("Null arguments\n");
        return NULL;
    }

    if (conn->vip_enabled) {
        if (vip_digest_chunk_advance(conn) != 0) {
            return NULL;
        }
    }

    firehose_request_context_t *req = create_request(conn, request_data, len);
    if (!req) {
        qcomdl_log_error("Unable to create request\n");
        return NULL;
    }

    req->response_node_out = response_node_out;

    qcomdl_xfer_submit(req->rsp_xfer);
    qcomdl_xfer_submit(req->req_xfer);

    while ((!req->error) && req->ack_state == FIREHOSE_ACK_STATE_CLEAR) {
        int r = qcomdl_xfer_poll();
        if (r) {
            req->error = true;
            break;
        }
    }
    
    return req;
}


static void wait_for_firehose_ack(firehose_connection_t *conn, firehose_request_context_t *req)
{
    // wait for firehose ack
    if (!req->error && req->ack_state == FIREHOSE_ACK_STATE_CLEAR) {
        req->label = "ack";
        int r = qcomdl_xfer_submit(req->rsp_xfer);
        if (r) {
            qcomdl_log_error("unable to submit ack xfer\n");
            req->error = true;
            return;
        }

        while ((!req->error) && req->ack_state == FIREHOSE_ACK_STATE_CLEAR) {
            r = qcomdl_xfer_poll();
            if (r) {
                qcomdl_log_error("handle_event error\n");
                req->error = true;
                return;
            }
        }
    }
}


static int init_chained_digests(firehose_connection_t *conn, qcomdl_resource_package_t *package, const char *chained_digests_path)
{
    // this function needs to handle both the file existing and not existing - both are valid
    if (qcomdl_resource_package_file_exists(package, package->img_dir, chained_digests_path) == 0) {
        conn->vip_chained_digests_file = qcomdl_fopen(package, package->img_dir, chained_digests_path, "rb");
        qcomdl_log_info("Setting chained digests file: %s\n", chained_digests_path);
        if (!conn->vip_chained_digests_file) {
            qcomdl_log_error("Unable to open chained digests file %s - %s", chained_digests_path, strerror(errno));
            return -1;
        }
    } else {
        qcomdl_log_debug("Chained digests file does not exist at %s - assuming no chained digests for build\n", chained_digests_path);
        conn->vip_chained_digests_file = NULL;
    }
    return 0;
}


static int send_next_digest_table_chunk(firehose_connection_t *conn) {
    if (conn->cfg.MaxDigestTableSizeInBytes < 0) {
        qcomdl_log_error("MaxDigestTableSizeInBytes negative value\n");
        return -1;
    }

    if (!conn->vip_chained_digests_file) {
        qcomdl_log_error("digest file not initialized\n");
        return -1;
    }

    size_t table_size = (size_t)conn->cfg.MaxDigestTableSizeInBytes;
    uint8_t *table_data = calloc(1, table_size);
    if (!table_data) {
        qcomdl_log_perror("calloc");
        return -1;
    }

    size_t bytes_read = 0;
    while (bytes_read < table_size && (!qcomdl_feof(conn->vip_chained_digests_file)) && (!qcomdl_ferror(conn->vip_chained_digests_file))) {
        bytes_read += qcomdl_fread((table_data + bytes_read), 1, (size_t)(table_size-bytes_read), conn->vip_chained_digests_file);
    }

    if (bytes_read < FIREHOSE_DIGEST_SIZE) {
        qcomdl_log_error("unable to read at least %i bytes from chained digests file (only got %zu)\n", FIREHOSE_DIGEST_SIZE, bytes_read);
        free(table_data);
        return -1;
    }

    qcomdl_log_debug("Sending %zu bytes of chained digests\n", bytes_read);
    conn->vip_enabled = false;
    firehose_request_context_t *req = send_acked_request(conn, (char*)table_data, (int)bytes_read, NULL);
    conn->vip_enabled = true;
    int ret = ((!req->error) && (req->ack_state == FIREHOSE_ACK_STATE_ACK)) ? (int)bytes_read : -1;
    free_request(req);
    free(table_data);
    return ret;
}


static int vip_digest_chunk_advance(firehose_connection_t *conn)
{
    if (conn->vip_digests_chunk_left == 0) {
        qcomdl_log_error("Exhausted current digest pool without sending chained digest chunk\n");
        return -1;
    }

    conn->vip_digests_chunk_left--;
    conn->vip_total_packet_count++;

    //qcomdl_log(0, "\nPacket #%zu\n", conn->vip_total_packet_count);

    if (conn->vip_digests_chunk_left == 0) {
        int bytes_sent = send_next_digest_table_chunk(conn);
        if (bytes_sent < FIREHOSE_DIGEST_SIZE) {
            qcomdl_log_error("There was an error sending the current chained digest chunk\n");
            return -1;
        }

        conn->vip_digests_chunk_left = (size_t)(bytes_sent / FIREHOSE_DIGEST_SIZE);

        if (!qcomdl_feof(conn->vip_chained_digests_file)) {
            conn->vip_digests_chunk_left--; // last digest will point at next chained digest file chunk
        }
    }

    return 0;
}


static int send_raw_data(firehose_connection_t *conn, uint8_t *data, int size, firehose_request_context_t *req)
{
    if (conn->vip_enabled) {
        if (vip_digest_chunk_advance(conn) != 0) {
            return -1;
        }
    }

    qcomdl_xfer_ctx *raw_xfer = create_raw_transfer(conn, data, size, req);
    if (!raw_xfer) {
        req->error = true;
        return -1;
    }

    int r = send_raw_transfer(conn, raw_xfer, req);
    qcomdl_xfer_free(raw_xfer);

    if ((r != 0) || (qcomdl_xfer_get_status(raw_xfer) != QCOMDL_XFER_COMPLETED)) {
        req->error = true;
        return -1;
    }

    return 0;
}


static firehose_request_context_t *send_raw_chunked_file(firehose_connection_t *conn, qcomdl_resource_package_t *package, const char *filename, qcomdl_resource_file_t *f)
{
    size_t sectors_written = 0;
    int chunk_size = conn->cfg.MaxPayloadSizeToTargetInBytes;

    if ((chunk_size < FIREHOSE_SECTOR_SIZE) || (chunk_size % FIREHOSE_SECTOR_SIZE)) {
        qcomdl_log_error("connection configured with invalid payload_size: %i\n", chunk_size);
        return NULL;
    }
    ssize_t total_file_sectors = file_sector_count(package, filename);
    if (total_file_sectors < 0) {
        return NULL;
    }

    firehose_request_context_t *req = create_request(conn, NULL, 0);
    if (!req) {
        qcomdl_log_error("unable to create request context\n");
        return NULL;
    }

    uint8_t *chunk = malloc((size_t)chunk_size);
    if (!chunk) {
        qcomdl_log_error("unable to allocate %i bytes - %s\n", chunk_size, strerror(errno));
        free_request(req);
        return NULL;
    }

    if (conn->file_progress_handlers.handle_start_sectors_from_file) {
        if (! conn->file_progress_handlers.handle_start_sectors_from_file(filename, (size_t)total_file_sectors, conn->file_progress_ctx)) {
            qcomdl_log_error("Transfer interrupted by progress API callback\n");
            free_request(req);
            free(chunk);
            return NULL;
        }
    }

    while (!qcomdl_feof(f) && (!req->error) && (req->ack_state == FIREHOSE_ACK_STATE_CLEAR)) {
        memset(chunk, 0, (size_t)chunk_size);
        int send_size = (int)qcomdl_fread(chunk, 1, (size_t)chunk_size, f);
        if ((send_size != chunk_size) && (!qcomdl_feof(f))) {
            qcomdl_log_error("short read from file handle before end of file: %i < %i\n", send_size, chunk_size);
            req->error = true;
            break;
        } else if (!send_size) {
            // On some systems we may not get feof -> true until we do a
            // final read even if we are positioned at the end of a file.
            break;
        }

        int extra = send_size % FIREHOSE_SECTOR_SIZE;
        if (extra) {
            send_size += (FIREHOSE_SECTOR_SIZE - extra);
        }

        if (send_raw_data(conn, chunk, send_size, req) != 0) {
            break;
        }

        sectors_written += (size_t)(send_size / FIREHOSE_SECTOR_SIZE);

        if (conn->file_progress_handlers.handle_sent_file_sectors) {
            if (! conn->file_progress_handlers.handle_sent_file_sectors(filename, sectors_written, conn->file_progress_ctx)) {
                qcomdl_log_error("Transfer interrupted by progress API callback\n");
                req->error = true;
                break;
            }
        }
    }

    if (conn->file_progress_handlers.handle_finished_sectors_from_file) {
        int r = (req->error)? -1 : 0;
        if (! conn->file_progress_handlers.handle_finished_sectors_from_file(filename, r, sectors_written, conn->file_progress_ctx)) {
            qcomdl_log_error("Transfer interrupted by progress API callback\n");
            req->error = true;
        }
    } else {
        qcomdl_log_debug("raw write loop finished sectors written = %zu\n", sectors_written);
    }

    free(chunk);

    wait_for_firehose_ack(conn, req);

    return req;
}


static firehose_request_context_t *send_xml_request(firehose_connection_t *conn, char *xml_request, int len, xmlNodePtr *response_node_out)
{
    qcomdl_log_verbose_debug("Sending xml request (%i bytes) :\n%s\n", len, xml_request);
    return send_acked_request(conn, xml_request, len, response_node_out);
}


static const xmlChar *itoxmlchar(int intval, xmlChar *out_buf, size_t out_buf_size)
{
    if (out_buf_size == 0) {
        qcomdl_log_error("FATAL: zero-length buffer passed in: %zu\n", out_buf_size);
        abort();
    }
    int rc = snprintf((char*)out_buf, out_buf_size - 1, "%i", intval);
    if (rc < 0) {
        qcomdl_log_error("snprintf error\n");
        abort();
    }
    if (out_buf_size < (size_t)rc)  {
        qcomdl_log_error("FATAL: int string value would overflow buffer sized: %zu?\n", out_buf_size);
        abort();
    }
    return out_buf;
}


static int get_prop_as_int(xmlNodePtr node, const xmlChar* propname)
{
    xmlChar *value = xmlGetProp(node, propname);
    if (!value) {
        return -1;
    }
    int ret = atoi((char*)value);
    xmlFree(value);
    return ret;
}


static int handle_config_response(xmlNodePtr response, firehose_connection_t *conn)
{
    if (!conn) {
        qcomdl_log_error("Called with null connection\n");
        return -1;
    }

    qcomdl_log_debug("got config response\n");

    int max_payload_sz_supported = get_prop_as_int(response, firehoseAttrCfgMaxPayloadSizeToTargetInBytesSupported);
    if ((max_payload_sz_supported > conn->cfg.MaxPayloadSizeToTargetInBytes) && (max_payload_sz_supported % FIREHOSE_SECTOR_SIZE) == 0) {
        qcomdl_log_debug("Target supports a larger max payload size than proposed: (supported=%i > proposed=%i)\n",
                    max_payload_sz_supported, conn->cfg.MaxPayloadSizeToTargetInBytes);
        conn->cfg.MaxPayloadSizeToTargetInBytesSupported = max_payload_sz_supported;
    }

    int max_payload_sz = get_prop_as_int(response, firehoseAttrCfgMaxPayloadSizeToTargetInBytes);
    if (max_payload_sz < FIREHOSE_SECTOR_SIZE || (max_payload_sz % FIREHOSE_SECTOR_SIZE) != 0) {
        qcomdl_log_error("Received invalid/missing max payload size from target: %i\n", max_payload_sz);
        return -1;
    }

    conn->cfg.MaxPayloadSizeToTargetInBytes = max_payload_sz;

    // Not sure if we need these, but they seem useful...
    conn->cfg.MaxXMLSizeInBytes = get_prop_as_int(response, firehoseAttrCfgMaxXMLSizeInBytes);
    conn->cfg.MaxPayloadSizeFromTargetInBytes = get_prop_as_int(response, firehoseAttrCfgMaxPayloadSizeFromTargetInBytes);

    xmlChar *mem_name = xmlGetProp(response, firehoseAttrCfgMemoryName);
    if (mem_name) {
        conn->memory_name = strdup((char*)mem_name);
    }
    xmlFree(mem_name);
    xmlChar *target_name = xmlGetProp(response, firehoseAttrCfgTargetName);
    if (target_name) {
        conn->target_name = strdup((char*)target_name);
    }
    xmlFree(target_name);

    // TODO(EM) do we need to store anything else back into our config?

    return 0;
}


static xmlNodePtr create_firehose_xml_command(xmlChar *command_name)
{
    xmlDocPtr doc = xmlNewDoc((xmlChar*)"1.0");
    if (!doc) {
        qcomdl_log_error("cannot create a new xml doc - %s\n", get_xml_error());
        return NULL;
    }

    xmlNodePtr data_node = xmlNewNode(NULL, (xmlChar*)"data");
    if (!data_node) {
        qcomdl_log_error("cannot create xml root data node - %s\n", get_xml_error());
        xmlFreeDoc(doc);
        return NULL;
    }

    xmlDocSetRootElement(doc, data_node);

    xmlNodePtr command_node = xmlNewNode(NULL, command_name);
    if (!data_node) {
        qcomdl_log_error("cannot create xml %s node - %s\n", command_name, get_xml_error());
        xmlFreeDoc(doc);
        return NULL;
    }

    xmlAddChild(data_node, command_node);

    return command_node;
}


static int create_config_xml(struct firehose_configuration *cfg, uint8_t **out_xml, int *out_xml_size)
{
    if (!cfg) {
        qcomdl_log_error("missing cfg\n");
        return -1;
    }

    xmlNodePtr node = create_firehose_xml_command((xmlChar*)"configure");
    if (!node) {
        return -1;
    }

    // MaxPayloadSizeFromTargetInBytes is always sent.
    if (cfg->MaxPayloadSizeToTargetInBytes < FIREHOSE_SECTOR_SIZE) {
        cfg->MaxPayloadSizeToTargetInBytes = FIREHOSE_DEFAULT_PAYLOAD_SIZE;
    }

    xmlChar tmp_str_buf[32];
    xmlSetProp(node, firehoseAttrCfgMaxPayloadSizeToTargetInBytes,
               itoxmlchar(cfg->MaxPayloadSizeToTargetInBytes, tmp_str_buf, sizeof(tmp_str_buf)));

    // string values

    if (cfg->MemoryName) {
        xmlSetProp(node, firehoseAttrCfgMemoryName, (xmlChar*)cfg->MemoryName);
    }

    if (cfg->TargetName) {
        xmlSetProp(node, firehoseAttrCfgTargetName, (xmlChar*)cfg->TargetName);
    }

    // optional int values

    if (cfg->AckRawDataEveryNumPackets > -1) {
        xmlSetProp(node, firehoseAttrCfgAckRawDataEveryNumPackets,
                   itoxmlchar(cfg->AckRawDataEveryNumPackets, tmp_str_buf, sizeof(tmp_str_buf)));
    }

    if (cfg->AlwaysValidate > -1) {
        xmlSetProp(node, firehoseAttrCfgAlwaysValidate,
                   itoxmlchar(cfg->AlwaysValidate, tmp_str_buf, sizeof(tmp_str_buf)));
    }

    if (cfg->MaxDigestTableSizeInBytes > -1) {
        xmlSetProp(node, firehoseAttrCfgMaxDigestTableSizeInBytes,
                   itoxmlchar(cfg->MaxDigestTableSizeInBytes, tmp_str_buf, sizeof(tmp_str_buf)));
    }

    if (cfg->MinVersionSupported > -1) {
        xmlSetProp(node, firehoseAttrCfgMinVersionSupported,
                   itoxmlchar(cfg->MinVersionSupported, tmp_str_buf, sizeof(tmp_str_buf)));
    }

    if (cfg->SkipStorageInit > -1) {
        xmlSetProp(node, firehoseAttrCfgSkipStorageInit,
                   itoxmlchar(cfg->SkipStorageInit, tmp_str_buf, sizeof(tmp_str_buf)));
    }

    if (cfg->SkipWrite > -1) {
        xmlSetProp(node, firehoseAttrCfgSkipWrite,
                   itoxmlchar(cfg->SkipWrite, tmp_str_buf, sizeof(tmp_str_buf)));
    }

    if (cfg->Verbose > -1) {
        xmlSetProp(node, firehoseAttrCfgVerbose,
                   itoxmlchar(cfg->Verbose, tmp_str_buf, sizeof(tmp_str_buf)));
    }

    if (cfg->Version > -1) {
        xmlSetProp(node, firehoseAttrCfgVersion,
                   itoxmlchar(cfg->Version, tmp_str_buf, sizeof(tmp_str_buf)));
    }

    if (cfg->ZlpAwareHost > -1) {
        xmlSetProp(node, firehoseAttrCfgZlpAwareHost,
                   itoxmlchar(cfg->ZlpAwareHost, tmp_str_buf, sizeof(tmp_str_buf)));
    }

    *out_xml = NULL;
    *out_xml_size = 0;
    xmlDocDumpMemory(node->doc, out_xml, out_xml_size);
    xmlFreeDoc(node->doc);
    return (*out_xml != NULL)? 0 : -1;
}


static int create_power_xml(char *value, int delay_secs, uint8_t **out_xml, int *out_xml_size)
{
    xmlNodePtr node = create_firehose_xml_command((xmlChar*)"power");
    if (!node) {
        return -1;
    }

    xmlChar tmp_str_buf[32];
    xmlSetProp(node, (xmlChar*)"value", (xmlChar*)value);
    if (delay_secs > 0) {
        xmlSetProp(node, (xmlChar*)"DelayInSeconds", itoxmlchar(delay_secs, tmp_str_buf, sizeof(tmp_str_buf)));
    }

    *out_xml = NULL;
    *out_xml_size = 0;
    xmlDocDumpMemory(node->doc, out_xml, out_xml_size);
    xmlFreeDoc(node->doc);
    return (*out_xml != NULL)? 0 : -1;
}


static int create_benchmark_xml(int trials, uint8_t **out_xml, int *out_xml_size)
{
    xmlNodePtr node = create_firehose_xml_command((xmlChar*)"benchmark");
    if (!node) {
        return -1;
    }

    xmlChar tmp_str_buf[32];
    xmlSetProp(node, (xmlChar*)"trials", itoxmlchar(trials, tmp_str_buf, sizeof(tmp_str_buf)));
    xmlSetProp(node, (xmlChar*)"TestWritePerformance", (xmlChar*)"1");

    *out_xml = NULL;
    *out_xml_size = 0;
    xmlDocDumpMemory(node->doc, out_xml, out_xml_size);
    xmlFreeDoc(node->doc);
    return (*out_xml != NULL)? 0 : -1;
}


static int create_patch_xml(u_char *byte_offset,
                            u_char *physical_partition_number,
                            u_char *size_in_bytes,
                            u_char *start_sector,
                            u_char *value,
                            u_char *what,
                            uint8_t **out_xml,
                            int *out_xml_size)
{
    xmlNodePtr node = create_firehose_xml_command((xmlChar*)"patch");
    if (!node) {
        return -1;
    }

    xmlChar tmp_str_buf[32];
    xmlSetProp(node, firehoseAttrPatchSectorSizeInBytes, itoxmlchar(FIREHOSE_SECTOR_SIZE, tmp_str_buf, sizeof(tmp_str_buf)));
    xmlSetProp(node, firehoseAttrPatchByteOffset, byte_offset);
    xmlSetProp(node, firehoseAttrPatchFilename, (xmlChar*)"DISK"); // this should always say DISK
    xmlSetProp(node, firehoseAttrPatchPhysicalPartitionNum, physical_partition_number);
    xmlSetProp(node, firehoseAttrPatchSizeInBytes, size_in_bytes);
    xmlSetProp(node, firehoseAttrPatchStartSector, start_sector);
    xmlSetProp(node, firehoseAttrPatchValue, value);
    xmlSetProp(node, firehoseAttrPatchWhat, what);

    *out_xml = NULL;
    *out_xml_size = 0;
    xmlDocDumpMemory(node->doc, out_xml, out_xml_size);
    xmlFreeDoc(node->doc);
    return (*out_xml != NULL)? 0 : -1;
}


static int create_getsha256digest_xml(int num_partition_sectors,
                                      u_char *start_sector,
                                      u_char *physical_partition_number,
                                      uint8_t **out_xml,
                                      int *out_xml_size)
{
    xmlNodePtr node = create_firehose_xml_command((xmlChar*)"getsha256digest");
    if (!node) {
        return -1;
    }

    xmlChar tmp_str_buf[32];

    // <getsha256digest> uses almost all the same parameters as <program>
    xmlSetProp(node, firehoseAttrProgSectorSizeInBytes, itoxmlchar(FIREHOSE_SECTOR_SIZE, tmp_str_buf, sizeof(tmp_str_buf)));
    xmlSetProp(node, firehoseAttrProgNumPartitionSectors, itoxmlchar(num_partition_sectors, tmp_str_buf, sizeof(tmp_str_buf)));
    xmlSetProp(node, firehoseAttrProgStartSector, start_sector);
    xmlSetProp(node, firehoseAttrProgPhysicalPartitionNum, physical_partition_number);

    *out_xml = NULL;
    *out_xml_size = 0;
    xmlDocDumpMemory(node->doc, out_xml, out_xml_size);
    xmlFreeDoc(node->doc);
    return (*out_xml != NULL)? 0 : -1;
}


static int create_program_xml(int num_partition_sectors,
                              u_char *start_sector,
                              u_char *physical_partition_number,
                              int read_back_verify,
                              uint8_t **out_xml,
                              int *out_xml_size)
{
    xmlNodePtr node = create_firehose_xml_command((xmlChar*)"program");
    if (!node) {
        return -1;
    }

    xmlChar tmp_str_buf[32];

    xmlSetProp(node, firehoseAttrProgSectorSizeInBytes, itoxmlchar(FIREHOSE_SECTOR_SIZE, tmp_str_buf, sizeof(tmp_str_buf)));
    xmlSetProp(node, firehoseAttrProgNumPartitionSectors, itoxmlchar(num_partition_sectors, tmp_str_buf, sizeof(tmp_str_buf)));
    xmlSetProp(node, firehoseAttrProgStartSector, start_sector);
    xmlSetProp(node, firehoseAttrProgPhysicalPartitionNum, physical_partition_number);
    xmlSetProp(node, firehoseAttrProgReadBackVerify, itoxmlchar(read_back_verify, tmp_str_buf, sizeof(tmp_str_buf)));

    *out_xml = NULL;
    *out_xml_size = 0;
    xmlDocDumpMemory(node->doc, out_xml, out_xml_size);
    xmlFreeDoc(node->doc);
    return (*out_xml != NULL)? 0 : -1;
}


static int create_erase_xml(int storagedrive, uint8_t **out_xml, int *out_xml_size)
{
    xmlNodePtr node = create_firehose_xml_command((xmlChar*)"erase");
    if (!node) {
        return -1;
    }

    xmlChar tmp_str_buf[32];

    xmlSetProp(node, firehoseAttrEraseStorageDrive, itoxmlchar(storagedrive, tmp_str_buf, sizeof(tmp_str_buf)));

    *out_xml = NULL;
    *out_xml_size = 0;
    xmlDocDumpMemory(node->doc, out_xml, out_xml_size);
    xmlFreeDoc(node->doc);
    return (*out_xml != NULL)? 0 : -1;
}


static int create_getstorageinfo_xml(int partition_num, uint8_t **out_xml, int *out_xml_size)
{
    xmlNodePtr node = create_firehose_xml_command((xmlChar*)"getstorageinfo");
    if (!node) {
        return -1;
    }

    xmlChar tmp_str_buf[32];

    xmlSetProp(node, firehoseAttrGetStorageInfoPhysicalPartitionNum, itoxmlchar(partition_num, tmp_str_buf, sizeof(tmp_str_buf)));

    *out_xml = NULL;
    *out_xml_size = 0;
    xmlDocDumpMemory(node->doc, out_xml, out_xml_size);
    xmlFreeDoc(node->doc);
    return (*out_xml != NULL)? 0 : -1;
}


static int create_peek_xml(uint64_t address64, size_t size_in_bytes, uint8_t **out_xml, int *out_xml_size)
{
    xmlNodePtr node = create_firehose_xml_command((xmlChar*)"peek");
    if (!node) {
        return -1;
    }

    xmlChar tmp_addr64_buf[32];
    xmlChar tmp_size_buf[32];
    snprintf((char*)&tmp_addr64_buf, sizeof(tmp_addr64_buf), "0x%"PRIx64, address64);
    snprintf((char*)&tmp_size_buf, sizeof(tmp_size_buf), "%zu", size_in_bytes);

    xmlSetProp(node, firehoseAttrPeekPokeAddress64, tmp_addr64_buf);
    xmlSetProp(node, firehoseAttrPeekPokeSizeInBytes, tmp_size_buf);

    *out_xml = NULL;
    *out_xml_size = 0;
    xmlDocDumpMemory(node->doc, out_xml, out_xml_size);
    xmlFreeDoc(node->doc);
    return (*out_xml != NULL)? 0 : -1;
}


static int create_poke_xml(uint64_t address64, size_t size_in_bytes, uint64_t value, uint8_t **out_xml, int *out_xml_size)
{
    xmlNodePtr node = create_firehose_xml_command((xmlChar*)"poke");
    if (!node) {
        return -1;
    }

    xmlChar tmp_addr64_buf[32];
    xmlChar tmp_size_buf[32];
    xmlChar tmp_value_buf[32];

    snprintf((char*)&tmp_addr64_buf, sizeof(tmp_addr64_buf), "0x%"PRIx64, address64);
    snprintf((char*)&tmp_size_buf, sizeof(tmp_size_buf), "%zu", size_in_bytes);
    snprintf((char*)&tmp_value_buf, sizeof(tmp_value_buf), "0x%"PRIx64, value);

    xmlSetProp(node, firehoseAttrPeekPokeAddress64, tmp_addr64_buf);
    xmlSetProp(node, firehoseAttrPeekPokeSizeInBytes, tmp_size_buf);
    xmlSetProp(node, firehoseAttrPeekPokeValue, tmp_value_buf);

    *out_xml = NULL;
    *out_xml_size = 0;
    xmlDocDumpMemory(node->doc, out_xml, out_xml_size);
    xmlFreeDoc(node->doc);
    return (*out_xml != NULL)? 0 : -1;
}


static int create_rpmb_erase_xml(uint8_t **out_xml, int *out_xml_size)
{
    xmlNodePtr node = create_firehose_xml_command((xmlChar*)"rpmbErase");
    if (!node) {
        return -1;
    }

    *out_xml = NULL;
    *out_xml_size = 0;
    xmlDocDumpMemory(node->doc, out_xml, out_xml_size);
    xmlFreeDoc(node->doc);
    return (*out_xml != NULL)? 0 : -1;
}


static int create_setbootablestoragedrive_xml(int value, uint8_t **out_xml, int *out_xml_size)
{
    xmlNodePtr node = create_firehose_xml_command((xmlChar*)"setbootablestoragedrive");
    if (!node) {
        return -1;
    }

    xmlChar tmp_str_buf[32];

    xmlSetProp(node, (xmlChar*)"value", itoxmlchar(value, tmp_str_buf, sizeof(tmp_str_buf)));

    *out_xml = NULL;
    *out_xml_size = 0;
    xmlDocDumpMemory(node->doc, out_xml, out_xml_size);
    xmlFreeDoc(node->doc);
    return (*out_xml != NULL)? 0 : -1;
}


static int firehose_program_do(firehose_connection_t *conn, qcomdl_resource_package_t *package, const char *filename, u_char *program_xml, int program_xml_size)
{
    qcomdl_resource_file_t *f = qcomdl_fopen(package, package->img_dir, filename, "rb");
    if (!f) {
        qcomdl_log_error("unable to open %s - %s\n", filename, strerror(errno));
        return -1;
    }

    if (!conn) {
        qcomdl_log_error("NULL conn argument\n");
        return -1;
    }

    xmlNodePtr response = NULL;
    firehose_request_context_t *req = send_xml_request(conn, (char*)program_xml, program_xml_size, &response);
    int ret = 0;

    if (req->ack_state == FIREHOSE_ACK_STATE_ACK) {
        xmlChar *rawmode = xmlGetProp(response, (u_char*)"rawmode");
        if ((!response) || (strcmp((char*)rawmode, "true") != 0)) {
            qcomdl_log_error("received ack, but target does not appear to have entered rawmode\n");
            ret = -1;
        }
        xmlFree(rawmode);
    } else {
        ret = -1;
    }

    free_request(req);

    if (ret != 0) {
        qcomdl_log_error("program command failed\n");
        qcomdl_fclose(f);
        return ret;
    }

    req = send_raw_chunked_file(conn, package, filename, f);
    qcomdl_fclose(f);

    ret = (req && req->ack_state == FIREHOSE_ACK_STATE_ACK) ? 0 : -1;
    free_request(req);
    return ret;
}


static void print_xml_node(xmlNodePtr node)
{
    xmlBufferPtr buf = xmlBufferCreate();
    xmlNodeDump(buf, node->doc, node, 0, 0);
    fprintf(qcomdl_log_get_output(), "%s\n", buf->content);
    xmlBufferFree(buf);
}


static int firehose_vip_do(firehose_connection_t *conn, qcomdl_resource_package_t *package, xmlNodePtr messages)
{
    int max_msg_size = conn->cfg.MaxPayloadSizeToTargetInBytes;
    uint8_t *message_buffer = malloc((size_t)max_msg_size);
    if (!message_buffer) {
        qcomdl_log_error("malloc - %s\n", strerror(errno));
        return -1;
    }

    int ret = 0;

    for (xmlNodePtr cur = messages->children; cur; cur = cur->next) {
        bool is_program_message = false;

        if (strcmp((const char*)cur->name, "message") == 0) {
            is_program_message = false;
        } else if (strcmp((const char*)cur->name, "program_message") == 0) {
            is_program_message = true;
        } else {
            continue;
        }

        xmlChar *msg_hex = xmlNodeGetContent(cur);
        int msg_len = unhex(msg_hex, message_buffer, max_msg_size);
        free(msg_hex);
        if (msg_len < 0) {
            ret = -1;
            break;
        }

        // null terminate just for printf'ing/debugging the xml elsewhere
        if (msg_len < max_msg_size) {
            message_buffer[msg_len] = 0;
        }

        if (is_program_message) {
            xmlChar *filename = xmlGetProp(cur, (xmlChar *)"filename");
            if (!filename) {
                qcomdl_log_error("Encountered program_message without a filename\n");
                ret = -1;
                break;
            }

            qcomdl_log_debug("VIP Sending raw program message for filename: %s\n", filename);
            ret = firehose_program_do(conn, package, (char *)filename, message_buffer, msg_len);
            if (ret != 0) {
                qcomdl_log_error("program command failed for filename: %s\n", filename);
                xmlFree(filename);
                break;
            }
            xmlFree(filename);
        } else {
            qcomdl_log_debug("VIP Sending raw message\n");
            ret = firehose_send_command(conn, message_buffer, msg_len);
            if (ret != 0) {
                qcomdl_log_error("received NAK for message: %s", message_buffer);
                break;
            }
        }
    }

    free(message_buffer);

    return ret;
}


static int send_digest_table(firehose_connection_t *conn, qcomdl_resource_package_t *package, const char *digest_table_path)
{
    uint64_t size;

    int ret = qcomdl_resource_package_get_size(package, package->img_dir, digest_table_path, &size);
    if (ret != 0) {
        qcomdl_log_perror(digest_table_path);
        return -1;
    }

    if (size < (off_t)sizeof(struct mbn40_header)) {
        qcomdl_log_error("digest table file is too small to be an MBN");
        return -1;
    }

    size_t digest_table_size = (size_t)size;
    if (digest_table_size > (size_t)conn->cfg.MaxDigestTableSizeInBytes) {
        qcomdl_log_error("digest table file size exceeds max - %s: %zu > max: %i\n", digest_table_path, digest_table_size, conn->cfg.MaxDigestTableSizeInBytes);
        return -1;
    }

    uint8_t *digest_table_data = malloc(digest_table_size);
    if (!digest_table_data) {
        qcomdl_log_perror("malloc");
        return -1;
    }

    qcomdl_resource_file_t * digest_table_file = qcomdl_fopen(package, package->img_dir, digest_table_path, "rb");
    if (!digest_table_file) {
        qcomdl_log_perror(digest_table_path);
        free(digest_table_data);
        return -1;
    }

    size_t bytesread = 0;
    while ((bytesread < digest_table_size) && (!qcomdl_feof(digest_table_file)) && (!qcomdl_ferror(digest_table_file))) {
        bytesread += qcomdl_fread(digest_table_data+bytesread, 1, (digest_table_size-bytesread), digest_table_file);
    }
    qcomdl_fclose(digest_table_file);

    if (bytesread != digest_table_size) {
        qcomdl_log_error("Size error reading %s - read %zu of %zu bytes\n", digest_table_path, bytesread, digest_table_size);
        free(digest_table_data);
        return -1;
    }

    struct mbn40_header *mbn = (void*) digest_table_data;
    size_t num_mbn_digests = mbn->code_size / FIREHOSE_DIGEST_SIZE;

    qcomdl_log_info("Sending digest table file (%zu bytes): %s\n", bytesread, digest_table_path);
    conn->vip_enabled = false;
    firehose_request_context_t *req_ctx = send_acked_request(conn, (char*)digest_table_data, (int)bytesread, NULL);
    free(digest_table_data);
    conn->vip_enabled = true;

    ret = ((!req_ctx->error) && (req_ctx->ack_state == FIREHOSE_ACK_STATE_ACK)) ? 0 : -1;

    free_request(req_ctx);

    if (ret == 0) {
        qcomdl_log_info("Loaded %zu message digests from mbn digest table\n", num_mbn_digests);
        conn->vip_digests_chunk_left = num_mbn_digests;
    }

    return ret;
}


static int verify_table_digest(sha256_digest digest, firehose_verify_vip_ctx_t *ctx)
{
    off_t orig_pos = qcomdl_ftello(ctx->chained_digests);

    qcomdl_log_debug("Verifying chained digest table at offset 0x%zx\n", (size_t)orig_pos);

    uint8_t table_chunk[ctx->max_digest_table_count * SHA256_DIGEST_LENGTH];
    memset(table_chunk, 0, sizeof(table_chunk));
    size_t num_read = qcomdl_fread(table_chunk, SHA256_DIGEST_LENGTH, ctx->max_digest_table_count, ctx->chained_digests);
    if (num_read == 0) {
        qcomdl_log_error("unable to read chained digest table chunk at offset: 0x%zx\n", (size_t)orig_pos);
        return -1;
    }

    sha256_digest chunk_digest;
    sha256(chunk_digest, table_chunk, (num_read * SHA256_DIGEST_LENGTH));

    if (memcmp(digest, chunk_digest, SHA256_DIGEST_LENGTH) != 0) {
        uint8_t pr_chunk_sha[SHA256_DIGEST_STRING_LENGTH + 1];
        pr_chunk_sha[SHA256_DIGEST_STRING_LENGTH] = 0;
        uint8_t pr_digest_sha[SHA256_DIGEST_STRING_LENGTH + 1];
        pr_digest_sha[SHA256_DIGEST_STRING_LENGTH] = 0;

        hex(chunk_digest, SHA256_DIGEST_LENGTH, pr_chunk_sha, sizeof(pr_chunk_sha));
        hex(digest, SHA256_DIGEST_LENGTH, pr_digest_sha, sizeof(pr_digest_sha));

        qcomdl_log_error("invalid table digest for chained digest table chunk at offset: 0x%zx\n"
                         "  (message) %s\n"
                         "  (expect)  %s\n",
                         (size_t)orig_pos,
                         pr_chunk_sha,
                         pr_digest_sha);
        return -1;
    }

    if (qcomdl_fseeko(ctx->chained_digests, orig_pos, SEEK_SET) != 0) {
        qcomdl_log_error("unable to seek to chained digest file offset: 0x%zx - %s\n", (size_t)orig_pos, strerror(errno));
        return -1;
    }

    return 0;
}


/*
 * Used during vip verification to get digests to validate messages and
 * file payloads.
 * Returns the next digest in the digest chain, automatically detecting and
 * verifying the next digest table chunk when the end of the preceding
 * chunk is reached and (assuming it is valid) returning the next message
 * digest.
 *
 * See Qualcomm Firehose Protocol doc. 80-NG319-1 for more information.
 */
static int get_next_digest(firehose_verify_vip_ctx_t *ctx)
{
    memset(ctx->cur_digest, 0, sizeof(ctx->cur_digest));
    if (ctx->num_digests_consumed < ctx->num_mbn_digests) {
        if (qcomdl_fread(ctx->cur_digest, sizeof(ctx->cur_digest), 1, ctx->mbn_digests) != 1) {
            qcomdl_log_error("unable to read MBN digest table digest at index %zu\n",
                            ctx->num_digests_consumed);
            return -1;
        }
        ctx->num_digests_consumed++;

    } else if (ctx->chained_digests) {
        if (ctx->num_digests_consumed == (FIREHOSE_MAX_MBN_DIGESTS - 1)) {
            sha256_digest mbn_table_digest;
            if (qcomdl_fread(mbn_table_digest, sizeof(mbn_table_digest), 1, ctx->mbn_digests) != 1) {
                qcomdl_log_error("unable to read MBN digest table digest at index %zu\n", ctx->num_digests_consumed);
                return -1;
            }
            ctx->num_digests_consumed++;

            if (verify_table_digest(mbn_table_digest, ctx) != 0) {
                return -1;
            }
        }

        if (qcomdl_fread(ctx->cur_digest, sizeof(ctx->cur_digest), 1, ctx->chained_digests) != 1) {
            qcomdl_log_error("unable to read chained digest at index %zu\n",
                            ctx->num_digests_consumed);
            return -1;
        }
        ctx->num_digests_consumed++;

        size_t chain_consumed = ctx->num_digests_consumed - FIREHOSE_MAX_MBN_DIGESTS;
        if ((chain_consumed != 0) && ((chain_consumed % ctx->max_digest_table_count) == 0)) {

            if (verify_table_digest(ctx->cur_digest, ctx) != 0) {
                return -1;
            }

            if (qcomdl_fread(ctx->cur_digest, sizeof(ctx->cur_digest), 1, ctx->chained_digests) != 1) {
                qcomdl_log_error("unable to read chained digest at index %zu\n", ctx->num_digests_consumed);
                return -1;
            }
            ctx->num_digests_consumed++;
        }
    } else {
        qcomdl_log_error("MBN digests have been depleted but there are no chained digests\n");
        return -1;
    }

    return 0;
}


#pragma mark Public Functions

firehose_connection_t *firehose_connect(edl_connection_t *edl_conn)
{
    if (!edl_conn) {
        qcomdl_log_error("%s called with a NULL EDL connection\n", __func__);
        return NULL;
    }

    firehose_connection_t *conn = calloc(1, sizeof(firehose_connection_t));
    if (conn) {
        conn->usb_dev = edl_conn->usb_dev;

        conn->cfg.timeout = FIREHOSE_DEFAULT_TRANSFER_TIMEOUT_MSEC;
        conn->cfg.tries = 0;

        conn->cfg.MaxPayloadSizeToTargetInBytes = FIREHOSE_DEFAULT_PAYLOAD_SIZE;
        conn->cfg.ZlpAwareHost = 1;

        conn->cfg.AckRawDataEveryNumPackets = -1;
        conn->cfg.AlwaysValidate = -1;
        conn->cfg.MaxDigestTableSizeInBytes = FIREHOSE_DEFAULT_DIGEST_TABLE_SIZE;
        conn->cfg.MaxPayloadSizeFromTargetInBytes = -1;
        conn->cfg.MaxPayloadSizeToTargetInBytesSupported = -1;
        conn->cfg.MaxXMLSizeInBytes = -1;
        conn->cfg.MinVersionSupported = -1;
        conn->cfg.SkipStorageInit = -1;
        conn->cfg.SkipWrite = -1;
        conn->cfg.Verbose = -1;
        conn->cfg.Version = -1;

        conn->cfg.MemoryName = NULL;
        conn->cfg.TargetName = NULL;

        conn->memory_name = NULL;
        conn->target_name = NULL;

        conn->vip_enabled = false;
        conn->vip_chained_digests_file = NULL;
        conn->vip_digests_chunk_left = 0;
        conn->vip_total_packet_count = 0;

        memset(&conn->file_progress_handlers, 0, sizeof(conn->file_progress_handlers));
        conn->file_progress_ctx = NULL;

        memset(&conn->percent_progress_handlers, 0, sizeof(conn->percent_progress_handlers));
        conn->percent_progress_ctx = NULL;
    }
    return conn;
}


void firehose_connection_free(firehose_connection_t *conn)
{
    if (conn) {
        free(conn->memory_name);
        free(conn->target_name);
    }
    free(conn);
}


int firehose_send_command(firehose_connection_t *conn, uint8_t *xml, int xml_size)
{
    if (!conn) {
        qcomdl_log_error("NULL conn argument\n");
        return -1;
    }

    firehose_request_context_t *req = send_xml_request(conn, (char*)xml, xml_size, NULL);
    int ret = ((req) && (req->ack_state == FIREHOSE_ACK_STATE_ACK)) ? 0 : -1;
    free_request(req);
    return ret;
}


int firehose_ping(firehose_connection_t *conn)
{
    qcomdl_log_info("Sending ping\n");
    uint8_t *ping_request = (uint8_t*)"<?xml version=\"1.0\" ?><data><nop value=\"ping\" /></data>";
    return firehose_send_command(conn, ping_request, (int)strlen((char*)ping_request));
}


int firehose_configure(firehose_connection_t *conn)
{
    if (!conn) {
        qcomdl_log_error("NULL conn argument\n");
        return -1;
    }

    int max_payload_size_proposed = conn->cfg.MaxPayloadSizeToTargetInBytes;
    conn->cfg.tries++;

    qcomdl_log_info("Negotiating configuration with target. Proposed MaxPayloadSizeToTargetInBytes=%i\n", max_payload_size_proposed);

    xmlChar *xml = NULL;
    int xml_size = 0;
    int r = create_config_xml(&conn->cfg, &xml, &xml_size);
    if (r != 0) {
        qcomdl_log_error("cannot create config xml\n");
        return -1;
    }

    xmlNodePtr response_node = NULL;

    firehose_request_context_t *req = send_xml_request(conn, (char*)xml, xml_size, &response_node);
    free(xml);

    if (!req) {
        qcomdl_log_error("configuration request failed\n");
        return -1;
    }

    int ack_state = req->ack_state;

    int cfg_ret = (response_node) ? handle_config_response(response_node, conn) : -1;
    free_request(req);

    if (cfg_ret != 0) {
        qcomdl_log_error("failed to handle the configuration response from the target\n");
        return -1;
    }

    if (ack_state == FIREHOSE_ACK_STATE_NAK && conn->cfg.tries < FIREHOSE_MAX_CONFIG_TRIES) {
        qcomdl_log_debug("Target replied to our configuration with NACK. Retrying with adjusted payload size\n");
        // The handler should have already recorded the target's supported payload size, so we don't need to adjust it here
        return firehose_configure(conn);
    }

    if ((ack_state == FIREHOSE_ACK_STATE_ACK) &&
        (conn->cfg.MaxPayloadSizeToTargetInBytesSupported > max_payload_size_proposed) &&
        (conn->cfg.tries < FIREHOSE_MAX_CONFIG_TRIES))
    {
        qcomdl_log_debug("Attempting to re-configure using target's max supported payload size\n");
        conn->cfg.MaxPayloadSizeToTargetInBytes = conn->cfg.MaxPayloadSizeToTargetInBytesSupported;
        return firehose_configure(conn);
    }

    if (ack_state == FIREHOSE_ACK_STATE_ACK) {
        qcomdl_log_info("Successfully negotiated configuration with target. MaxPayloadSizeToTargetInBytes=%i\n", conn->cfg.MaxPayloadSizeToTargetInBytes);
        return 0;
    } else {
        qcomdl_log_error("unable to negotiate a supported configuration. ack_state=%i\n", ack_state);
        return -1;
    }
}


int firehose_setbootablestoragedrive(firehose_connection_t *conn, int value)
{
    qcomdl_log_info("Sending setbootablestoragedrive command: value=%i\n", value);

    uint8_t *xml = NULL;
    int xml_size = 0;
    if (create_setbootablestoragedrive_xml(value, &xml, &xml_size) != 0) {
        qcomdl_log_error("cannot create setbootablestoragedrive xml command\n");
        return -1;
    }

    int ret = firehose_send_command(conn, xml, xml_size);
    free(xml);
    return ret;
}


int firehose_erase(firehose_connection_t *conn, int storagedrive)
{
    qcomdl_log_info("Sending erase command: StorageDrive=%i\n", storagedrive);

    uint8_t *xml = NULL;
    int xml_size = 0;
    if (create_erase_xml(storagedrive, &xml, &xml_size) != 0) {
        qcomdl_log_error("cannot create erase xml command\n");
        return -1;
    }

    int ret = firehose_send_command(conn, xml, xml_size);
    free(xml);
    return ret;
}


int firehose_rpmb_erase(firehose_connection_t *conn)
{
    qcomdl_log_info("Sending RPMB erase command\n");

    uint8_t *xml = NULL;
    int xml_size = 0;

    if (create_rpmb_erase_xml(&xml, &xml_size) != 0) {
        qcomdl_log_error("cannot create RPMB erase xml command\n");
        return -1;
    }

    int ret = firehose_send_command(conn, xml, xml_size);
    free(xml);
    return ret;
}


int firehose_getstorageinfo(firehose_connection_t *conn, int partition_num)
{
    qcomdl_log_info("Sending getstorageinfo command: physical_partition_number=%i\n", partition_num);

    uint8_t *xml = NULL;
    int xml_size = 0;
    if (create_getstorageinfo_xml(partition_num, &xml, &xml_size) != 0) {
        qcomdl_log_error("cannot create getstorageinfo xml command\n");
        return -1;
    }

    int ret = firehose_send_command(conn, xml, xml_size);
    free(xml);
    return ret;
}


int firehose_peek(firehose_connection_t *conn, uint64_t address64, size_t size_in_bytes)
{
    qcomdl_log_info("Sending peek command: address64=0x%"PRIx64" size_in_bytes=%zu\n", address64, size_in_bytes);

    uint8_t *xml = NULL;
    int xml_size = 0;
    if (create_peek_xml(address64, size_in_bytes, &xml, &xml_size) != 0) {
        qcomdl_log_error("cannot create peek xml command\n");
        return -1;
    }

    int ret = firehose_send_command(conn, xml, xml_size);
    free(xml);
    return ret;
}


int firehose_poke(firehose_connection_t *conn, uint64_t addr64, size_t size_in_bytes, uint64_t value)
{
    qcomdl_log_info("Sending poke command: address64=0x%"PRIx64" size_in_bytes=%zu, value=0x%"PRIx64"\n", addr64, size_in_bytes, value);

    uint8_t *xml = NULL;
    int xml_size = 0;
    if (create_poke_xml(addr64, size_in_bytes, value, &xml, &xml_size) != 0) {
        qcomdl_log_error("cannot create poke xml command\n");
        return -1;
    }

    int ret = firehose_send_command(conn, xml, xml_size);
    free(xml);
    return ret;
}


int firehose_power(firehose_connection_t *conn, char *value, int delay_secs)
{
    qcomdl_log_info("Sending power command: value=%s DelayInSeconds=%i\n", value, delay_secs);

    uint8_t *xml = NULL;
    int xml_size = 0;
    if (create_power_xml(value, delay_secs, &xml, &xml_size) != 0) {
        qcomdl_log_error("cannot create power xml command\n");
        return -1;
    }

    int ret = firehose_send_command(conn, xml, xml_size);
    free(xml);
    return ret;
}


int firehose_benchmark(firehose_connection_t *conn, int trials, unsigned int timeout_msec)
{

    qcomdl_log_info("Sending benchmark command with %i trials\n", trials);

    uint8_t *xml = NULL;
    int xml_size = 0;
    if (create_benchmark_xml(trials, &xml, &xml_size) != 0) {
        qcomdl_log_error("cannot create benchmark xml command\n");
        return -1;
    }

    if (!conn) {
        qcomdl_log_error("NULL conn argument\n");
        return -1;
    }
    unsigned int orig_timeout = conn->cfg.timeout;
    conn->cfg.timeout = timeout_msec;
    int ret = firehose_send_command(conn, xml, xml_size);
    conn->cfg.timeout = orig_timeout;
    free(xml);
    return ret;
}


int firehose_patch(firehose_connection_t *conn,
                   u_char *byte_offset,
                   u_char *physical_partition_number,
                   u_char *size_in_bytes,
                   u_char *start_sector,
                   u_char *value,
                   u_char *what)
{
    qcomdl_log_info("Sending patch command: %s\n", what);

    uint8_t *xml = NULL;
    int xml_size = 0;
    int r = create_patch_xml(byte_offset,
                             physical_partition_number,
                             size_in_bytes,
                             start_sector,
                             value,
                             what,
                             &xml,
                             &xml_size);
    if (r != 0) {
        qcomdl_log_error("cannot create benchmark xml command\n");
        return -1;
    }

    int ret = firehose_send_command(conn, xml, xml_size);
    free(xml);
    return ret;
}


int firehose_program(firehose_connection_t *conn,
                     qcomdl_resource_package_t *package,
                     const char *filename,
                     u_char *start_sector,
                     u_char *physical_partition_number,
                     int read_back_verify)
{
    ssize_t num_sectors = file_sector_count(package, filename);
    if (num_sectors < 0) {
        qcomdl_log_error("cannot stat %s - %s\n", filename, strerror(errno));
        return -1;
    }

    qcomdl_log_info("Sending program command with %d sectors at start_sector=%s on partition=%s for filename: %s\n",
               (int)num_sectors, start_sector, physical_partition_number, filename);

    uint8_t *xml = NULL;
    int xml_size = 0;
    int r = create_program_xml((int)num_sectors, start_sector, physical_partition_number, read_back_verify, &xml, &xml_size);
    if (r != 0) {
        qcomdl_log_error("cannot create program xml command\n");
        return -1;
    }

    int ret = firehose_program_do(conn, package, filename, xml, xml_size);
    free(xml);

    return ret;
}


int firehose_getsha256digest(firehose_connection_t *conn,
                             int num_partition_sectors,
                             u_char *start_sector,
                             u_char *physical_partition_number)
{
    qcomdl_log_info("Sending getsha256digest command\n");

    uint8_t *xml = NULL;
    int xml_size = 0;
    int r = create_getsha256digest_xml(num_partition_sectors, start_sector, physical_partition_number, &xml, &xml_size);
    if (r != 0) {
        qcomdl_log_error("cannot create getsha256digest xml command\n");
        return -1;
    }

    int ret = firehose_send_command(conn, xml, xml_size);
    free(xml);
    return ret;
}

static int read_file_to_buffer(qcomdl_resource_package_t *package, const char *path, char **buffer, int *size) {
    size_t read;

    qcomdl_resource_file_t *resource = qcomdl_fopen(package, package->img_dir, path, "r");
    if (!resource) {
        return -1;
    }

    *buffer = malloc(resource->size);
    if (!*buffer) {
        qcomdl_fclose(resource);
        return -1;
    }

    read = qcomdl_fread((void *)*buffer, 1, resource->size, resource);
    if (read != resource->size) {
        // this wouldn't normally be an error, but since we're trying to read the entire file
        // we should treat a short read as an error.
        fprintf(stderr, "%s: short read, %d != %"PRIu64"\n", __FUNCTION__, *size, resource->size);
        free(*buffer);
        *buffer = NULL;
        qcomdl_fclose(resource);
        return -1;
    }

    *size = (int)read;
    qcomdl_fclose(resource);
    return 0;
}

static int firehose_program_file_iter(firehose_connection_t *conn,
                                      qcomdl_resource_package_t *package,
                                      const char *program_xml_path,
                                      int (*iter_func)(firehose_connection_t *conn, qcomdl_resource_package_t *package, const char *full_path, u_char *start_sector, u_char *phys_part_num, void *arg_info),
                                      void *arg_info)
{
    char *xmlData = NULL;
    int len;
    int ret;

    ret = read_file_to_buffer(package, program_xml_path, &xmlData, &len);
    if (ret != 0) {
        qcomdl_log_error("could not read data from %s\n", program_xml_path);
        return -1;
    }

    xmlDocPtr doc = xmlReadMemory(xmlData, len, NULL, NULL, 0);
    free(xmlData);

    if (!doc) {
        qcomdl_log_error("cannot parse %s - %s\n", program_xml_path, get_xml_error());
        return -1;
    }

    xmlNodePtr data = xmlDocGetRootElement(doc);
    if (!data || strcmp((const char*)data->name, "data") != 0) {
        qcomdl_log_error("parse error, missing <data> node in %s\n", program_xml_path);
        xmlFreeDoc(doc);
        return -1;
    }

    size_t count = 0;
    size_t node_count = 0;
    bool error = false;

    for (xmlNodePtr cur = data->children; cur; cur = cur->next) {
        if (strcmp((const char*)cur->name, "program") != 0) {
            continue;
        }

        node_count++;
        xmlChar *filename = xmlGetProp(cur, (xmlChar*)"filename");

        if ((!filename) || strlen((char*)filename) == 0) {
            // skip blank filenames
            xmlFree(filename);
            continue;
        }

        count++;

        xmlChar *start_sector = xmlGetProp(cur, firehoseAttrProgStartSector);
        xmlChar *phys_partition_num = xmlGetProp(cur, firehoseAttrProgPhysicalPartitionNum);
        xmlChar *label = xmlGetProp(cur, firehoseAttrProgLabel);

        qcomdl_log_debug("processing <program> command for %s (%s)\n", filename, label);
        int r = iter_func(conn, package, (char *)filename, start_sector, phys_partition_num, arg_info);

        xmlFree(filename);
        xmlFree(start_sector);
        xmlFree(phys_partition_num);
        xmlFree(label);

        if (r != 0) {
            qcomdl_log_error("encountered an error processing program command #%zu\n", node_count);
            print_xml_node(cur);
            error = true;
            break;
        }
    }

    xmlFreeDoc(doc);

    if (error) {
        qcomdl_log_error("processing <program> command loop terminated early\n");
        return -1;
    } else {
        return 0;
    }
}


static int firehose_program_file_iter_program(firehose_connection_t *conn, qcomdl_resource_package_t *package, const char *full_path, u_char *start_sector, u_char *phys_part_num, void *arg_info)
{
    int read_back_verify = *(int*)arg_info;
    return firehose_program(conn, package, full_path, start_sector, phys_part_num, read_back_verify);
}


int firehose_program_from_file(firehose_connection_t *conn, qcomdl_resource_package_t *package, const char *program_xml_path, int read_back_verify)
{
    return firehose_program_file_iter(conn, package, program_xml_path, firehose_program_file_iter_program, &read_back_verify);
}


static int firehose_program_file_iter_getsha256digest(firehose_connection_t *conn, qcomdl_resource_package_t *package, const char *full_path, u_char *start_sector, u_char *phys_part_num, void *arg_info)
{
    (void)arg_info;
    ssize_t num_sectors = file_sector_count(package, full_path);

    if (num_sectors < 0) {
        return -1;
    }

    return firehose_getsha256digest(conn, (int)num_sectors, start_sector, phys_part_num);
}


static int firehose_program_file_iter_total_image_sector_count(firehose_connection_t *conn, qcomdl_resource_package_t *package, const char *full_path, u_char *start_sector, u_char *phys_part_num, void *arg_info)
{
    ssize_t count = file_sector_count(package, full_path);
    if (count < 0) {
        return -1;
    }
    ssize_t *total_count = arg_info;
    *total_count += count;
    return 0;
}


int firehose_getsha256digests_from_file(firehose_connection_t *conn, qcomdl_resource_package_t *package, const char *program_xml_path)
{
    return firehose_program_file_iter(conn, package, program_xml_path, firehose_program_file_iter_getsha256digest, NULL);
}


int firehose_patch_from_file(firehose_connection_t *conn, qcomdl_resource_package_t *package, const char *patch_xml_path)
{
    char *xmlData = NULL;
    int len;
    int ret;

    ret = read_file_to_buffer(package, patch_xml_path, &xmlData, &len);
    if (ret != 0) {
        qcomdl_log_error("could not read data from %s\n", patch_xml_path);
        return -1;
    }

    xmlDocPtr doc = xmlReadMemory(xmlData, len, NULL, NULL, 0);
    free(xmlData);

    if (!doc) {
        qcomdl_log_error("cannot parse %s - %s\n", patch_xml_path, get_xml_error());
        return -1;
    }

    xmlNodePtr patches = xmlDocGetRootElement(doc);
    if (!patches || strcmp((const char*)patches->name, "patches") != 0) {
        qcomdl_log_error("parse error, missing <patches> node in %s\n", patch_xml_path);
        xmlFreeDoc(doc);
        return -1;
    }

    size_t node_count = 0;
    bool error = false;

    for (xmlNodePtr cur = patches->children; cur; cur = cur->next) {
        if (strcmp((const char*)cur->name, "patch") != 0) {
            continue;
        }

        node_count++;

        // skip any patch command that is not for DISK, it is for patching images on the host via other tooling...
        xmlChar *filename = xmlGetProp(cur, (xmlChar*)"filename");
        bool is_disk = ((filename != NULL) && (strcmp((char*)filename, "DISK") == 0));
        xmlFree(filename);
        if (!is_disk) {
            continue;
        }

        xmlChar *byte_offset = xmlGetProp(cur, firehoseAttrPatchByteOffset);
        xmlChar *partition_number = xmlGetProp(cur, firehoseAttrPatchPhysicalPartitionNum);
        xmlChar *size_in_bytes = xmlGetProp(cur, firehoseAttrPatchSizeInBytes);
        xmlChar *start_sector = xmlGetProp(cur, firehoseAttrPatchStartSector);
        xmlChar *value = xmlGetProp(cur, firehoseAttrPatchValue);
        xmlChar *what = xmlGetProp(cur, firehoseAttrPatchWhat);

        int r = firehose_patch(conn, byte_offset, partition_number, size_in_bytes, start_sector, value, what);

        xmlFree(byte_offset);
        xmlFree(partition_number);
        xmlFree(size_in_bytes);
        xmlFree(start_sector);
        xmlFree(value);
        xmlFree(what);

        if (r != 0) {
            qcomdl_log_error("encountered an error processing DISK patch command #%zu\n", node_count);
            print_xml_node(cur);
            error = true;
            break;
        }
    }

    xmlFreeDoc(doc);

    if (error) {
        qcomdl_log_error("patch loop terminated early\n");
        return -1;
    } else {
        return 0;
    }
}


int firehose_non_vip(firehose_connection_t *fh_conn, qcomdl_resource_package_t *package, const char *program_xml, const char *patch_xml, bool do_erase, bool read_back_verify, bool do_sha256, int reset_delay, bool do_rpmb_erase)
{
    if (!fh_conn) {
        qcomdl_log_error("Called with NULL firehose connection arguement\n");
        return -1;
    }

    if (!program_xml) {
        program_xml = FIREHOSE_DEFAULT_PROGRAM_XML_FILENAME;
    }
    if (qcomdl_resource_package_file_exists(package, package->img_dir, program_xml) != 0) {
        qcomdl_log_perror(program_xml);
        return -1;
    }

    if (!patch_xml) {
        patch_xml = FIREHOSE_DEFAULT_PATCH_XML_FILENAME;
    }
    if ((fh_conn->cfg.SkipWrite == 0) && (qcomdl_resource_package_file_exists(package, package->img_dir, patch_xml) != 0)) {
        qcomdl_log_perror(patch_xml);
        return -1;
    }

    if (firehose_ping(fh_conn) != 0) {
        return -1;
    }

    // based on QFIL captures
    fh_conn->cfg.ZlpAwareHost = 1;
    fh_conn->cfg.SkipStorageInit = 0;
    fh_conn->cfg.MemoryName = (char*)"eMMC";
    fh_conn->cfg.TargetName = (char*)"8x26";

    if (firehose_configure(fh_conn) != 0) {
        return -1;
    }

    qcomdl_log_info("Configuration completed with target. MemoryName=%s TargetName=%s\n",
                    ((fh_conn->memory_name) ? fh_conn->memory_name : "[unknown]"),
                    ((fh_conn->target_name) ? fh_conn->target_name : "[unknown]"));


    if (do_erase) {
        qcomdl_log_info("Erasing flash before sending programming commands\n");
        if (firehose_erase(fh_conn, 0) != 0) {
            qcomdl_log_error("firehose_erase failed\n");
            return -1;
        }
    }

    if (do_rpmb_erase) {
        qcomdl_log_info("Erasing RPMB flash before sending programming commands\n");
        if (firehose_rpmb_erase(fh_conn) != 0) {
            qcomdl_log_error("firehose_rpmb_erase failed\n");
            return -1;
        }
    }

    qcomdl_log(QCOMDL_LOG_LEVEL_NONE, "Flashing images from %s\n", program_xml);
    if (firehose_program_from_file(fh_conn, package, program_xml, read_back_verify) != 0) {
        qcomdl_log_error("programming failed\n");
        return -1;
    }

    if (qcomdl_log_isatty()) {
        qcomdl_log(QCOMDL_LOG_LEVEL_NONE, "\n");
    }

    if (do_sha256) {
        // Digests take a lot longer to receive a reply usb packet than
        // other requests. Set a minimum usb timeout value to ensure they
        // have time to run. Luckily, the firehose binary's sha256digest
        // routine sends periodic log messages indicating it's working
        // at roughly 5 second intervals.
        unsigned int orig_timeout = fh_conn->cfg.timeout;
        if (fh_conn->cfg.timeout < FIREHOSE_MIN_SHA256DIGEST_TIMEOUT_MSEC) {
            fh_conn->cfg.timeout = FIREHOSE_MIN_SHA256DIGEST_TIMEOUT_MSEC;
        }
        int sha_ret = firehose_getsha256digests_from_file(fh_conn, package, program_xml);
        fh_conn->cfg.timeout = orig_timeout;
        if (sha_ret != 0) {
            qcomdl_log_error("getsha256digests failed\n");
            return -1;
        }
    }

    if (fh_conn->cfg.SkipWrite) {
        qcomdl_log_info("SkipWrite=%i - disabling patch process\n", fh_conn->cfg.SkipWrite);
    } else {
        qcomdl_log(QCOMDL_LOG_LEVEL_NONE, "Applying patches from %s\n", patch_xml);
        if (firehose_patch_from_file(fh_conn, package, patch_xml) != 0) {
            qcomdl_log_error("patch failed\n");
            return -1;
        }
    }

    qcomdl_log(QCOMDL_LOG_LEVEL_NONE, "Resetting target via firehose\n");
    if (firehose_power(fh_conn, (char*)"reset", reset_delay) != 0) {
        qcomdl_log_error("unable to reset device\n");
        return -1;
    }

    return 0;
}


int firehose_vip(firehose_connection_t *conn, qcomdl_resource_package_t *package, const char *vip_xml, const char *digest_table, const char *chained_digests)
{
    if (!conn) {
        qcomdl_log_error("Called with NULL firehose connection arguement\n");
        return -1;
    }

    if (vip_xml == NULL) {
        vip_xml = FIREHOSE_DEFAULT_VIP_XML_FILENAME;
    }

    if (digest_table == NULL) {
        digest_table = FIREHOSE_DEFAULT_DIGEST_TABLE_FILENAME;
    }

    if (chained_digests == NULL) {
        chained_digests = FIREHOSE_DEFAULT_CHAINED_DIGESTS_FILENAME;
    }

    qcomdl_log(QCOMDL_LOG_LEVEL_NONE, "Applying prepared firehose commands from %s\n", vip_xml);
    char *xmlData = NULL;
    int len;
    int ret;

    ret = read_file_to_buffer(package, vip_xml, &xmlData, &len);
    if (ret != 0) {
        qcomdl_log_error("could not read data from %s\n", vip_xml);
        return -1;
    }

    xmlDocPtr doc = xmlReadMemory(xmlData, len, NULL, NULL, 0);
    free(xmlData);

    if (!doc) {
        qcomdl_log_error("cannot parse %s - %s\n", vip_xml, get_xml_error());
        return -1;
    }

    ret = -1;
    do {
        xmlNodePtr messages = xmlDocGetRootElement(doc);
        if (!messages || strcmp((const char*)messages->name, "messages") != 0) {
            qcomdl_log_error("parse error, missing <messages> node in %s\n", vip_xml);
            break;
        }

        // The payload size and digest table size can't be negotiated with the target in VIP.
        // MaxPayloadSize and MaxDigestTable size are provided in the VIP messages configuration.
        // If left unspecified in the VIP messages configuration the default values are used.
        int max_payload_size = get_prop_as_int(messages, (const xmlChar*)"max_payload_size");
        if (max_payload_size > 0) {
            conn->cfg.MaxPayloadSizeToTargetInBytes = max_payload_size;
        }

        int max_digest_table_count = get_prop_as_int(messages, (const xmlChar*)"max_digest_table_count");
        if (max_digest_table_count > 0) {
            if (max_digest_table_count > FIREHOSE_MAX_DIGEST_TABLE_COUNT) {
                qcomdl_log_error("max_digest_table_count attribute in vip xml file is too large: %i > %i\n", max_digest_table_count, FIREHOSE_MAX_DIGEST_TABLE_COUNT);
                break;
            }
            conn->cfg.MaxDigestTableSizeInBytes = (max_digest_table_count * FIREHOSE_DIGEST_SIZE);
        }

        conn->cfg.MaxPayloadSizeToTargetInBytesSupported = conn->cfg.MaxPayloadSizeToTargetInBytes;


        if (init_chained_digests(conn, package, chained_digests) != 0) {
            qcomdl_log_error("Unable to initialize chained digests file: %s\n", chained_digests);
            break;
        }

        if (send_digest_table(conn, package, digest_table) != 0) {
            qcomdl_log_error("Unable to send digest table file: %s\n", digest_table);
            break;
        }

        if ((! conn->vip_chained_digests_file) && (conn->vip_digests_chunk_left < FIREHOSE_MAX_MBN_DIGESTS)) {
            // If the mbn contains fewer than max mbn digests it means there will not be a
            // chained digests file containing the rest.
            // In this case we increment the chunks left counter so that it never runs out.
            conn->vip_digests_chunk_left++;
        }

        ret = firehose_vip_do(conn, package, messages);
    } while(0);

    conn->vip_enabled = false;
    if (conn->vip_chained_digests_file) {
        qcomdl_fclose(conn->vip_chained_digests_file);
        conn->vip_chained_digests_file = NULL;
    }
    xmlFreeDoc(doc);
    return ret;
}


int firehose_register_file_progress_handlers(firehose_connection_t *conn, const struct firehose_file_progress_api *handlers, void *ctx)
{
    if (!conn) {
        qcomdl_log_error("NULL conn argument\n");
        return -1;
    }

    conn->file_progress_ctx = ctx;

    if (handlers) {
        memcpy(&conn->file_progress_handlers, handlers, sizeof(conn->file_progress_handlers));
    } else {
        memset(&conn->file_progress_handlers, 0, sizeof(conn->file_progress_handlers));
    }

    return 0;
}


int firehose_register_percent_progress_handlers(firehose_connection_t *conn, const struct firehose_percent_progress_api *handlers, void *user_ctx)
{
    if (!conn) {
        qcomdl_log_error("NULL conn argument\n");
        return -1;
    }

    conn->percent_progress_ctx = user_ctx;

    if (handlers) {
        memcpy(&conn->percent_progress_handlers, handlers, sizeof(conn->percent_progress_handlers));
        conn->percent_progress_handlers._internal_ctx = user_ctx;
        conn->percent_progress_handlers._internal_last_percent = 0;
        conn->percent_progress_handlers._internal_total_progess_sectors = 0;
        conn->percent_progress_handlers._internal_last_file_sectors_written = 0;

        struct firehose_file_progress_api file_handlers = {
            .handle_start_sectors_from_file = wrap_percent_start_sectors_from_file,
            .handle_sent_file_sectors = wrap_percent_sent_file_sectors,
            .handle_finished_sectors_from_file = NULL,
        };
        return firehose_register_file_progress_handlers(conn, &file_handlers, &conn->percent_progress_handlers);
    } else {
        memset(&conn->percent_progress_handlers, 0, sizeof(conn->percent_progress_handlers));
        return firehose_register_file_progress_handlers(conn, NULL, NULL);
    }
}


ssize_t firehose_total_image_sectors_vip(qcomdl_resource_package_t *package, const char *vip_xml)
{
    char *xmlData = NULL;
    int len;
    int readRet;

    if (!vip_xml) {
        vip_xml = FIREHOSE_DEFAULT_VIP_XML_FILENAME;
    }

    // load XML data into buffer
    readRet = read_file_to_buffer(package, vip_xml, &xmlData, &len);
    if (readRet != 0) {
        qcomdl_log_error("could not read data from %s\n", vip_xml);
        return -1;
    }

    xmlDocPtr doc = xmlReadMemory(xmlData, len, NULL, NULL, 0);
    free(xmlData);

    if (!doc) {
        qcomdl_log_error("cannot parse %s - %s\n", vip_xml, get_xml_error());
        return -1;
    }

    xmlNodePtr messages = xmlDocGetRootElement(doc);
    if (!messages || strcmp((const char*)messages->name, "messages") != 0) {
        qcomdl_log_error("parse error, missing <messages> node in %s\n", vip_xml);
        xmlFreeDoc(doc);
        return -1;
    }

    ssize_t ret = 0;

    for (xmlNodePtr cur = messages->children; cur; cur = cur->next) {
        if (strcmp((const char*)cur->name, "program_message") != 0) {
            continue;
        }
        xmlChar *filename = xmlGetProp(cur, (xmlChar *)"filename");
        if (!filename) {
            qcomdl_log_error("Encountered program_message without a filename\n");
            ret = -1;
            break;
        }
        ssize_t count = file_sector_count(package, (char *)filename);
        xmlFree(filename);
        if (count < 0) {
            ret = -1;
            break;
        }
        ret += count;
    }

    xmlFreeDoc(doc);
    return ret;
}


ssize_t firehose_total_image_sectors_non_vip(qcomdl_resource_package_t *package, const char *program_xml)
{
    if (!program_xml) {
        program_xml = FIREHOSE_DEFAULT_PROGRAM_XML_FILENAME;
    }

    ssize_t image_total_size = 0;
    int r = firehose_program_file_iter(NULL, package, program_xml, firehose_program_file_iter_total_image_sector_count, &image_total_size);
    if (r != 0) {
        return r;
    }
    return image_total_size;
}


QCOMDL_API
int firehose_verify_vip(qcomdl_resource_package_t *package, const char *vip_xml, const char *digest_table, const char *chained_digests)
{

    int ret = -1;
    xmlDocPtr doc = NULL;
    uint8_t *msg_buf = NULL;
    char *xmlData;
    int len;

    firehose_verify_vip_ctx_t vip_ctx = {
        .num_digests_consumed = 0,
        .num_mbn_digests = 0,
        .max_digest_table_count = 0,
        .mbn_digests = NULL,
        .chained_digests = NULL,
    };
    memset(vip_ctx.cur_digest, 0, sizeof(vip_ctx.cur_digest));

    if (vip_xml == NULL) {
        vip_xml = FIREHOSE_DEFAULT_VIP_XML_FILENAME;
    }
    if (digest_table == NULL) {
        digest_table = FIREHOSE_DEFAULT_DIGEST_TABLE_FILENAME;
    }
    if (chained_digests == NULL) {
        chained_digests = FIREHOSE_DEFAULT_CHAINED_DIGESTS_FILENAME;
    }

    // load XML data into buffer
    int fret = read_file_to_buffer(package, vip_xml, &xmlData, &len);
    if (fret != 0) {
        qcomdl_log_error("could not read data from %s\n", vip_xml);
        goto teardown;
    }

    doc = xmlReadMemory(xmlData, len, NULL, NULL, 0);
    free(xmlData);

    if (!doc) {
        qcomdl_log_error("cannot parse %s - %s\n", vip_xml, get_xml_error());
        goto teardown;
    }

    vip_ctx.mbn_digests = qcomdl_fopen(package, package->img_dir, digest_table, "r");
    if (!vip_ctx.mbn_digests) {
        qcomdl_log_error("cannot open digest table: %s\n", digest_table);
        goto teardown;
    }

    xmlNodePtr messages = xmlDocGetRootElement(doc);
    if (!messages || strcmp((const char*)messages->name, "messages") != 0) {
        qcomdl_log_error("parse error, missing <messages> node in %s\n", vip_xml);
        goto teardown;
    }

    struct mbn40_header mbn;
    if (qcomdl_fread(&mbn, sizeof(mbn), 1, vip_ctx.mbn_digests) != 1) {
        qcomdl_log_error("unable to read mbn header from %s\n", digest_table);
        goto teardown;
    }

    if (mbn.image_id != MBN_VIP_IMAGE_ID) {
        qcomdl_log_error("invalid MBN Image ID in %s - 0x%x != 0x%x(MBN_VIP_IMAGE_ID)\n",
                         digest_table,
                         mbn.image_id,
                         MBN_VIP_IMAGE_ID);
        goto teardown;
    }

    if (mbn.header_vsn_num != MBN_VERSION_NUM) {
        qcomdl_log_error("invalid MBN version number in %s - 0x%x != 0x%x(MBN_VIP_IMAGE_ID)\n",
                         digest_table,
                         mbn.header_vsn_num,
                         MBN_VERSION_NUM);
        goto teardown;
    }

    vip_ctx.num_mbn_digests = mbn.code_size / SHA256_DIGEST_LENGTH;
    if (vip_ctx.num_mbn_digests > FIREHOSE_MAX_MBN_DIGESTS) {
        qcomdl_log_error("too many digests in %s - %zu > %i(MAX_MBN_DIGESTS)\n",
                         digest_table,
                         vip_ctx.num_mbn_digests,
                         FIREHOSE_MAX_MBN_DIGESTS);
        goto teardown;
    }

    if (vip_ctx.num_mbn_digests == FIREHOSE_MAX_MBN_DIGESTS) {
        vip_ctx.chained_digests = qcomdl_fopen(package, package->img_dir, chained_digests, "r");
        if (!vip_ctx.chained_digests) {
            qcomdl_log_error("cannot open chained digests: %s\n", chained_digests);
            goto teardown;
        }
        vip_ctx.num_mbn_digests--;
    }
    // chained_digests doesn't always exist so no check (here at least)

    if (qcomdl_fseeko(vip_ctx.mbn_digests, mbn.image_src, SEEK_SET) != 0) {
        qcomdl_log_error("unable to seek to MBN image_src offset in %s : 0x%x (reason: %s)\n",
                         digest_table,
                         mbn.image_src,
                         strerror(errno));
        goto teardown;
    }

    // The payload size and digest table size can't be negotiated with the target in VIP.
    // MaxPayloadSize and MaxDigestTable size are provided in the VIP messages configuration.
    // If left unspecified in the VIP messages configuration the default values are used.
    int max_payload_size = FIREHOSE_DEFAULT_PAYLOAD_SIZE;
    vip_ctx.max_digest_table_count = FIREHOSE_MAX_DIGEST_TABLE_COUNT;

    int v = get_prop_as_int(messages, (const xmlChar*)"max_payload_size");
    if (v > 0) {
        max_payload_size = v;
    }

    v = get_prop_as_int(messages, (const xmlChar*)"max_digest_table_count");
    if (v > 0) {
        if (v > FIREHOSE_MAX_DIGEST_TABLE_COUNT) {
            qcomdl_log_error("max_digest_table_count attribute in vip xml file is too large: %i > %i\n",
                             v,
                             FIREHOSE_MAX_DIGEST_TABLE_COUNT);
            goto teardown;
        }
        vip_ctx.max_digest_table_count = (size_t)v;
    }

    msg_buf = malloc((size_t)max_payload_size);
    if (!msg_buf) {
        qcomdl_log_error("malloc - %s\n", strerror(errno));
        return -1;
    }

    uint8_t pr_digest[SHA256_DIGEST_STRING_LENGTH + 1];
    pr_digest[SHA256_DIGEST_STRING_LENGTH] = 0;

    uint8_t pr_cur_digest[SHA256_DIGEST_STRING_LENGTH +1];
    pr_cur_digest[SHA256_DIGEST_STRING_LENGTH] = 0;

    size_t msg_idx = 0;
    for (xmlNodePtr cur = messages->children; cur; cur = cur->next) {
        bool is_program_message = false;
        if (strcmp((const char*)cur->name, "message") == 0) {
            is_program_message = false;
        } else if (strcmp((const char*)cur->name, "program_message") == 0) {
            is_program_message = true;
        } else {
            continue;
        }

        qcomdl_log_info("Processing firehose VIP command message at index %zu\n", msg_idx);

        if (get_next_digest(&vip_ctx) != 0) {
            goto teardown;
        }

        xmlChar *msg_hex = xmlNodeGetContent(cur);
        int msg_len = unhex(msg_hex, msg_buf, max_payload_size);
        free(msg_hex);
        if (msg_len < 0) {
            qcomdl_log_error("unable to parse vip xml digest in %s at idx=%zu\n",
                             digest_table,
                             msg_idx);
            goto teardown;
        }

        sha256_digest msg_digest;
        sha256(msg_digest, msg_buf, (size_t)msg_len);

        if (memcmp(msg_digest, vip_ctx.cur_digest, sizeof(sha256_digest)) != 0) {
            hex(msg_digest, sizeof(msg_digest), pr_digest, sizeof(pr_digest)-1);
            hex(vip_ctx.cur_digest, sizeof(vip_ctx.cur_digest), pr_cur_digest, sizeof(pr_cur_digest)-1);

            qcomdl_log_error("digest mismatch for VIP %s in %s at idx: %zu\n"
                             "  (message) %s\n"
                             "  (expect)  %s\n",
                             cur->name,
                             vip_xml,
                             msg_idx,
                             pr_digest,
                             pr_cur_digest);
            goto teardown;
        }

        msg_idx++;

        if (!is_program_message) {
            continue;
        }

        xmlChar *filename = xmlGetProp(cur, (xmlChar *)"filename");
        if (!filename) {
            qcomdl_log_error("unable to get filename from program_message at vip_xml idx: %zu\n", msg_idx);
            goto teardown;
        }

        qcomdl_log_info("Verifying file digests for \"%s\"\n", filename);

        qcomdl_resource_file_t *f = qcomdl_fopen(package, package->img_dir, (char *)filename, "r");
        if (!f) {
            qcomdl_log_error("unable to open file from program_message at vip_xml idx: %zu - %s\n",
                             msg_idx,
                             filename);
            xmlFree(filename);
            goto teardown;
        }
        uint8_t chunk_buf[max_payload_size];
        memset(chunk_buf, 0, (size_t)max_payload_size);
        size_t chunk_len = 0;
        bool f_error = false;
        while((chunk_len = qcomdl_fread(chunk_buf, 1, (size_t)max_payload_size, f)) != 0) {
            if (get_next_digest(&vip_ctx) != 0) {
                f_error = true;
                break;
            }

            size_t pad = (chunk_len % FIREHOSE_SECTOR_SIZE);
            if (pad) {
                chunk_len += (FIREHOSE_SECTOR_SIZE - pad);
            }

            assert(chunk_len <= (size_t)max_payload_size);

            sha256(msg_digest, chunk_buf, chunk_len);
            if (memcmp(msg_digest, vip_ctx.cur_digest, sizeof(sha256_digest)) != 0) {
                hex(msg_digest, sizeof(msg_digest), pr_digest, sizeof(pr_digest));
                hex(vip_ctx.cur_digest, sizeof(vip_ctx.cur_digest), pr_cur_digest, sizeof(pr_cur_digest));

                qcomdl_log_error("digest mismatch for %s chunk sized %zu at offset 0x%zx at vip_xml idx: %zu\n"
                                 "  (message) %s\n"
                                 "  (expect)  %s\n",
                                 filename,
                                 chunk_len,
                                 (size_t)(qcomdl_ftello(f) - (off_t)chunk_len),
                                 msg_idx,
                                 pr_digest,
                                 pr_cur_digest);
                f_error = true;
                break;
            }
            memset(chunk_buf, 0, (size_t)max_payload_size);
        }
        int eof = qcomdl_feof(f);
        qcomdl_fclose(f);
        if (f_error || (!eof)) {
            qcomdl_log_error("unable to verify file %s\n", filename);
            xmlFree(filename);
            goto teardown;
        }
        xmlFree(filename);
    }

    if (vip_ctx.num_digests_consumed < vip_ctx.num_mbn_digests) {
        qcomdl_log_error("Extra digests at end of file: %s\n", digest_table);
        goto teardown;
    }

    if (vip_ctx.chained_digests) {
        bool tail_error = false;
        sha256_digest tail_digest;
        sha256_digest zero_digest;
        memset(zero_digest, 0, sizeof(zero_digest));
        while(qcomdl_fread(tail_digest, sizeof(tail_digest), 1, vip_ctx.chained_digests)) {
            if (memcmp(zero_digest, tail_digest, sizeof(sha256_digest)) != 0) {
                hex(tail_digest, sizeof(tail_digest), pr_digest, sizeof(pr_digest));
                qcomdl_log_error("Extra non-zero chained digest at file offset 0x%zx: %s\n",
                                 (size_t)qcomdl_ftello(vip_ctx.chained_digests),
                                 pr_digest);
                tail_error = true;
            }
        }
        if (tail_error) {
            goto teardown;
        }
    }

    ret = 0;

teardown:
    if (doc) {
        xmlFreeDoc(doc);
    }
    if (vip_ctx.mbn_digests) {
        qcomdl_fclose(vip_ctx.mbn_digests);
    }
    if (vip_ctx.chained_digests) {
        qcomdl_fclose(vip_ctx.chained_digests);
    }
    free(msg_buf);
    if (ret != 0) {
        qcomdl_log_error("\n"
                         "  (digests consumed) %zu\n"
                         "  (mbn digests)      %zu\n",
                         vip_ctx.num_digests_consumed,
                         vip_ctx.num_mbn_digests);
    }
    return ret;
}
