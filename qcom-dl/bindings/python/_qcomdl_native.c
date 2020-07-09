// Copyright © 2015-2018 Square, Inc. All rights reserved.

// Per https://docs.python.org/3/c-api/intro.html#include-files include Python.h before any other headers.
#include <Python.h>

#include <stdio.h>
#include <stdint.h>
#include <libgen.h>


#include <libusb.h>

#include "qcomdl.h"
#include "qcomdl_usb.h"
#include "qcomdl_log.h"
#include "edl.h"
#include "firehose.h"
#include "sahara.h"


// Library-specific exceptions will be raised as QcomDlError's
// this type is defined in the module initialization function
static PyObject *QDLPY_Qcomdl_Error;


typedef struct {
    PyObject_HEAD;
    edl_connection_t *connection;
} QDLPY_Edl;


typedef struct {
    PyObject_HEAD;
    sahara_connection_t *connection;
} QDLPY_Sahara;


typedef struct {
    PyObject_HEAD;
    firehose_connection_t *connection;
    bool using_percent_progress;
} QDLPY_Firehose;



#pragma mark internal utility C functions and structures

typedef struct {
    PyObject *py_start_sectors_from_file;
    PyObject *py_sent_file_sectors;
    PyObject *py_finished_sectors_from_file;
} python_file_progress_api_t;


typedef struct {
    PyObject *py_total_progress;
} python_percent_progress_api_t;


static bool wrap_start_sectors_from_file(const char *file, size_t file_sectors, void *ctx)
{
    const python_file_progress_api_t *api = ctx;
    if (!api) {
        qcomdl_log_error("python callback wrapper called with missing/unregistered python file progress API\n");
        return false;
    }
    if (api->py_start_sectors_from_file) {
        PyObject *args = Py_BuildValue("(sl)", file, file_sectors);
        PyObject *result = PyObject_CallObject(api->py_start_sectors_from_file, args);
        Py_DECREF(args);
        if (result == NULL) {
            qcomdl_log_error("A python exception occurred in the py_start_sectors_from_file callback\n");
            return false;
        }
        Py_DECREF(result);
    }
    return true;
}


static bool wrap_sent_file_sectors(const char *file, size_t sectors_written, void *ctx)
{
    const python_file_progress_api_t *api = ctx;
    if (!api) {
        qcomdl_log_error("python callback wrapper called with missing/unregistered python file progress API\n");
        return false;
    }
    if (api->py_sent_file_sectors) {
        PyObject *args = Py_BuildValue("(sl)", file, sectors_written);
        PyObject *result = PyObject_CallObject(api->py_sent_file_sectors, args);
        Py_DECREF(args);
        if (result == NULL) {
            qcomdl_log_error("A python exception occurred in the py_sent_file_sectors callback\n");
            return false;
        }
        Py_DECREF(result);
    }
    return true;
}


static bool wrap_finished_sectors_from_file(const char *file, int result, size_t total_sectors_written, void *ctx)
{
    const python_file_progress_api_t *api = ctx;
    if (!api) {
        qcomdl_log_error("python callback wrapper called with missing/unregistered python file progress API\n");
        return false;
    }
    if (api->py_finished_sectors_from_file) {
        PyObject *args = Py_BuildValue("(sil)", file, result, total_sectors_written);
        PyObject *result = PyObject_CallObject(api->py_finished_sectors_from_file, args);
        Py_DECREF(args);
        if (result == NULL) {
            qcomdl_log_error("A python exception occurred in the py_finished_sectors_from_file callback\n");
            return false;
        }
        Py_DECREF(result);
    }
    return true;
}


static bool wrap_percent_progress(int percent_written, void *ctx)
{
    const python_percent_progress_api_t *api = ctx;
    if (!api) {
        qcomdl_log_error("python callback wrapper called with missing/unregistered python file progress API\n");
        return false;
    }
    if (api->py_total_progress) {
        PyObject *args = Py_BuildValue("(i)", percent_written);
        PyObject *result = PyObject_CallObject(api->py_total_progress, args);
        Py_DECREF(args);
        if (result == NULL) {
            qcomdl_log_error("A python exception occurred in the py_total_progress callback\n");
            return false;
        }
        Py_DECREF(result);
    }
    return true;

}


static python_file_progress_api_t *create_python_file_progress_api(PyObject *f1, PyObject *f2, PyObject *f3)
{
    python_file_progress_api_t *tmp = calloc(1, sizeof(python_file_progress_api_t));
    if (!tmp) {
        qcomdl_log_perror("calloc");
        return NULL;
    }
    if (f1) {
        Py_INCREF(f1);
    }
    if (f2) {
        Py_INCREF(f2);
    }
    if (f3) {
        Py_INCREF(f3);
    }
    tmp->py_start_sectors_from_file = f1;
    tmp->py_sent_file_sectors = f2;
    tmp->py_finished_sectors_from_file = f3;
    return tmp;
}


static void free_python_file_progress_api(python_file_progress_api_t *api)
{
    if (api) {
        if (api->py_start_sectors_from_file) {
            Py_DECREF(api->py_start_sectors_from_file);
        }
        if (api->py_sent_file_sectors) {
            Py_DECREF(api->py_sent_file_sectors);
        }
        if (api->py_finished_sectors_from_file) {
            Py_DECREF(api->py_finished_sectors_from_file);
        }
        free(api);
    }
}


static python_percent_progress_api_t *create_python_percent_progress_api(PyObject *func, size_t total_image_sectors)
{
    python_percent_progress_api_t *tmp = calloc(1, sizeof(python_percent_progress_api_t));
    if (!tmp) {
        qcomdl_log_perror("calloc");
        return NULL;
    }
    if (func) {
        Py_INCREF(func);
    }
    tmp->py_total_progress = func;
    return tmp;
}


static void free_python_percent_progress_api(python_percent_progress_api_t *api)
{
    if (api) {
        if (api->py_total_progress) {
            Py_DECREF(api->py_total_progress);
        }
        free(api);
    }
}


static void free_progress_api_from_firehose(QDLPY_Firehose *obj)
{
    if (obj && obj->connection) {
        if (obj->using_percent_progress) {
            free_python_percent_progress_api(obj->connection->percent_progress_ctx);
        } else {
            free_python_file_progress_api((python_file_progress_api_t*)obj->connection->file_progress_ctx);
        }

        firehose_register_percent_progress_handlers(obj->connection, NULL, NULL);
        firehose_register_file_progress_handlers(obj->connection, NULL, NULL);
    }
}


#pragma mark qcomdl class methods

static PyObject *QDLPY_Qcomdl_Version(PyObject *self, PyObject *args)
{
    return Py_BuildValue("s", qcomdl_version_string());
}


static PyObject *QDLPY_Qcomdl_SetQcomdlLoglevel(PyObject *self, PyObject *args)
{
    int level = 0;
    if (!PyArg_ParseTuple(args, "i", &level)) {
        return NULL;
    }
    qcomdl_log_set_level((qcomdl_log_level_t)level);
    return Py_None;
}


static PyObject *QDLPY_Qcomdl_SetUsbLoglevel(PyObject *self, PyObject *args)
{
    int level = 0;
    if (!PyArg_ParseTuple(args, "i", &level)) {
        return NULL;
    }
    qcomdl_set_usb_loglevel(level);
    return Py_None;
}


static PyObject *QDLPY_Qcomdl_GetDeviceInfo(PyObject *self, PyObject *args)
{
    qcomdl_usb_device_descriptor_t dev;

    qcomdl_usb_device_status_t status = qcomdl_usb_get_device_info(&dev, false);

    PyObject *ret = NULL;

    switch (status) {
        case QCOMDL_DEVICE_STATUS_USB_ERROR: {
            PyErr_SetString(QDLPY_Qcomdl_Error, "libusb error");
            break;
        }

        case QCOMDL_DEVICE_STATUS_MULTIPLE_DEVICES_ERROR:
        {
            PyErr_SetString(QDLPY_Qcomdl_Error, "too many usb devices");
            break;
        }

        case QCOMDL_DEVICE_STATUS_DEVICE_NOT_FOUND:
        {
            ret = Py_None;
            break;
        }

        case QCOMDL_DEVICE_STATUS_SUCCESS:
        {
            PyObject *dict = PyDict_New();
            if (dict) {
                PyDict_SetItemString(dict, "vid", PyInt_FromLong((long)dev.vid));
                PyDict_SetItemString(dict, "pid", PyInt_FromLong((long)dev.pid));
                PyDict_SetItemString(dict, "serial", PyString_FromString((const char*)dev.serial));
            }
            ret = dict;
            break;
        }

        default:
        {
            PyErr_SetString(QDLPY_Qcomdl_Error, "unrecognized return value getting device info");
            ret = NULL;
            break;
        }

    }
    return ret;
}


static PyObject *QDLPY_Qcomdl_TotalImageSectorsVip(PyObject *self, PyObject *args)
{
    PyObject *ret = NULL;
    const char *img_dir = NULL;
    const char *vip_xml = NULL;
    if (!PyArg_ParseTuple(args, "ss", &img_dir, &vip_xml)) {
        return NULL;
    }
    qcomdl_resource_package_t *package = qcomdl_resource_package_open(img_dir);
    if (!package) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "qcomdl_resource_package_open failed");
        return NULL;
    }
    ssize_t count = firehose_total_image_sectors_vip(package, vip_xml);
    if (count < 0) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "firehose_total_image_sectors_vip failed");
        goto teardown_package;
    }
    ret = PyLong_FromSsize_t(count);
teardown_package:
    qcomdl_resource_package_free(package);
    return ret;
}


static PyObject *QDLPY_Qcomdl_TotalImageSectorsNonVip(PyObject *self, PyObject *args)
{
    PyObject *ret = NULL;
    const char *img_dir = NULL;
    const char *prog_xml = NULL;
    if (!PyArg_ParseTuple(args, "ss", &img_dir, &prog_xml)) {
        return NULL;
    }
    qcomdl_resource_package_t *package = qcomdl_resource_package_open(img_dir);
    if (!package) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "qcomdl_resource_package_open failed");
        return NULL;
    }
    ssize_t count = firehose_total_image_sectors_non_vip(package, prog_xml);
    if (count < 0) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "firehose_total_image_sectors_non_vip failed");
        goto teardown_package;
    }
    ret = PyLong_FromSsize_t(count);
teardown_package:
    qcomdl_resource_package_free(package);
    return ret;
}


static PyObject *QDLPY_Qcomdl_VerifyVip(PyObject *self, PyObject *args)
{
    PyObject *ret = NULL;
    const char *images_dir = NULL;
    const char *vip_xml = NULL;
    const char *digest_table = NULL;
    const char *chained_digests = NULL;

    if (!PyArg_ParseTuple(args, "s|sss", &images_dir, &vip_xml, &digest_table, &chained_digests)) {
        return NULL;
    }

    qcomdl_resource_package_t *package = qcomdl_resource_package_open(images_dir);
    if (!package) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "qcomdl_resource_package_open failed");
        return NULL;
    }

    if (firehose_verify_vip(package, vip_xml, digest_table, chained_digests) == 0) {
        ret = Py_True;
    } else {
        ret = Py_False;
    }
    qcomdl_resource_package_free(package);
    return ret;
}


#pragma mark edl interface

static PyObject *QDLPY_Edl_New(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    QDLPY_Edl *self = (QDLPY_Edl*)type->tp_alloc(type, 0);
    if (self != NULL) {
        self->connection = NULL;
    }
    return (PyObject *)self;
}


static void QDLPY_Edl_Dealloc(QDLPY_Edl *self)
{
    // tbd
    self->ob_type->tp_free((PyObject*)self);
}


static PyObject *QDLPY_Edl_ListDevices(QDLPY_Edl *self)
{
    qcomdl_usb_device_descriptor_t **edl_devices = NULL;
    ssize_t count = qcomdl_usb_get_device_list(&edl_devices, false);
    if (count < 0) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "There was an error enumerating devices");
        return NULL;
    }

    PyObject *device_list = PyList_New(count);
    if ((device_list) && (count > 0)) {
        for (ssize_t i = 0; i < count; i++) {
            PyObject *dict = PyDict_New();
            if (!dict) {
                Py_DECREF(device_list);
                return NULL;
            }
            PyDict_SetItemString(dict, "bus", PyInt_FromLong((long)edl_devices[i]->bus));
            PyDict_SetItemString(dict, "port", PyInt_FromLong((long)edl_devices[i]->port));
            PyDict_SetItemString(dict, "vid", PyInt_FromLong((long)edl_devices[i]->vid));
            PyDict_SetItemString(dict, "pid", PyInt_FromLong((long)edl_devices[i]->pid));
            PyDict_SetItemString(dict, "vid_description", PyString_FromString(qcomdl_usb_vid_str(edl_devices[i]->vid)));
            PyDict_SetItemString(dict, "pid_description", PyString_FromString(qcomdl_usb_pid_str(edl_devices[i]->pid)));
            PyDict_SetItemString(dict, "port_path", PyString_FromString(edl_devices[i]->port_str));
            PyList_SetItem(device_list, i, dict);
        }
    }

    qcomdl_usb_free_device_list(edl_devices);

    return device_list;
}


static PyObject *QDLPY_Edl_Connect(QDLPY_Edl *self)
{
    if (self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "EDL is already connected");
        return NULL;
    }

    self->connection = edl_connect();
    if (self->connection) {
        return Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "edl_connect returned NULL");
        }
        return NULL;
    }
}


static PyObject *QDLPY_Edl_DiagConnect(QDLPY_Edl *self)
{
    if (self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "EDL is already connected");
        return NULL;
    }

    self->connection = edl_diag_connect();
    if (self->connection) {
        return Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "edl_diag_connect returned NULL");
        }
        return NULL;
    }
}


static PyObject *QDLPY_Edl_ConnectBusAndPort(QDLPY_Edl *self, PyObject *args)
{
    if (self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "EDL is already connected");
        return NULL;
    }

    uint8_t bus = 0;
    uint8_t port = 0;
    if (!PyArg_ParseTuple(args, "bb", &bus, &port)) {
        return NULL;
    }

    self->connection = edl_connect_bus_and_port(bus, port);
    if (self->connection) {
        return Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "edl_connect_bus_and_port returned NULL");
        }
        return NULL;
    }
}


static PyObject *QDLPY_Edl_ConnectBusAndPortPath(QDLPY_Edl *self, PyObject *args)
{
    if (self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "EDL is already connected");
        return NULL;
    }

    uint8_t bus = 0;
    const char *port = NULL;
    if (!PyArg_ParseTuple(args, "bs", &bus, &port)) {
        return NULL;
    }

    self->connection = edl_connect_bus_and_port_path(bus, port);
    if (self->connection) {
        return Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "edl_connect_bus_and_port_path returned NULL");
        }
        return NULL;
    }
}


static PyObject *QDLPY_Edl_IsConnected(QDLPY_Edl *self) {
    return (self->connection) ? Py_True : Py_False;
}


static PyObject *QDLPY_Edl_Disconnect(QDLPY_Edl *self)
{
    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "EDL is not connected");
        return NULL;
    }

    int ret = edl_disconnect(self->connection);
    self->connection = NULL;

    if (ret == 0) {
        return Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "edl_disconnect failed");
        }
        return NULL;
    }
}


static PyMethodDef QDLPY_Edl_methods[] = {
    {
        .ml_name = "list_devices",
        .ml_meth = (PyCFunction)QDLPY_Edl_ListDevices,
        .ml_flags = METH_CLASS,
        .ml_doc = "Get a list of attached EDL devices by their USB bus and port numbers",
    },
    {
        .ml_name = "connect",
        .ml_meth = (PyCFunction)QDLPY_Edl_Connect,
        .ml_flags = METH_NOARGS,
        .ml_doc = "Connect to a EDL target over USB. If more than one EDL target is attached, the first one found is selected.",
    },
    {
        .ml_name = "diag_connect",
        .ml_meth = (PyCFunction)QDLPY_Edl_DiagConnect,
        .ml_flags = METH_NOARGS,
        .ml_doc = "Connect to a EDL target in 'Diagnostic' mode over USB (this is the mode EDL comes up in when a bootloader panic or crash occurs). If more than one EDL target is attached, the first one found is selected.",
    },
    {
        .ml_name = "connect_bus_and_port",
        .ml_meth = (PyCFunction)QDLPY_Edl_ConnectBusAndPort,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Connect to a EDL target over USB by specifying the USB bus and port it is connected to.",
    },
    {
        .ml_name = "connect_bus_and_port_path",
        .ml_meth = (PyCFunction)QDLPY_Edl_ConnectBusAndPortPath,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Connect to a EDL target over USB by specifying the USB bus and port it is connected to.",
    },
    {
        .ml_name = "isconnected",
        .ml_meth = (PyCFunction)QDLPY_Edl_IsConnected,
        .ml_flags = METH_NOARGS,
        .ml_doc = "Check whether an EDL instance is connected.",
    },
    {
        .ml_name = "disconnect",
        .ml_meth = (PyCFunction)QDLPY_Edl_Disconnect,
        .ml_flags = METH_NOARGS,
        .ml_doc = "Disconnect from an already connected EDL target over USB."
    },
    {NULL}
};


static PyTypeObject QDLPY_EdlType = {
    PyObject_HEAD_INIT(&PyType_Type)
    .tp_name = "qcomdl._qcomdl_native.Edl",
    .tp_basicsize = sizeof(QDLPY_Edl),
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_doc = "EDL USB connection wrapper",

    .tp_new = (newfunc)QDLPY_Edl_New,
    .tp_dealloc = (destructor)QDLPY_Edl_Dealloc,
    .tp_methods = QDLPY_Edl_methods,
};


#pragma mark sahara interface

static PyObject *QDLPY_Sahara_New(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    QDLPY_Edl *edl = NULL;
    if (!PyArg_ParseTuple(args, "O", &edl)) {
        return NULL;
    }

    if (PyObject_IsInstance((PyObject*)edl, (PyObject*)&QDLPY_EdlType) == 0) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Invalid argument - argument must be an Edl instance");
        return NULL;
    }

    sahara_connection_t *conn = sahara_connect(edl->connection);
    if (!conn) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Unable to connect to sahara");
        return NULL;
    }

    QDLPY_Sahara *self = (QDLPY_Sahara*)type->tp_alloc(type, 0);
    if (self != NULL) {
        self->connection = conn;
    }
    return (PyObject*)self;
}


static void QDLPY_Sahara_Dealloc(QDLPY_Sahara *self)
{
    if (self->connection) {
        sahara_connection_free(self->connection);
    }

    self->ob_type->tp_free((PyObject*)self);
}


static PyObject *QDLPY_Sahara_Upload(QDLPY_Sahara *self, PyObject *args)
{
    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "EDL is not connected");
        return NULL;
    }

    PyObject *ret = NULL;
    const char *arg1 = NULL;
    const char *arg2_optional = NULL;
    const char *images_dir = NULL;
    const char *filename = NULL;

    if (!PyArg_ParseTuple(args, "s|s", &arg1, &arg2_optional)) {
        return NULL;
    }

    if (arg2_optional) {
        images_dir = arg1;
        filename = arg2_optional;
    } else {
        // Support legacy callers (from before we added resource layer abstraction)
        images_dir = "";
        filename = arg1;
    }

    qcomdl_resource_package_t *package = qcomdl_resource_package_open(images_dir);
    if (!package) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "qcomdl_resource_package_open failed");
        return NULL;
    }

    if (sahara_upload(self->connection, package, filename) == 0) {
        ret = Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "sahara_upload failed");
        }
        goto teardown_package;
    }
teardown_package:
    qcomdl_resource_package_free(package);
    return ret;
}


static PyObject *QDLPY_Sahara_DeviceInfo(QDLPY_Sahara *self)
{
    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "EDL is not connected");
        return NULL;
    }

    pbl_info_t pbl_info;
    bzero(&pbl_info, sizeof(pbl_info));

    int ret = sahara_device_info(self->connection, &pbl_info);
    if (ret != 0) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Unable to dump device info");
        return NULL;
    }

    PyObject *dict = PyDict_New();
    if (dict) {
        PyDict_SetItemString(dict, "serial", PyLong_FromUnsignedLong(pbl_info.serial));
        PyDict_SetItemString(dict, "msm_id", PyLong_FromUnsignedLong(pbl_info.msm_id));
        PyDict_SetItemString(dict, "pbl_sw", PyLong_FromUnsignedLong(pbl_info.pbl_sw));
        PyDict_SetItemString(dict, "pk_hash", PyByteArray_FromStringAndSize((const char*)pbl_info.pk_hash, sizeof(pbl_info.pk_hash)));
    }

    return dict;
}


static PyObject *QDLPY_Sahara_ReadDebugData(QDLPY_Sahara *self)
{
    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "EDL is not connected");
        return NULL;
    }

    pbl_info_t pbl_info;
    bzero(&pbl_info, sizeof(pbl_info));

    uint8_t *buf = NULL;
    int buf_len = 0;

    int rc = sahara_read_debug_data(self->connection, &buf, &buf_len);
    if (rc != 0) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Unable to read debug data");
        return NULL;
    }

    PyObject *bytes = PyByteArray_FromStringAndSize((const char*)buf, (Py_ssize_t)buf_len);
    free(buf);
    return bytes;
}


static PyObject *QDLPY_Sahara_EnterMemoryDebug(QDLPY_Sahara *self)
{
    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "EDL is not connected");
        return NULL;
    }

    if (sahara_enter_memory_debug(self->connection) == 0) {
        return Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "sahara_enter_memory_debug failed");
        }
        return NULL;
    }
}


static PyObject *QDLPY_Sahara_DumpMemoryTable(QDLPY_Sahara *self, PyObject *args)
{
    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "EDL is not connected");
        return NULL;
    }

    char *outdir = NULL;
    if (!PyArg_ParseTuple(args, "s", &outdir)) {
        return NULL;
    }

    if (sahara_memory_dump_table(self->connection, outdir) == 0) {
        return Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "sahara_memory_dump_table failed");
        }
        return NULL;
    }
}


static bool append_memory_table_desc(PyObject *list, const char *desc, const char *filename, unsigned long long addr, unsigned long long len, uint8_t save_pref)
{
    PyObject *dict = PyDict_New();
    if (dict) {
        PyDict_SetItemString(dict, "desc", PyString_FromString(desc));
        PyDict_SetItemString(dict, "filename", PyString_FromString(filename));
        PyDict_SetItemString(dict, "address", PyLong_FromUnsignedLongLong(addr));
        PyDict_SetItemString(dict, "length", PyLong_FromUnsignedLongLong(len));
        PyDict_SetItemString(dict, "save_pref", PyInt_FromLong(save_pref));
        PyList_Append(list, dict);
        return true;
    } else {
        return false;
    }
}


static PyObject *QDLPY_Sahara_ParseMemoryTable(QDLPY_Sahara *self, PyObject *args)
{
    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "EDL is not connected");
        return NULL;
    }

    if (!self->connection->memory_table || !self->connection->memory_table_length) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "No memory table information is available");
        return NULL;
    }

    PyObject* list = PyList_New(0);
    if (list) {
        if (self->connection->target_is_64bit) {
            size_t count = (size_t)self->connection->memory_table_length / sizeof(dload_64_bit_debug_type);
            dload_64_bit_debug_type *region = self->connection->memory_table;
            for (; count > 0; count--, region++) {
                bool r = append_memory_table_desc(list,
                                                  region->desc,
                                                  region->filename,
                                                  region->mem_base,
                                                  region->length,
                                                  (uint8_t)(region->save_pref & 0xFF));
                if (!r) {
                    Py_DecRef(list);
                    return NULL;
                }
            }
        } else {
            size_t count = (size_t)self->connection->memory_table_length / sizeof(dload_debug_type);
            dload_debug_type *region = self->connection->memory_table;
            for (; count > 0; count--, region++) {
                bool r = append_memory_table_desc(list,
                                                  region->desc,
                                                  region->filename,
                                                  region->mem_base,
                                                  region->length,
                                                  (uint8_t)(region->save_pref & 0xFF));
                if (!r) {
                    Py_DecRef(list);
                    return NULL;
                }
            }
        }
    }
    return list;
}


static PyObject *QDLPY_Sahara_MemoryRead(QDLPY_Sahara *self, PyObject *args)
{
    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "EDL is not connected");
        return NULL;
    }


    unsigned long long address = 0;
    unsigned long len = 0;

    if (!PyArg_ParseTuple(args, "Kk", &address, &len)) {
        return NULL;
    }

    uint8_t *buf = NULL;
    size_t buf_size = 0;
    if (sahara_memory_read(self->connection, (uint64_t)address, (size_t)len, &buf, &buf_size) == 0) {
        PyObject *bytes = PyByteArray_FromStringAndSize((const char *)buf, (Py_ssize_t)buf_size);
        free(buf);
        return bytes;
    } else {
        return Py_None;
    }
}

static PyObject *QDLPY_Sahara_MemoryReadToFile(QDLPY_Sahara *self, PyObject *args)
{
    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "EDL is not connected");
        return NULL;
    }

    unsigned long long address = 0;
    unsigned long long len = 0;
    char *outpath = NULL;

    if (!PyArg_ParseTuple(args, "KKs", &address, &len, &outpath)) {
        return NULL;
    }

    if (sahara_memory_read_to_file(self->connection, (uint64_t)address, (uint64_t)len, outpath) == 0) {
        return Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "sahara_memory_read_to_file failed");
        }
        return NULL;
    }
}


static PyObject *QDLPY_Sahara_Done(QDLPY_Sahara *self)
{
    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "EDL is not connected");
        return NULL;
    }

    if (sahara_done(self->connection) == 0) {
        return Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "sahara_enter_memory_debug failed");
        }
        return NULL;
    }

}


static PyObject *QDLPY_Sahara_ResetDevice(QDLPY_Sahara *self)
{
    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "EDL is not connected");
        return NULL;
    }

    if (sahara_device_reset(self->connection) == 0) {
        return Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "sahara_device_reset failed");
        }
        return NULL;
    }
}


static PyMethodDef QDLPY_Sahara_methods[] = {
    {
        .ml_name = "upload",
        .ml_meth = (PyCFunction)QDLPY_Sahara_Upload,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Upload a flash programmer binary (usually Firehose) to an EDL target via the Sahara protocol"
    },
    {
        .ml_name = "done",
        .ml_meth = (PyCFunction)QDLPY_Sahara_Done,
        .ml_flags = METH_NOARGS,
        .ml_doc = "Send a done packet and receive the response, instructing the target to continue execution"
    },
    {
        .ml_name = "device_info",
        .ml_meth = (PyCFunction)QDLPY_Sahara_DeviceInfo,
        .ml_flags = METH_NOARGS,
        .ml_doc = "Retrieve device information via the Sahara protocol."
    },
    {
        .ml_name = "read_debug_data",
        .ml_meth = (PyCFunction)QDLPY_Sahara_ReadDebugData,
        .ml_flags = METH_NOARGS,
        .ml_doc = "Retrieve device information via the Sahara protocol."
    },
    {
        .ml_name = "enter_memory_debug",
        .ml_meth = (PyCFunction)QDLPY_Sahara_EnterMemoryDebug,
        .ml_flags = METH_NOARGS,
        .ml_doc = "Enter memory debug mode (diagnostic-mode EDL feature)",
    },
    {
        .ml_name = "dump_memory_table",
        .ml_meth = (PyCFunction)QDLPY_Sahara_DumpMemoryTable,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Dump all memory regions in memory table to files (diagnostic-mode EDL feature)",
    },
    {
        .ml_name = "parse_memory_table",
        .ml_meth = (PyCFunction)QDLPY_Sahara_ParseMemoryTable,
        .ml_flags = METH_NOARGS,
        .ml_doc = "Returns a list of dictionaries representing the memory table (diagnostic-mode EDL feature)",
    },
    {
        .ml_name = "memory_read",
        .ml_meth = (PyCFunction)QDLPY_Sahara_MemoryRead,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Read target memory (diagnostic-mode EDL feature)",
    },
    {
        .ml_name = "memory_read_to_file",
        .ml_meth = (PyCFunction)QDLPY_Sahara_MemoryReadToFile,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Read large regions of target memory and write it to a file (diagnostic-mode EDL feature)",
    },
    {
        .ml_name = "reset_device",
        .ml_meth = (PyCFunction)QDLPY_Sahara_ResetDevice,
        .ml_flags = METH_NOARGS,
        .ml_doc = "Send a reset command using the Sahara protocol. (WARNING) this command does not currently seem to bring the device back online, It is probably better to use the firehose reset commands."
    },
    {NULL}
};


static PyTypeObject QDLPY_SaharaType = {
    PyObject_HEAD_INIT(&PyType_Type)
    .tp_name = "qcomdl._qcomdl_native.Sahara",
    .tp_basicsize = sizeof(QDLPY_Sahara),
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_doc = "Sahara USB connection wrapper",

    .tp_new = (newfunc)QDLPY_Sahara_New,
    .tp_dealloc = (destructor)QDLPY_Sahara_Dealloc,
    .tp_methods = QDLPY_Sahara_methods,
};


#pragma mark firehose interface

static PyObject *QDLPY_Firehose_New(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    QDLPY_Edl *edl = NULL;
    if (!PyArg_ParseTuple(args, "O", &edl)) {
        return NULL;
    }

    if (PyObject_IsInstance((PyObject*)edl, (PyObject*)&QDLPY_EdlType) == 0) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Invalid argument - argument must be an Edl instance");
        return NULL;
    }

    firehose_connection_t *conn = firehose_connect(edl->connection);
    if (!conn) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Unable to connect to firehose");
        return NULL;
    }

    QDLPY_Firehose *self = (QDLPY_Firehose*)type->tp_alloc(type, 0);
    if (self != NULL) {
        self->connection = conn;
    }

    self->using_percent_progress = false;

    return (PyObject*)self;
}


static void QDLPY_Firehose_Dealloc(QDLPY_Firehose *self)
{

    free_progress_api_from_firehose(self);
    firehose_connection_free(self->connection);

    self->ob_type->tp_free((PyObject*)self);
}


static PyObject *QDLPY_Firehose_Configure(QDLPY_Firehose *self)
{
    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }

    if (firehose_configure(self->connection) == 0) {
        return Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "firehose_configure failed");
        }
        return NULL;
    }
}


static PyObject *QDLPY_Firehose_CfgSetSkipWrite(QDLPY_Firehose *self, PyObject *args)
{
    int value = 0;
    if (!PyArg_ParseTuple(args, "i", &value)) {
        return NULL;
    }

    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }
    self->connection->cfg.SkipWrite = value;
    return Py_None;
}


static PyObject *QDLPY_Firehose_MemoryName(QDLPY_Firehose *self)
{
    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }

    if (self->connection->memory_name) {
        return PyString_FromString(self->connection->memory_name);
    } else {
        return Py_None;
    }
}


static PyObject *QDLPY_Firehose_TargetName(QDLPY_Firehose *self)
{
    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }

    if (self->connection->target_name) {
        return PyString_FromString(self->connection->target_name);
    } else {
        return Py_None;
    }
}


static PyObject *QDLPY_Firehose_Ping(QDLPY_Firehose *self)
{
    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }

    if (firehose_ping(self->connection) == 0) {
        return Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "firehose_ping failed");
        }
        return NULL;
    }
}


static PyObject *QDLPY_Firehose_SoftReset(QDLPY_Firehose *self, PyObject *args)
{
    int delay_secs = 0;
    if (!PyArg_ParseTuple(args, "i", &delay_secs)) {
        return NULL;
    }

    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }

    if (firehose_power(self->connection, "reset", delay_secs) == 0) {
        return Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "firehose_power failed");
        }
        return NULL;
    }
}


static PyObject *QDLPY_Firehose_PowerOff(QDLPY_Firehose *self, PyObject *args)
{
    int delay_secs = 0;
    if (!PyArg_ParseTuple(args, "i", &delay_secs)) {
        return NULL;
    }

    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }

    if (firehose_power(self->connection, "off", delay_secs) == 0) {
        return Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "firehose_power failed");
        }
        return NULL;
    }
}


static PyObject *QDLPY_Firehose_SendCommand(QDLPY_Firehose *self, PyObject *args)
{
    u_char *xml = NULL;
    if (!PyArg_ParseTuple(args, "s", &xml)) {
        return NULL;
    }

    size_t xml_size = strlen((char*)xml);
    if (xml_size > INT_MAX) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "xml string is too long (it must be <= MAX_INT)");
        return NULL;
    }

    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }

    if (firehose_send_command(self->connection, xml, (int)xml_size) == 0) {
        return Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "firehose_send_command failed");
        }
        return NULL;
    }
}


static PyObject *QDLPY_Firehose_SetBootableStorageDrive(QDLPY_Firehose *self, PyObject *args)
{
    int value = 0;
    if (!PyArg_ParseTuple(args, "i", &value)) {
        return NULL;
    }

    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }

    if (firehose_setbootablestoragedrive(self->connection, value) == 0) {
        return Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "firehose_setbootablestoragedrive failed");
        }
        return NULL;
    }
}


static PyObject *QDLPY_Firehose_Erase(QDLPY_Firehose *self, PyObject *args)
{
    int storagedrive = 0;
    if (!PyArg_ParseTuple(args, "i", &storagedrive)) {
        return NULL;
    }

    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }

    if (firehose_erase(self->connection, storagedrive) == 0) {
        return Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "firehose_erase failed");
        }
        return NULL;
    }
}


static PyObject *QDLPY_Firehose_RPMB_Erase(QDLPY_Firehose *self, PyObject *args)
{
    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }

    if (firehose_rpmb_erase(self->connection) == 0) {
        return Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "firehose_rpmb_erase failed");
        }
        return NULL;
    }
}


static PyObject *QDLPY_Firehose_GetStorageInfo(QDLPY_Firehose *self, PyObject *args)
{
    int partition_num = 0;
    if (!PyArg_ParseTuple(args, "i", &partition_num)) {
        return NULL;
    }

    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }

    if (firehose_getstorageinfo(self->connection, partition_num) == 0) {
        return Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "firehose_getstorageinfo failed");
        }
        return NULL;
    }
}


static PyObject *QDLPY_Firehose_Peek(QDLPY_Firehose *self, PyObject *args)
{
    uint64_t address64 = 0;
    uint64_t size = 0;

    if (!PyArg_ParseTuple(args, "KK", &address64, &size)) {
        return NULL;
    }

    if (size > SIZE_MAX) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "size parameter is too large");
        return NULL;
    }

    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }

    if (firehose_peek(self->connection, address64, (size_t)size) == 0) {
        return Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "firehose_peek failed");
        }
        return NULL;
    }
}


static PyObject *QDLPY_Firehose_Poke(QDLPY_Firehose *self, PyObject *args)
{
    uint64_t address64 = 0;
    uint64_t size = 0;
    uint64_t value = 0;

    if (!PyArg_ParseTuple(args, "KKK", &address64, &size, &value)) {
        return NULL;
    }

    if (size > SIZE_MAX) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "size parameter is too large");
        return NULL;
    }

    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }

    if (firehose_poke(self->connection, address64, (size_t)size, value) == 0) {
        return Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "firehose_poke failed");
        }
        return NULL;
    }
}


static PyObject *QDLPY_Firehose_Benchmark(QDLPY_Firehose *self, PyObject *args)
{
    int trials = 0;
    unsigned int timeout = 0;
    if (!PyArg_ParseTuple(args, "ii", &trials, &timeout)) {
        return NULL;
    }

    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }

    if (firehose_benchmark(self->connection, trials, timeout) == 0) {
        return Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "firehose_benchmark failed");
        }
        return NULL;
    }
}


static PyObject *QDLPY_Firehose_Patch(QDLPY_Firehose *self, PyObject *args)
{
    u_char *byte_offset = NULL;
    u_char *partition_num = NULL;
    u_char *size_in_bytes = NULL;
    u_char *start_sector = NULL;
    u_char *value = NULL;
    u_char *what = NULL;

    int parse_ret = PyArg_ParseTuple(args, "ssssss",
                                     &byte_offset,
                                     &partition_num,
                                     &size_in_bytes,
                                     &start_sector,
                                     &value,
                                     &what);
    if (!parse_ret) {
        return NULL;
    }

    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }

    int firehose_ret = firehose_patch(self->connection, byte_offset, partition_num, size_in_bytes, start_sector, value, what);
    if (firehose_ret == 0) {
        return Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "firehose_patch failed");
        }
        return NULL;
    }
}


static PyObject *QDLPY_Firehose_PatchFromFile(QDLPY_Firehose *self, PyObject *args)
{
    PyObject *ret = NULL;
    const char *images_dir = NULL;
    const char *patch_xml_filename = NULL;

    if (!PyArg_ParseTuple(args, "ss", &images_dir, &patch_xml_filename)) {
        return NULL;
    }

    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }

    self->connection->cfg.MemoryName = (char*)"eMMC";
    if (firehose_configure(self->connection) != 0) {
        return NULL;
    }

    qcomdl_resource_package_t *package = qcomdl_resource_package_open(images_dir);
    if (!package) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "qcomdl_resource_package_open failed");
        return NULL;
    }

    int firehose_ret = firehose_patch_from_file(self->connection, package, patch_xml_filename);
    if (firehose_ret == 0) {
        ret = Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "firehose_patch_from_file failed");
        }
        goto teardown_package;
    }
teardown_package:
    qcomdl_resource_package_free(package);
    return ret;
}


static PyObject *QDLPY_Firehose_GetSha256Digest(QDLPY_Firehose *self, PyObject *args)
{
    int num_partition_sectors = 0;
    u_char *start_sector = NULL;
    u_char *partition_num = NULL;

    if (!PyArg_ParseTuple(args, "iss", &num_partition_sectors, &start_sector, &partition_num)) {
        return NULL;
    }

    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }

    int firehose_ret = firehose_getsha256digest(self->connection, num_partition_sectors, start_sector, partition_num);
    if (firehose_ret == 0) {
        return Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "firehose_getsha256digest failed");
        }
        return NULL;
    }
}


static PyObject *QDLPY_Firehose_Program(QDLPY_Firehose *self, PyObject *args)
{
    PyObject *ret = NULL;
    const char *filename = NULL;
    u_char *start_sector = NULL;
    u_char *partition_num = NULL;
    int read_back_verify = 0;

    if (!PyArg_ParseTuple(args, "sssi", &filename, &start_sector, &partition_num, &read_back_verify)) {
        return NULL;
    }

    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }

    qcomdl_resource_package_t *package = qcomdl_resource_package_open("");
    if (!package) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "qcomdl_resource_package_open failed");
        return NULL;
    }

    int firehose_ret = firehose_program(self->connection, package, filename, start_sector, partition_num, read_back_verify);
    if (firehose_ret == 0) {
        ret = Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "firehose_program failed");
        }
        goto teardown_package;
    }
teardown_package:
    qcomdl_resource_package_free(package);
    return ret;
}


static PyObject *QDLPY_Firehose_Getsha256digestsFromFile(QDLPY_Firehose *self, PyObject *args)
{
    PyObject *ret = NULL;
    const char *filename = NULL;

    if (!PyArg_ParseTuple(args, "s", &filename)) {
        return NULL;
    }

    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }

    qcomdl_resource_package_t *package = qcomdl_resource_package_open("");
    if (!package) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "qcomdl_resource_package_open failed");
        return NULL;
    }

    int firehose_ret = firehose_getsha256digests_from_file(self->connection, package, filename);
    if (firehose_ret == 0) {
        ret = Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "firehose_getsha256digests_from_file failed");
        }
        goto teardown_package;
    }
teardown_package:
    qcomdl_resource_package_free(package);
    return ret;
}


static PyObject *QDLPY_Firehose_ProgramFromFile(QDLPY_Firehose *self, PyObject *args)
{
    PyObject *ret = NULL;
    char *images_dir = NULL;
    char *program_xml_filename = NULL;
    int read_back_verify = 0;

    if (!PyArg_ParseTuple(args, "ssi", &images_dir, &program_xml_filename, &read_back_verify)) {
        return NULL;
    }

    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }

    self->connection->cfg.MemoryName = (char*)"eMMC";
    if (firehose_configure(self->connection) != 0) {
        return NULL;
    }

    qcomdl_resource_package_t *package = qcomdl_resource_package_open(images_dir);
    if (!package) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "qcomdl_resource_package_open failed");
        return NULL;
    }

    int firehose_ret = firehose_program_from_file(self->connection, package, program_xml_filename, read_back_verify);
    if (firehose_ret == 0) {
        ret = Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "firehose_program_from_file failed");
        }
        goto teardown_package;
    }
teardown_package:
    qcomdl_resource_package_free(package);
    return ret;
}


static PyObject *QDLPY_Firehose_Vip(QDLPY_Firehose *self, PyObject *args)
{
    PyObject *ret = NULL;
    const char *images_dir = NULL;
    const char *vip_xml = NULL;
    const char *digest_table = NULL;
    const char *chained_digests = NULL;

    if (!PyArg_ParseTuple(args, "ssss", &images_dir, &vip_xml, &digest_table, &chained_digests)) {
        return NULL;
    }

    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }

    qcomdl_resource_package_t *package = qcomdl_resource_package_open(images_dir);
    if (!package) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "qcomdl_resource_package_open failed");
        return NULL;
    }

    int firehose_ret = firehose_vip(self->connection, package, vip_xml, digest_table, chained_digests);
    if (firehose_ret == 0) {
        ret = Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "firehose_vip failed");
        }
        goto teardown_package;
    }
teardown_package:
    qcomdl_resource_package_free(package);
    return ret;
}


static PyObject *QDLPY_Firehose_NonVip(QDLPY_Firehose *self, PyObject *args)
{
    PyObject *ret = NULL;
    const char *images_dir = NULL;
    const char *program_xml = NULL;
    const char *patch_xml = NULL;
    int do_erase;
    int read_back_verify;
    int do_sha256;
    int reset_delay;
    int do_rpmb_erase = 0;

    if (!PyArg_ParseTuple(args, "sssiiii|i", &images_dir, &program_xml, &patch_xml, &do_erase, &read_back_verify, &do_sha256, &reset_delay, &do_rpmb_erase)) {
        return NULL;
    }

    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }

    qcomdl_resource_package_t *package = qcomdl_resource_package_open(images_dir);
    if (!package) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "qcomdl_resource_package_open failed");
        return NULL;
    }

    int firehose_ret = firehose_non_vip(self->connection,
                                       package,
                                       program_xml,
                                       patch_xml,
                                       do_erase,
                                       read_back_verify,
                                       do_sha256,
                                       reset_delay,
                                       do_rpmb_erase);
    if (firehose_ret == 0) {
        ret = Py_True;
    } else {
        if (! PyErr_Occurred()) {
            PyErr_SetString(QDLPY_Qcomdl_Error, "firehose_non_vip failed");
        }
        goto teardown_package;
    }
teardown_package:
    qcomdl_resource_package_free(package);
    return ret;
}


static PyObject *QDLPY_Firehose_RegisterFileProgressCallbacks(QDLPY_Firehose *self, PyObject *args)
{
    PyObject *tmpf1 = NULL;
    PyObject *tmpf2 = NULL;
    PyObject *tmpf3 = NULL;

    if (!PyArg_ParseTuple(args, "OOO", &tmpf1, &tmpf2, &tmpf3)) {
        return NULL;
    }
    if (tmpf1 == Py_None) {
        tmpf1 = NULL;
    }
    if (tmpf2 == Py_None) {
        tmpf2 = NULL;
    }
    if (tmpf3 == Py_None) {
        tmpf3 = NULL;
    }
    if ( (tmpf1 && !PyCallable_Check(tmpf1)) ||
         (tmpf2 && !PyCallable_Check(tmpf2)) ||
         (tmpf3 && !PyCallable_Check(tmpf3)) ) {
        PyErr_SetString(PyExc_TypeError, "parameters must be callable");
        return NULL;
    }

    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }

    python_file_progress_api_t *api = create_python_file_progress_api(tmpf1, tmpf2, tmpf3);
    if (!api) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Cannot allocate python file progress api");
        return NULL;
    }

    struct firehose_file_progress_api handlers = {
        .handle_start_sectors_from_file = wrap_start_sectors_from_file,
        .handle_sent_file_sectors = wrap_sent_file_sectors,
        .handle_finished_sectors_from_file = wrap_finished_sectors_from_file,
    };

    free_progress_api_from_firehose(self);
    if (firehose_register_file_progress_handlers(self->connection, &handlers, api) != 0) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "firehose_register_file_progress_handlers failed");
        return NULL;
    }
    self->using_percent_progress = false;

    return Py_True;
}

static PyObject *QDLPY_Firehose_RegisterPercentProgressCallbacks(QDLPY_Firehose *self, PyObject *args)
{
    PyObject *tmpf1 = NULL;
    ssize_t total_image_sectors = 0;

    if (!PyArg_ParseTuple(args, "On", &tmpf1, &total_image_sectors)) {
        return NULL;
    }

    if (total_image_sectors < 0) {
        PyErr_SetString(PyExc_ValueError, "total_image_sectors must not be less than zero");
        return NULL;
    }

    if (tmpf1 == Py_None) {
        tmpf1 = NULL;
    }
    if (tmpf1 && !PyCallable_Check(tmpf1)) {
        PyErr_SetString(PyExc_TypeError, "parameters must be callable");
        return NULL;
    }

    if (!self->connection) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Firehose is not connected");
        return NULL;
    }

    python_percent_progress_api_t *api = create_python_percent_progress_api(tmpf1, (size_t)total_image_sectors);
    if (!api) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "Cannot allocate python percent progress api");
        return NULL;
    }

    struct firehose_percent_progress_api handlers = {
        .total_image_sectors = (size_t)total_image_sectors,
        .handle_progress_percent = wrap_percent_progress,
    };

    free_progress_api_from_firehose(self);
    if (firehose_register_percent_progress_handlers(self->connection, &handlers, api) != 0) {
        PyErr_SetString(QDLPY_Qcomdl_Error, "firehose_register_percent_progress_handlers failed");
        return NULL;
    }
    self->using_percent_progress = true;

    return Py_True;
}


static PyMethodDef QDLPY_Firehose_methods[] = {
    {
        .ml_name = "configure",
        .ml_meth = (PyCFunction)QDLPY_Firehose_Configure,
        .ml_flags = METH_NOARGS,
        .ml_doc = "Negotiate Firehose configuration with target",
    },
    {
        .ml_name = "cfg_set_skip_write",
        .ml_meth = (PyCFunction)QDLPY_Firehose_CfgSetSkipWrite,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Set the SkipWrite configuration parameter to 0 or 1. Only seems to affect <program> commands. Must be followed by a call to configure() to take effect",
    },
    {
        .ml_name = "memory_name",
        .ml_meth = (PyCFunction)QDLPY_Firehose_MemoryName,
        .ml_flags = METH_NOARGS,
        .ml_doc = "MemoryName as identified by the target after configuration is complete",
    },
    {
        .ml_name = "target_name",
        .ml_meth = (PyCFunction)QDLPY_Firehose_TargetName,
        .ml_flags = METH_NOARGS,
        .ml_doc = "TargetName as identified by the target after configuration is complete",
    },
    {
        .ml_name = "send_command",
        .ml_meth = (PyCFunction)QDLPY_Firehose_SendCommand,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Send a Firehose XML string command opaquely and confirm that an ACK is received",
    },
    {
        .ml_name = "ping",
        .ml_meth = (PyCFunction)QDLPY_Firehose_Ping,
        .ml_flags = METH_NOARGS,
        .ml_doc = "A dummy command that can be sent to the target to see if it is alive",
    },
    {
        .ml_name = "soft_reset",
        .ml_meth = (PyCFunction)QDLPY_Firehose_SoftReset,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Send the target a soft power reset command",
    },
    {
        .ml_name = "power_off",
        .ml_meth = (PyCFunction)QDLPY_Firehose_PowerOff,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Send the target a power off command",
    },
    {
        .ml_name = "set_bootable_storagedrive",
        .ml_meth = (PyCFunction)QDLPY_Firehose_SetBootableStorageDrive,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Define which storage drive (Pyhisical Partition) will be made bootable (i.e. active)",
    },
    {
        .ml_name = "erase",
        .ml_meth = (PyCFunction)QDLPY_Firehose_Erase,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Erase contents of an entire memory device (for those that support it, such as an eMMC User Partition)",
    },
    {
        .ml_name = "rpmb_erase",
        .ml_meth = (PyCFunction)QDLPY_Firehose_RPMB_Erase,
        .ml_flags = METH_NOARGS,
        .ml_doc = "Erase contents of an eMMC RPMB partition",
    },
    {
        .ml_name = "get_storage_info",
        .ml_meth = (PyCFunction)QDLPY_Firehose_GetStorageInfo,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Get storage info on a specified partition (returned by device as target logs)",
    },
    {
        .ml_name = "peek",
        .ml_meth = (PyCFunction)QDLPY_Firehose_Peek,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Read memory directly from device at any memory address (data returned by device as target logs)",
    },
    {
        .ml_name = "poke",
        .ml_meth = (PyCFunction)QDLPY_Firehose_Poke,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Write an 8-bit to 64-bit value to any memory address on the device",
    },
    {
        .ml_name = "benchmark",
        .ml_meth = (PyCFunction)QDLPY_Firehose_Benchmark,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Non-destructively test specific features of the target in order to determine performance bottlenecks",
    },
    {
        .ml_name = "program",
        .ml_meth = (PyCFunction)QDLPY_Firehose_Program,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Flash file data to regions in the target's memory",
    },
    {
        .ml_name = "getsha256digests_from_file",
        .ml_meth = (PyCFunction)QDLPY_Firehose_Getsha256digestsFromFile,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Generate sha256digests of regions in the target's memory using <program> commands defined in a program xml file",
    },
    {
        .ml_name = "program_from_file",
        .ml_meth = (PyCFunction)QDLPY_Firehose_ProgramFromFile,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Flash file data to regions in the target's memory using commands defined in a program xml file",
    },
    {
        .ml_name = "patch",
        .ml_meth = (PyCFunction)QDLPY_Firehose_Patch,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Set individual bytes/words/etc. at a specific address in memory",
    },
    {
        .ml_name = "patch_from_file",
        .ml_meth = (PyCFunction)QDLPY_Firehose_PatchFromFile,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Set individual bytes/words/etc. at a specific address in memory using commands defined in a patch xml file",
    },
    {
        .ml_name = "getsha256digest",
        .ml_meth = (PyCFunction)QDLPY_Firehose_GetSha256Digest,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Calculate a SHA256 digest on a range of memory. Allows verification of data written",
    },
    {
        .ml_name = "run_vip",
        .ml_meth = (PyCFunction)QDLPY_Firehose_Vip,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Perform Validated Image Programming (VIP)",
    },
    {
        .ml_name = "run",
        .ml_meth = (PyCFunction)QDLPY_Firehose_NonVip,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Perform programming using an unvalidated image",
    },
    {
        .ml_name = "register_file_progress_callbacks",
        .ml_meth = (PyCFunction)QDLPY_Firehose_RegisterFileProgressCallbacks,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Register for callbacks via the file progress callback API"
    },
    {
        .ml_name = "register_percent_progress_callbacks",
        .ml_meth = (PyCFunction)QDLPY_Firehose_RegisterPercentProgressCallbacks,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Register for callbacks via the percent progress callback API"
    },
    {"NULL"}
};


static PyTypeObject QDLPY_FirehoseType = {
    PyObject_HEAD_INIT(&PyType_Type)
    .tp_name = "qcomdl._qcomdl_native.Firehose",
    .tp_basicsize = sizeof(QDLPY_Firehose),
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_doc = "Firehose USB connection wrapper",

    .tp_new = (newfunc)QDLPY_Firehose_New,
    .tp_dealloc = (destructor)QDLPY_Firehose_Dealloc,

    .tp_methods = QDLPY_Firehose_methods,
};


#pragma mark python module initialization


static PyMethodDef module_methods[] = {
    {
        .ml_name = "version",
        .ml_meth = (PyCFunction)QDLPY_Qcomdl_Version,
        .ml_flags = METH_NOARGS,
        .ml_doc = "Returns the version string for qcomdl",
    },
    {
        .ml_name = "set_loglevel",
        .ml_meth = (PyCFunction)QDLPY_Qcomdl_SetQcomdlLoglevel,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Set the qcomdl loglevel",
    },
    {
        .ml_name = "set_usb_loglevel",
        .ml_meth = (PyCFunction)QDLPY_Qcomdl_SetUsbLoglevel,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Set the libusb loglevel",
    },
    {
        .ml_name = "get_device_info",
        .ml_meth = (PyCFunction)QDLPY_Qcomdl_GetDeviceInfo,
        .ml_flags = METH_NOARGS,
        .ml_doc = "Gets information about a currently connected device. Multiple connected devices are not supported",
    },
    {
        .ml_name = "total_image_sectors_vip",
        .ml_meth = (PyCFunction)QDLPY_Qcomdl_TotalImageSectorsVip,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Calculate total number of sectors to be flashed for a VIP image",
    },
    {
        .ml_name = "total_image_sectors_non_vip",
        .ml_meth = (PyCFunction)QDLPY_Qcomdl_TotalImageSectorsNonVip,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Calculate total number of sectors to be flashed for a Non-VIP image",
    },
    {
        .ml_name = "verify_vip",
        .ml_meth = (PyCFunction)QDLPY_Qcomdl_VerifyVip,
        .ml_flags = METH_VARARGS,
        .ml_doc = "Verify the contents of a flashable VIP image using the same method that VIP itself does on the device",
    },
    {NULL}
};

#define ADD_STRING_CONST(m, x) PyModule_AddStringConstant(m, #x, x)
#define ADD_INT_CONST(m, x) PyModule_AddIntConstant(m, #x, x)

PyMODINIT_FUNC
init_qcomdl_native(void)
{
    if (PyType_Ready(&QDLPY_EdlType) < 0) {
        return;
    }

    if (PyType_Ready(&QDLPY_SaharaType) < 0) {
        return;
    }

    if (PyType_Ready(&QDLPY_FirehoseType) < 0) {
        return;
    }

    PyObject *m = Py_InitModule3("qcomdl._qcomdl_native", module_methods,
                       "Python extension for communicating with Qcom EDL using the Sahara and Firehose protocols over USB");

    if (!m) {
        return;
    }

    Py_INCREF(&QDLPY_EdlType);
    PyModule_AddObject(m, "Edl", (PyObject*)&QDLPY_EdlType);

    Py_INCREF(&QDLPY_SaharaType);
    PyModule_AddObject(m, "Sahara", (PyObject*)&QDLPY_SaharaType);

    Py_INCREF(&QDLPY_FirehoseType);
    PyModule_AddObject(m, "Firehose", (PyObject*)&QDLPY_FirehoseType);


    QDLPY_Qcomdl_Error = PyErr_NewException("qcomdl.error", NULL, NULL);
    Py_INCREF(QDLPY_Qcomdl_Error);
    PyModule_AddObject(m, "error", QDLPY_Qcomdl_Error);

    ADD_STRING_CONST(m, FIREHOSE_DEFAULT_VIP_XML_FILENAME);
    ADD_STRING_CONST(m, FIREHOSE_DEFAULT_DIGEST_TABLE_FILENAME);
    ADD_STRING_CONST(m, FIREHOSE_DEFAULT_CHAINED_DIGESTS_FILENAME);
    ADD_STRING_CONST(m, FIREHOSE_DEFAULT_PROGRAM_XML_FILENAME);
    ADD_STRING_CONST(m, FIREHOSE_DEFAULT_PATCH_XML_FILENAME);
    ADD_STRING_CONST(m, FIREHOSE_DEFAULT_BIN_APQ8039);
    ADD_STRING_CONST(m, FIREHOSE_DEFAULT_BIN_SDA660);
    ADD_STRING_CONST(m, FIREHOSE_DEFAULT_VIP_BIN_APQ8039);
    ADD_STRING_CONST(m, FIREHOSE_DEFAULT_VIP_BIN_SDA660);

    ADD_INT_CONST(m, FIREHOSE_DEFAULT_RESET_DELAY_SECS);
    ADD_INT_CONST(m, FIREHOSE_DEFAULT_PCT_LOGGING_GRANULARITY);

    ADD_INT_CONST(m, QCOMDL_LOG_LEVEL_NONE);
    ADD_INT_CONST(m, QCOMDL_LOG_LEVEL_ERROR);
    ADD_INT_CONST(m, QCOMDL_LOG_LEVEL_WARNING);
    ADD_INT_CONST(m, QCOMDL_LOG_LEVEL_INFO);
    ADD_INT_CONST(m, QCOMDL_LOG_LEVEL_DEBUG);
    ADD_INT_CONST(m, QCOMDL_LOG_LEVEL_VERBOSE_DEBUG);


    // perform qcomdl library initialization
    if (qcomdl_init() != 0) {
        fprintf(stderr, "[qcomdl fatal error] cannot initialize library\n");
        abort();
    }
}
