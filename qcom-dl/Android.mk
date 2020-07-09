# Copyright 2011 The Android Open Source Project
#
common_LOCAL_PATH := $(call my-dir)

QCOMDL_VERSION := $$(head -1 $(common_LOCAL_PATH)/VERSION | tr -d '\n')
common_CFLAGS := -std=c11 -Wno-unknown-pragmas -DQCOMDL_VERSION=\"$(QCOMDL_VERSION)\"

common_SHARED_LIBRARIES := \
	libusb1.0

common_C_INCLUDES := \
	external/qcom-dl/inc \
	external/libusb-1.0/libusb \
	external/libxml2/include \
	external/icu/icu4c/source/common \
	external/libzip \
	external/libzip/lib \
	external/libyaml/include

#---------------------------------------------------------
# qcom-dl executable
#---------------------------------------------------------
include $(CLEAR_VARS)
LOCAL_PATH := $(common_LOCAL_PATH)
LOCAL_MODULE := qcom-dl
LOCAL_BUILD_TARGET_ANDROID := true
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := $(common_CFLAGS)
LOCAL_SHARED_LIBRARIES := $(common_SHARED_LIBRARIES) libqcomdl
LOCAL_C_INCLUDES += $(common_C_INCLUDES)
LOCAL_SRC_FILES := src/main.c

include $(BUILD_EXECUTABLE)


#---------------------------------------------------------
# libqcomdl.so shared library
#---------------------------------------------------------
include $(CLEAR_VARS)
LOCAL_PATH := $(common_LOCAL_PATH)
LOCAL_MODULE := libqcomdl
LOCAL_BUILD_TARGET_ANDROID := true
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := $(common_CFLAGS) -shared
LOCAL_SHARED_LIBRARIES := $(common_SHARED_LIBRARIES) liblog libzip libyaml libxml2
LOCAL_C_INCLUDES += $(common_C_INCLUDES)
LOCAL_SRC_FILES := \
	src/edl.c \
	src/firehose.c \
	src/qcomdl.c \
	src/qcomdl_build_info.c \
	src/qcomdl_log.c \
	src/qcomdl_transport.c \
	src/qcomdl_usb.c \
	src/resource.c \
	src/sahara.c \
	src/sha256.c

include $(BUILD_SHARED_LIBRARY)


