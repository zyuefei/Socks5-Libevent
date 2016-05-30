# Copyright (C) 2009 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
LOCAL_PATH := $(call my-dir)

########################################################
## libcrypto
########################################################

include $(CLEAR_VARS)

LOCAL_MODULE := crypto
LOCAL_SRC_FILES := $(LOCAL_PATH)/turnclient/android/lib/libcrypto.a

include $(PREBUILT_STATIC_LIBRARY)

########################################################
## libancillary
########################################################

include $(CLEAR_VARS)

LOCAL_MODULE := ancillary
LOCAL_SRC_FILES := $(LOCAL_PATH)/turnclient/android/lib/libancillary.a

include $(PREBUILT_STATIC_LIBRARY)

########################################################
## libevent
########################################################

include $(CLEAR_VARS)

LOCAL_MODULE := event
LOCAL_SRC_FILES := $(LOCAL_PATH)/libevent-release-2.0.22-stable/android/lib/libevent.a

include $(PREBUILT_STATIC_LIBRARY)

########################################################
## libturnclient
########################################################

include $(CLEAR_VARS)

LOCAL_MODULE := turnclient
LOCAL_SRC_FILES := $(LOCAL_PATH)/turnclient/android/lib/libturnclient.a

include $(PREBUILT_STATIC_LIBRARY)

########################################################
## client
########################################################

include $(CLEAR_VARS)

LOCAL_MODULE    := client
LOCAL_SRC_FILES := \
    client.c
LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/libevent-release-2.0.22-stable/win32/include/ \
    $(LOCAL_PATH)/turnclient/android/include/
LOCAL_LDLIBS := -ldl -llog
LOCAL_CFLAGS += -O0
LOCAL_STATIC_LIBRARIES := \
    event \
    turnclient \
    crypto \
    ancillary

include $(BUILD_EXECUTABLE)
