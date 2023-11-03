/**
 * Copyright (C) 2023 Fibocom Corporation.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * @file fibo_helper_adapter.h
 * @author rick.chen@fibocom.com (chenhaotian)
 * @brief
 * @version 1.0
 * @date 2023-09-23
 *
 *
 **/


#ifndef _FIBO_HELPER_ADAPTER_H_
#define _FIBO_HELPER_ADAPTER_H_

#include <glib.h>
#include <gio/gio.h>
#include <libudev.h>
#include "libmbim-glib.h"
#include "fibo_helper_common.h"

#ifdef MBIM_FUNCTION_SUPPORTED
#include "mbim-fibocom.h"
#endif

typedef enum{
    CELLULAR_STATE_MIN      = 0,
    CELLULAR_STATE_UNKNOWN  = CELLULAR_STATE_MIN,
    CELLULAR_STATE_MISSING  = 1,
    CELLULAR_STATE_EXISTED  = 2,
    CELLULAR_STATE_MAX
}cellular_state_enum_type;

typedef enum{
    CELLULAR_TYPE_MIN     = 0,
    CELLULAR_TYPE_UNKNOWN = CELLULAR_TYPE_MIN,
    CELLULAR_TYPE_USB     = 1,
    CELLULAR_TYPE_PCIE    = 2,
    CELLULAR_TYPE_MAX
}cellular_type_enum_type;

typedef enum
{
    SEQ_INPUT      =  0,
    SEQ_OUTPUT     =  1,
    HELPERM_INPUT  = SEQ_INPUT,
    HELPERM_OUTPUT = SEQ_OUTPUT,
    HELPERD_INPUT  = SEQ_OUTPUT,
    HELPERD_OUTPUT = SEQ_INPUT
}queue_enum_type;

typedef enum
{
    MSG_ALL     =  0,
    MSG_NORMAL  =  1,
    MSG_CONTROL =  2
}seq_message_enum_type;

typedef enum
{
    OP_MIN     =  0,
    OP_READ    =  OP_MIN,
    OP_WRITE   =  1,
    OP_MAX     =  OP_WRITE
}at_operate_enum_type;

#define FIBOCOM_MODULE_NAME_LEN          16  // max size like "FM101R-GL-00-30"
#define FIBOCOM_MODULE_USBID_LEN         10  // max size like "2cb7:01a2"
#define FIBOCOM_MODULE_PCIEID_LEN        20  // max size like "aaaa.bbbb.cccc.dddd"
#define FIBOCOM_MODULE_PCIESSVID_LEN     5   // max size like "0d40"
#define FIBOCOM_MODULE_PCIESSDID_LEN     5   // max size like "4d75"
#define FIBOCOM_MODULE_MBIMPORT_LEN      16  // max size like "/dev/wwan0mbim0"
#define FIBOCOM_MODULE_DLPORT_LEN        16  // max size like "/dev/wwan0mbim0"
#define FIBOCOM_MODULE_ATPORT_LEN        14  // max size like "/dev/wwan0at1"
#define DEFAULT_TIMEOUT                  3

typedef struct
{
    cellular_state_enum_type cellular_state;
    cellular_type_enum_type  cellular_type;
    gchar                     work_module_name[FIBOCOM_MODULE_NAME_LEN];
    gint                     module_info_index;
} fibocom_cellular_type;

typedef struct
{
    gchar module_name[FIBOCOM_MODULE_NAME_LEN];
    gchar module_type;
    gchar usbsubsysid[FIBOCOM_MODULE_USBID_LEN];
    gchar pciessvid[FIBOCOM_MODULE_PCIESSVID_LEN];
    gchar pciessdid[FIBOCOM_MODULE_PCIESSDID_LEN];
    gchar mbimportname[FIBOCOM_MODULE_MBIMPORT_LEN];
    gchar dlportname[FIBOCOM_MODULE_DLPORT_LEN];
    gchar atportname[FIBOCOM_MODULE_ATPORT_LEN];
} Fibocom_module_info_type;

typedef struct
{
    gint                   serviceid;
    gint                   cid;
    FibocomGdbusHelper     *skeleton;
    GDBusMethodInvocation  *invocation;
}async_user_data_type;

typedef struct
{
    long   mtype;     // should be seq_message_type.
    char   mtext[0];  // should be fibo_async_struct_type.
}helper_message_struct;

void     fibo_adapter_trigger_app_exit(void);
gint     fibo_adapter_alloc_and_send_resp_structure(gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str);
void     fibo_adapter_mutex_sim_insert_flag_operate_lock(void);
void     fibo_adapter_mutex_sim_insert_flag_operate_unlock(void);
void     fibo_adapter_mutex_mbim_flag_operate_unlock(void);
void     fibo_adapter_mutex_mbim_flag_operate_lock(void);
void     fibo_adapter_mutex_keep_pointer_exist_unlock(void);
void     fibo_adapter_mutex_keep_pointer_exist_lock(void);
void     fibo_adapter_mutex_cellular_info_operate_unlock(void);
void     fibo_adapter_mutex_cellular_info_operate_lock(void);
void     fibo_adapter_mutex_force_sync_unlock(void);
void     fibo_adapter_mutex_force_sync_lock(void);
gint     fibo_adapter_all_mutex_init(void);
gint     fibo_adapter_helperm_send_control_message_to_helperd(int cid, int payloadlen, char *payload_str);
gint     fibo_adapter_helperd_send_control_message_to_helperm(int cid, int payloadlen, char *payload_str);
void     fibo_adapter_helperd_send_resp_to_dbus(FibocomGdbusHelper *skeleton, GDBusMethodInvocation *invocation, gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str);
gint     fibo_adapter_get_supported_module_number(void);
gint     fibo_adapter_get_supported_module_info(Fibocom_module_info_type *module_info, gint index);
gint     fibo_adapter_get_work_cellular_info(fibocom_cellular_type *work_cellular_info);
gint     fibo_adapter_set_work_cellular_info(fibocom_cellular_type *work_cellular_info);
gint     fibo_adapter_set_linux_app_signals(void);
gint     fibo_adapter_send_message_async(void *message, guint32 len, guint32 timeout, GAsyncReadyCallback callback, gpointer user_data);
void     fibo_adapter_udev_deinit(void);
gint     fibo_adapter_udev_init(gint cellular_type, gint *output_fd);
gint     fibo_adapter_check_cellular(gint *check_result);
void     fibo_adapter_mbim_port_deinit(void);
void     fibo_adapter_mbim_port_init(char *mbimportname);
void     fibo_adapter_control_mbim_init(void);
void     fibo_adapter_device_Check(gpointer user_data);

gint     fibo_adapter_helperm_get_normal_msg_from_helperd(void *msgs);
gint     fibo_adapter_helperm_get_control_msg_from_helperd(void *msgs);
gint     fibo_adapter_helperm_send_msg_to_helperd(void *msgs, int msgsize);
gint     fibo_adapter_helperd_get_control_msg_from_helperm(void *msgs);
gint     fibo_adapter_helperd_get_normal_msg_from_helperm(void *msgs);
gint     fibo_adapter_helperd_send_req_to_helperm(void *msgs, int msgsize);
gint     fibo_adapter_get_helper_seq_id(int seq);
gint     fibo_adapter_helper_queue_init(void);
gint     fibo_adapter_helperd_timer_handle(void);
gint     fibo_adapter_helperd_timer_close(void);
void     fibo_adapter_helperm_control_get_local_mccmnc_ready (MbimDevice *device, GAsyncResult *res, gpointer userdata);
gint     fibo_adapter_helperm_get_local_mccmnc(GAsyncReadyCallback func_pointer, gpointer userdata);
void     fibo_adapter_helperm_control_get_network_mccmnc_ready (MbimDevice *device, GAsyncResult *res, gpointer userdata);
gint     fibo_adapter_helperm_get_network_mccmnc(GAsyncReadyCallback func_pointer, gpointer userdata);
void     fibo_adapter_helperm_deinit_get_subscriber_ready_status_ready (MbimDevice *device, GAsyncResult *res, gpointer userdata);
void     fibo_adapter_helperm_control_get_subscriber_ready_status_ready (MbimDevice *device, GAsyncResult *res, gpointer userdata);
gint     fibo_adapter_helperm_get_subscriber_ready_status(GAsyncReadyCallback func_pointer, gpointer userdata);
gint     fibo_adapter_helperm_get_work_slot_info(GAsyncReadyCallback func_pointer, gpointer userdata);
gint     fibo_adapter_helperm_switch_work_slot(GAsyncReadyCallback func_pointer, gpointer userdata);
int      fibo_adapter_send_at_command(const char *req_cmd, char *rspbuf, const char *mbimportname);

#endif /* _FIBO_HELPER_ADAPTER_H_ */
