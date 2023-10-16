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
 * @file fibo_helper_basic_func.h
 * @author rick.chen@fibocom.com (chenhaotian)
 * @brief
 * @version 1.0
 * @date 2023-09-23
 *
 *
 **/

#ifndef _FIBO_HELPER_BASIC_FUNC_H_
#define _FIBO_HELPER_BASIC_FUNC_H_

#include <glib.h>
#include <gio/gio.h>
#include <libudev.h>
#include "libmbim-glib.h"
#include "fibo_helper_common.h"

typedef struct
{
    e_command_cid       cid;
    gint                 (*func_pointer)(gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str, gpointer callback, gchar *req_cmd);
    gpointer            callback;
    gchar                *at_amd;
}fibocom_request_table_type;

void     fibo_helper_control_message_receiver(void);
gint     alloc_and_send_resp_structure(gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str);
void     fibo_mutex_keep_pointer_exist_unlock(void);
void     fibo_mutex_keep_pointer_exist_lock(void);
void     fibo_mutex_modem_info_unlock(void);
void     fibo_mutex_modem_info_lock(void);
void     fibo_mutex_force_sync_unlock(void);
void     fibo_mutex_force_sync_lock(void);
gint     fibo_mutex_init(void);
void     request_receiver(void);
gint     fibo_get_supported_module_number(void);
gint     fibo_get_supported_module_info(void *module_info, gint index);
void     fibo_register_module_event_signal(void);
void     fibo_helper_device_check(void);
gint     fibo_helper_mmevent_register(void);
void     fibo_helper_main_receiver(void);
void     fibo_helper_control_receiver(void);
gint     fibo_register_helper_service(void);
gint     fibo_set_linux_app_signals(void);
void     fibo_udev_deinit(void);
void     fibo_mbim_port_deinit(void);
gint     fibo_get_helper_seq_id(gint seq);
gint     fibo_helper_queue_init(void);

gint     fibo_prase_sw_reboot(gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str, gpointer callback, gchar *req_cmd);
void     fibo_prase_get_ap_version_ready(MbimDevice *device, GAsyncResult *res, gpointer serviceid);
gint     fibo_prase_get_ap_version(gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str, gpointer callback, gchar *req_cmd);

void     fibo_resp_error_result_callback(MbimDevice *device, GAsyncResult *res, gpointer serviceid);
gint     fibo_resp_error_result(gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str, gpointer callback, gchar * req_cmd);

gint     fibo_prase_send_atcmd_ready(MbimDevice *device, GAsyncResult *res, gpointer user_data);
gint     fibo_prase_send_req_atcmd(gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str, gpointer callback, gchar *req_cmd);
gint     fibo_prase_send_set_atcmd(gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str, gpointer callback, gchar *req_cmd);
gint     fibo_prase_get_fw_info(gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str, gpointer callback, gchar *req_cmd);
gint     fibo_prase_get_fcc_status_ready(MbimDevice *device, GAsyncResult *res, gpointer user_data);
gint     fibocom_get_port_command_ready (gchar   *resp_str);
gint     fibocom_get_subsysid_ready(MbimDevice *device, GAsyncResult *res, gpointer user_data);
gint     fibocom_edl_flash_ready(MbimDevice *device, GAsyncResult *res, gpointer userdata);
gpointer fibocom_qdl_flash_command(gpointer payload);
gpointer edl_flashing_command(void *data);

gpointer fibocom_fastboot_flash_command(gpointer payload, int *fastboot_success_flag);
gpointer fastboot_flashing_command(void *data);
gint     fibocom_fastboot_flash_ready(MbimDevice *device, GAsyncResult *res, gpointer userdata);
int fibocom_hwreset_gpio_init(void);

#endif /* _FIBO_HELPER_BASIC_FUNC_H_ */

