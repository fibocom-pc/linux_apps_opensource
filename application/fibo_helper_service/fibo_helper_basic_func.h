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
#include <stdbool.h>
#include "libmbim-glib.h"
#include "fibo_helper_common.h"

#define RDONLY                           "r"
#define WRONLY                           "w"

#define FIRMWARE_PATH "/etc/opt/fibocom/fibo_fw_pkg/FwPackage/"
#define RECOVERY_PKG_PATH "/etc/opt/fibocom/fibo_fw_pkg/FwPackage/Maincode/"
#define RECOVERY_FLASHING "flashing..."
#define RECOVERY_FLASH_OK "flash ok"
#define RECOVERY_FLASH_FAIL "flash fail"

typedef struct
{
    e_command_cid       cid;
    gint                 (*func_pointer)(gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str, gpointer callback, gchar *req_cmd);
    gpointer            callback;
    gchar                *at_amd;
}fibocom_request_table_type;

/*progress*/
//枚举元素的命名不能随意更改，需要和DISTRIB_ID完全一致
enum CurrentDistibId {
    None = 0,
    Ubuntu,
    Thinpro,
    Fedora,
};
typedef struct Progress Progress;
// 父类结构体
struct Progress {
    int progressWidth;
    int progressHeight;
    FILE * progressFd;
    FILE * progressCloseFd;

    char progressType[32];
    char progressSchedule[32];
    char progressId[32];
    char progressTitle[64];
    char progressText[256];
    char environmentVariable[256];
    char progressCmd[1024];
    char progressCloseCmd[512];

    // 父类方法指针
    // 获取环境变量
    int (*fibocom_get_progress_environment_variable)(Progress *self);
    // 执行进度条命令
    int (*fibocom_start_progress)(Progress *self);
    // 更新进度条标题
    int (*fibocom_set_progress_title)(Progress *self, const char* title);
    // 初始进度条内容
    int (*fibocom_set_progress_init_text)(Progress *self);
    // 更新进度条内容
    int (*fibocom_set_progress_text)(Progress *self, const char* text);
    // 更新进度条进度
    int (*fibocom_set_progress_schedule)(Progress *self, int schedule);
    // 刷新进度条
    int (*fibocom_refresh_progress)(Progress *progress, const char *text, int schedule);
    // 关闭当前进度条
    int (*fibocom_close_progress)(Progress *self);
};

/*end of progress*/

#define ICCID_LENGTH 20 // ICCID length is 20 characters
#define MAX_PROFILE_NUM 20
typedef enum {
    TEST_PROFILE = 0,
    NORMAL,
} PROFILE_TYPE;

typedef struct 
{
    char profile_id[ICCID_LENGTH + 1]; // ICCID length is 20, plus null terminator
    bool status; // true:active, false:inactive
    PROFILE_TYPE type; // TEST_PROFILE or NORMAL
    int retry_times;
}profile_status;

typedef struct profile_stack_
{
    profile_status profiles[MAX_PROFILE_NUM]; // Array to hold up to 20 profiles
    int profile_top;
    bool (*func)(fibo_async_struct_type *user_data, struct profile_stack_ *profile);
    int ret;
    int channel_id;
}profile_obj;


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

gint     fibo_parse_sw_reboot(gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str, gpointer callback, gchar *req_cmd);
void     fibo_helperm_get_network_mccmnc_ready (MbimDevice *device, GAsyncResult *res, gpointer userdata);
void     fibo_helperm_get_local_mccmnc_ready (MbimDevice *device, GAsyncResult *res, gpointer userdata);
void     fibo_helperm_get_work_slot_id_ready (MbimDevice *device, GAsyncResult *res, gpointer userdata);
gint     fibo_parse_mbim_request(gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str, gpointer callback, char *req_cmd);

void     fibo_resp_error_result_callback(MbimDevice *device, GAsyncResult *res, gpointer serviceid);
gint     fibo_resp_error_result(gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str, gpointer callback, gchar * req_cmd);

gint     fibo_parse_send_atcmd_ready(MbimDevice *device, GAsyncResult *res, gpointer user_data);
gint     fibo_parse_send_req_atcmd(gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str, gpointer callback, gchar *req_cmd);
gint     fibo_parse_send_set_atcmd(gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str, gpointer callback, gchar *req_cmd);
gint     fibo_parse_get_fw_info(gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str, gpointer callback, gchar *req_cmd);
gint     fibo_parse_get_fcc_status_ready(MbimDevice *device, GAsyncResult *res, gpointer user_data);
gint     fibocom_get_port_command_ready (gchar   *resp_str);
gint     fibocom_get_subsysid_ready(MbimDevice *device, GAsyncResult *res, gpointer user_data);
gint     fibocom_edl_flash_ready(MbimDevice *device, GAsyncResult *res, gpointer userdata);
gpointer fibocom_qdl_flash_command(gpointer payload, int *qdl_success_flag);
gpointer edl_flashing_command(void *data);

gint fibo_delete_test_profile(gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str, gpointer callback, char *req_cmd);
gpointer fibocom_fastboot_flash_command(gpointer payload, int *fastboot_success_flag);
gpointer fastboot_flashing_command(void *data);
gint     fibocom_fastboot_flash_ready(MbimDevice *device, GAsyncResult *res, gpointer userdata);
int fibocom_hwreset_gpio_init(void);

#endif /* _FIBO_HELPER_BASIC_FUNC_H_ */

