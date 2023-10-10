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
 * @file fibo_helper_basic_func.c
 * @author rick.chen@fibocom.com (chenhaotian)
 * @brief
 * @version 1.0
 * @date 2023-09-23
 *
 *
 **/

#include "fibo_helper_basic_func.h"
#include <glib.h>
#include "fibo_helper_adapter.h"
#include "fibo_helper_common.h"
#include <libmm-glib.h>

fibocom_request_table_type supported_request_table[] = {

    {RESET_MODEM_SW,           fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,   fibo_prase_send_atcmd_ready,    "AT+CFUN=15"},
    {CTL_MBIM_INIT,            fibo_resp_error_result,       ASYNC_FUNCTION,   NULL,                           ""},
    {CTL_MBIM_DEINIT,          fibo_resp_error_result,       ASYNC_FUNCTION,   NULL,                           ""},
    {CTL_MBIM_NO_RESP,         fibo_resp_error_result,       ASYNC_FUNCTION,   NULL,                           ""},

    /* FWswitch service command list */
    {GET_AP_VERSION,           fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+GTSAPFWVER?"},
    {GET_MD_VERSION,           fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+CGMR"},
    {GET_OP_VERSION,           fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+GTCUSTPACKVER?"},
    {GET_OEM_VERSION,          fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+GTCFGELEMVER?"},
    {GET_DEV_VERSION,          fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+GTDEVPACKVER?"},
    {GET_IMEI,                 fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+CGSN"},
    {GET_MCCMNC,               fibo_resp_error_result,       ASYNC_FUNCTION,  NULL,                           ""},
    {GET_SUBSYSID,             fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibocom_get_subsysid_ready,     "AT"},
    {SET_ATTACH_APN,           fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  NULL,                           ""},
    {FLASH_FW_FASTBOOT,        fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibocom_fastboot_flash_ready,  "at+syscmd=sys_reboot bootloader"},

    /* FWrecovery service command list */
    //{GET_PORT_STATE,           fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibocom_get_port_command_ready, "AT"},
    {GET_OEM_ID,               fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+GTOEMUSBID?"},
    {RESET_MODEM_HW,           fibo_resp_error_result,       ASYNC_FUNCTION,  NULL,                           ""},
    {FLASH_FW_EDL,             fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibocom_edl_flash_ready,        "at+syscmd=sys_reboot edl"},

    /* MA service command list */
    {GET_FCCLOCK_STATUS,       fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+GTFCCEFFSTATUS?"},
    {GET_MODEM_RANDOM_KEY,     fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+GTFCCLOCKGEN"},
    {SET_FCC_UNLOCK,           fibo_prase_send_set_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+GTFCCLOCKVER="},

    /* config service command list */
    {SET_BODYSAR_ENABLE,       fibo_prase_send_set_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+BODYSAREN="},
    {GET_BODYSAR_STATUS,       fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+BODYSAREN?"},
    {GET_BODYSAR_CTRL_MODE,    fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+BODYSARMODE?"},
    {SET_BODYSAR_CTRL_MODE,    fibo_prase_send_set_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+BODYSARMODE="},
    {SET_BODYSAR_INDEX,        fibo_prase_send_set_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+BODYSARON=1,"},
    {SET_BODYSAR_CFG_DATA,     fibo_resp_error_result,       ASYNC_FUNCTION,  NULL,                           "AT+BODYSARCFG="},
    {SET_BODYSAR_VER,          fibo_prase_send_set_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+BODYSARVER="},
    {GET_BODYSAR_VER,          fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+BODYSARVER?"},
    {SET_ANTENNA_ENABLE,       fibo_prase_send_set_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+GTANTTUNINGEN="},
    {GET_ANTENNA_STATUS,       fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+GTANTTUNINGEN?"},
    {SET_ANTENNA_CTRL_MODE,    fibo_prase_send_set_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+GTANTCTRLMODE="},
    {GET_ANTENNA_CTRL_MODE,    fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+GTANTCTRLMODE?"},
    {SET_ANTENNA_WORK_MODE,    fibo_prase_send_set_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+GTANTTUNEMODE="},
    {GET_ANTENNA_WORK_MODE,    fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+GTANTTUNEMODE?"},
    {SET_ANTENNA_VER,          fibo_prase_send_set_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+GTANTVER="},
    {GET_ANTENNA_VER,          fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+GTANTVER?"},
    {SET_ANTENNA_INDEX,        fibo_prase_send_set_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+GTANTPROFILE="},
    {SET_FCCLOCK_ENABLE,       fibo_prase_send_set_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+GTFCCLOCKMODE="},
    {GET_NET_WORK_TYPE,        fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    ""},
    {SET_WDISABLE_ENABLE,      fibo_prase_send_set_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+GTFMODE="},
    {GET_WDISABLE_STATUS,      fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+GTFMODE?"},
    {SET_GNSS_ENABLE,          fibo_prase_send_set_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+GTGPSPOWER="},
    {GET_GNSS_STATUS,          fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+GTGPSPOWER?"},
    {GET_DISABLE_ESIM_STATUS,  fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+GTESIMCFG?"},
    {SET_DISABLE_ESIM,         fibo_prase_send_set_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "AT+GTESIMCFG="},
    {GET_FW_INFO,              fibo_prase_send_req_atcmd,    ASYNC_FUNCTION,  fibo_prase_send_atcmd_ready,    "ATI7"},
    /* config service list is not finished. */

    {ENUM_CID_MAX,             fibo_resp_error_result,       SYNC_FUNCTION,   NULL,                           ""}
};

/* 全局变量 */
FibocomGdbusHelper     *skeleton           = NULL;
extern GMainLoop       *gMainLoop;
extern gboolean        g_table_check_flag;
gboolean               g_data_updated      = FALSE;
fibo_async_struct_type *user_data1         = NULL;
FibocomGdbusHelper     *g_skeleton         = NULL;
static MMManager       *proxy              = NULL;
gchar                  g_local_mccmnc[8]   = {0};
gchar                  g_roam_mccmnc[8]    = {0};
static gboolean        g_sim_inserted_flag = FALSE;

typedef struct {
    char                *moudle;
    char                *vidpid;
}Support_Usbvidpid;

Support_Usbvidpid support_usbvidpid[]= {
        {"FM101-GL-00","2cb7:01a2"},
        {"FM101-GL-00","2cb7:01a3"},
        {"FM101-GL-00","2cb7:01a4"},
        {"FM101-GL-00","413c:8211"},
        {"FM101-GL-00","413c:8209"},
        {"FM101-GL-00","413c:8213"},
        {"FM101-GL-00","413c:8215"},
};


/*--------------------------------------Below are Internal Funcs-------------------------------------------------------*/

static gint
request_analyzer(fibo_async_struct_type *user_data)
{
    gint     serviceid      =  0;
    gint     cid            =  0;
    gint     rtcode         =  RET_ERR_PROCESS;
    gint     payloadlen     =  0;
    gchar    *payload_str   =  NULL;
    gint     table_len      =  RET_ERROR;
    gint     i              =  RET_ERROR;
    gboolean matched_flag   =  FALSE;
    gint     ret            =  RET_ERROR;

    serviceid = user_data->serviceid;
    cid = user_data->cid;
    rtcode = user_data->rtcode;
    payloadlen = user_data->payloadlen;
    payload_str = user_data->payload_str;

    FIBO_LOG_DEBUG("serviceid: %d\n", serviceid);
    FIBO_LOG_DEBUG("cid: 0x%04x\n", cid);
    FIBO_LOG_DEBUG("recode: %d\n", rtcode);
    FIBO_LOG_DEBUG("len: %d\n", payloadlen);
    FIBO_LOG_DEBUG("str: \"%s\"\n", payload_str);

    table_len = sizeof(supported_request_table) / sizeof(fibocom_request_table_type);

    for (i = 0; i < table_len; i++) {
        if (supported_request_table[i].cid == cid) {
            matched_flag = TRUE;
            if (supported_request_table[i].func_type == ASYNC_FUNCTION) {
                ret = supported_request_table[i].func_pointer(serviceid, cid, rtcode, payloadlen, payload_str, supported_request_table[i].callback, supported_request_table[i].at_amd);
            }
            else {
                // sub_thread = g_thread_new ("sync_analyzer", (GThreadFunc)sync_func_analyzer, str);
                FIBO_LOG_ERROR("Dont support AT over GNSS now!\n");
            }
            break;
        }
    }

    if (ret != RET_OK || !matched_flag) {
        FIBO_LOG_ERROR("Execute error or not matched! will call default resp!\n");
        // supported_request_table[table_len - 1].func_pointer(serviceid, cid, rtcode, payloadlen, payload_str, NULL, NULL);
        fibo_resp_error_result(serviceid, cid, rtcode, payloadlen, payload_str, NULL, NULL);
        return RET_ERROR;
    }

    FIBO_LOG_DEBUG("finished!\n");
    return RET_OK;
}

static gint
request_transmiter(FibocomGdbusHelper     *skeleton,
                      GDBusMethodInvocation  *invocation,
                      GVariant               *str)
{
    int                    ret          = RET_ERROR;
    helper_message_struct  *msgs        = NULL;
    fibo_async_struct_type *user_data   = NULL;

    gint                  serviceid    = RET_ERROR;
    gint                  cid          = RET_ERROR;
    gint                  rtcode       = RET_ERROR;
    gint                  payloadlen   = 0;
    gchar                 *payload_str = NULL;
    GVariant              *resp_str    = NULL;

    FIBO_LOG_DEBUG("enter! helper get request! req struct size: %ld\n", sizeof(fibo_async_struct_type));

    g_variant_get(str, "((ii)iis)", &serviceid, &cid, &rtcode, &payloadlen, &payload_str);

    user_data = (fibo_async_struct_type *)malloc(sizeof(fibo_async_struct_type) + payloadlen + 1);
    if (user_data == NULL)
    {
        FIBO_LOG_ERROR("malloc failed!\n");
        rtcode = RET_ERROR;
        fibo_adapter_send_async_resp_to_dbus(skeleton, g_object_ref(invocation), serviceid, cid, rtcode, payloadlen, payload_str);
        return RET_ERROR;
    }

    memset(user_data, 0, sizeof(fibo_async_struct_type) + payloadlen + 1);

    if (payloadlen == 0) {
        user_data->payloadlen  = 0;
        user_data->payload_str[0] = 0;
    }
    else {
        user_data->payloadlen  = payloadlen;
        memcpy(user_data->payload_str, payload_str, payloadlen);
    }

    user_data->serviceid   = serviceid;
    user_data->cid         = cid;
    user_data->rtcode      = rtcode;

    if(user_data->cid == GET_PORT_STATE)
    {
        char *resp_str = NULL;
        resp_str = (char*)malloc(sizeof(char)*16);
        memset(resp_str ,0 ,16);
        fibocom_get_port_command_ready(resp_str);
        payloadlen = strlen(resp_str);
        fibo_adapter_send_async_resp_to_dbus(skeleton, g_object_ref(invocation), user_data->serviceid, user_data->cid, user_data->rtcode,payloadlen, resp_str);
        if(resp_str) {
            free(resp_str);
        }
        return RET_OK;
    }

    if(user_data->cid == GET_MCCMNC)
    {
        payload_str = g_local_mccmnc;
        payloadlen = strlen(payload_str);
        g_print("%s   %d",payload_str,__LINE__);
        fibo_adapter_send_async_resp_to_dbus(skeleton, g_object_ref(invocation), user_data->serviceid, user_data->cid, user_data->rtcode,payloadlen, payload_str);
        return RET_OK;
    }

    if(user_data->cid == FLASH_FW_EDL)
    {
        char *resp_str = "edl flashing";
        char *payload  = NULL;

        payloadlen = strlen(resp_str);
        resp_str   = (char*)malloc(sizeof(char) * 16);

        memset(resp_str, 0, 16);
        fibocom_get_port_command_ready(resp_str);
        if (strstr(resp_str,"normalport") == NULL) {
            char *resp_str = NULL;
            GThread *gthread_edl_flash = NULL;
            gthread_edl_flash = g_thread_new("edl_flash", edl_flashing_command, payload);
            fibo_adapter_send_async_resp_to_dbus(skeleton, g_object_ref(invocation), serviceid, cid, rtcode, payloadlen, resp_str);
            return RET_OK;
        }
    }
/*
    if(user_data->cid == FLASH_FW_FASTBOOT)
    {
        GThread *gthread_fastboot_monitor = NULL;
        gthread_fastboot_monitor = g_thread_new("fibo_fastboot_monitor_msg", fibo_fastboot_monitor_msg, NULL);
    }
*/
    msgs = (helper_message_struct *)malloc(2048 * sizeof(char));
    if (msgs == NULL)
    {
        FIBO_LOG_ERROR("malloc failed!\n");
        rtcode = RET_ERROR;
        fibo_adapter_send_async_resp_to_dbus(skeleton, g_object_ref(invocation), serviceid, cid, rtcode, payloadlen, payload_str);
        return RET_ERROR;
    }
    memset(msgs, 0, 2048);

    memcpy(msgs->mtext, user_data, sizeof(fibo_async_struct_type) + payloadlen);
    msgs->mtype = 1;

    ret = fibo_adapter_send_req_to_mbim(msgs, 2048);
    if (ret != RET_OK) {

        FIBO_LOG_ERROR("Send message failed!\n");
        free(msgs);
        msgs = NULL;

        // if msgsnd func return error, will trigger a default resp func to caller.
        rtcode = RET_ERROR;
        fibo_adapter_send_async_resp_to_dbus(skeleton, g_object_ref(invocation), serviceid, cid, rtcode, payloadlen, payload_str);
        return RET_ERROR;
    }

    memset(msgs, 0, 2048);

    free(user_data);
    user_data = NULL;

    ret = fibo_adapter_get_normal_resp_from_mbim(msgs);
    if (RET_ERROR == ret)
    {
        FIBO_LOG_DEBUG("Get message failed!\n");
        free(msgs);
        msgs = NULL;

        // if msgrcv func return error, will trigger a default resp func to caller.
        rtcode = RET_ERROR;
        fibo_adapter_send_async_resp_to_dbus(skeleton, g_object_ref(invocation), serviceid, cid, rtcode, payloadlen, payload_str);
        return RET_ERROR;
    }

    user_data = (fibo_async_struct_type *)msgs->mtext;

    FIBO_LOG_DEBUG("len:%d\n", user_data->payloadlen);

    fibo_adapter_send_async_resp_to_dbus(skeleton, g_object_ref(invocation), user_data->serviceid, user_data->cid, user_data->rtcode, user_data->payloadlen, user_data->payload_str);

    free(msgs);
    msgs = NULL;
    user_data = NULL;

    FIBO_LOG_DEBUG("Helper send resp!\n");
    return RET_OK;

}

/**
 * 连接上bus daemon的回调
 **/
static void
bus_acquired (GDBusConnection *connection,
              const gchar     *name,
              gpointer        user_data)
{
    FIBO_LOG_DEBUG("Enter! name is %s\n", name);

    if (!connection || !name) {
        FIBO_LOG_ERROR("NULL pointer! wont register any signal!\n");
        return;
    }

    return;
}

/**
 * 成功注册busName的回调
 **/
static void
bus_name_acquired (GDBusConnection *connection,
                   const gchar     *name,
                   gpointer        user_data)
{
    FIBO_LOG_DEBUG("Enter!\n");
    if (!connection || !name) {
        FIBO_LOG_ERROR("NULL pointer! wont register any signal!\n");
        return;
    }

    GError             *error             = NULL;
    GThread            *receive_thread    = NULL;
    // FibocomGdbusHelper *skeleton          = NULL;

    g_skeleton = fibocom_gdbus_helper_skeleton_new();

    // main loop will send message to message queue and wait for return value, so main loop will be blocked.
    g_signal_connect(g_skeleton, "handle-send-mesg", G_CALLBACK(request_transmiter), NULL);

    g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(g_skeleton), connection, "/com/fibocom/helper", &error);
    if (error != NULL) {
        FIBO_LOG_ERROR("Error: Failed to export object. Reason: %s.\n", error->message);
        g_error_free(error);
    }

    return;
}

/**
 * busName丢失的回调，一般是server挂了？？
 **/
static void
bus_name_lost (GDBusConnection *connection,const gchar *name,gpointer user_data)
{
    FIBO_LOG_ERROR("bus_name_lost !!!!\n");
    return;
}

static void owner_name_change_notify_cb(GObject *object, GParamSpec *pspec, gpointer userdata)
{
    gchar *pname_owner = NULL;

    FIBO_LOG_DEBUG("enter!\n");

    pname_owner = g_dbus_proxy_get_name_owner((GDBusProxy *)object);
    if (NULL != pname_owner)
    {
        FIBO_LOG_DEBUG("modemmanager service is ready!\n");
        g_free(pname_owner);
    }
    else
    {
        FIBO_LOG_DEBUG("modemmanager service is disconnect!\n");
        g_free(pname_owner);
    }
}

static void scan_ready (MMModem3gpp  *modem_3gpp,
                        GAsyncResult *result)
{
    GList       *operation_result  = NULL;
    GError      *error             = NULL;
    const gchar *mcc_mnc           = NULL;
    const gchar *availability      = NULL;
    static int  cnt                = 0;
    GList       *l                 = NULL;

    FIBO_LOG_DEBUG("enter!\n");

    operation_result = mm_modem_3gpp_scan_finish (modem_3gpp, result, &error);
    if (!operation_result || error != NULL) {
        FIBO_LOG_ERROR("check network access failed! error:%s\n", error->message);
        if (modem_3gpp)
            g_object_unref (modem_3gpp);
        return;
    }

    if (operation_result)
        for (l = operation_result; l; l = g_list_next (l))
        {
            mcc_mnc = mm_modem_3gpp_network_get_operator_code ((MMModem3gppNetwork *)(l->data));
            if (NULL != mcc_mnc)
            {
                availability = mm_modem_3gpp_network_availability_get_string (mm_modem_3gpp_network_get_availability ((MMModem3gppNetwork *)(l->data)));

                if (0 == strncmp(availability,"current",strlen("current")))
                {
                    printf("get network operator code ok, mccmnc = %s\n", mcc_mnc);
                    break;
                }
                mcc_mnc = NULL;
            }
        }

    if (NULL == mcc_mnc)
    {
        FIBO_LOG_ERROR("Dont get current network mccmnc!\n");
        g_list_free_full (operation_result, (GDestroyNotify) mm_modem_3gpp_network_free);
        if (modem_3gpp)
            g_object_unref (modem_3gpp);
        return;
    }

    if (0 != strcmp(g_roam_mccmnc,mcc_mnc) && strlen(mcc_mnc) > 0)
    {
        // further: add mutex to control.
        strncpy(g_roam_mccmnc, mcc_mnc, strlen(mcc_mnc));

        fibocom_gdbus_helper_emit_roam_region(g_skeleton, "roaming region changed!");

        FIBO_LOG_DEBUG("network mcc changed, new mccmnc:%s ..\n", mcc_mnc);
    }
END:
    g_list_free_full (operation_result, (GDestroyNotify) mm_modem_3gpp_network_free);
    if (modem_3gpp)
        g_object_unref (modem_3gpp);
    return;
}

static void mm_plugin_object_added_cb(MMManager *manager, MMObject *gmodem_object)
{
    MMSim       *sim_obj     = NULL;
    GError      *error       = NULL;
    MMModem     *modem       = NULL;
    const gchar *mccmnc_id   = NULL;
    MMModem3gpp * modem_3gpp = NULL;

    FIBO_LOG_DEBUG("enter!\n");

    // although object add event will be triggered on module insert and sim card insert, we dont deal with modem insert cause modemmanager will get modem firstly and get sim card secondly!
    if (NULL == gmodem_object)
    {
        printf("cant get modem object, so consider no change on SIM card!\n");
        return;
    }

    // if local mccmnc changed, emit local mccmnc change signal.
    modem = mm_object_peek_modem(gmodem_object);

    // step1: verify whether sim card is inserted.
    sim_obj = mm_modem_get_sim_sync(modem, NULL, &error);
    if (NULL == sim_obj)
    {
        FIBO_LOG_ERROR("Dont find sim card!\n");
        return;
    }

    FIBO_LOG_ERROR("SIM card inserted!\n");

    fibo_adapter_mutex_sim_insert_flag_operate_lock();
    g_sim_inserted_flag = TRUE;
    fibo_adapter_mutex_sim_insert_flag_operate_unlock();

    if (g_skeleton != NULL)
        fibocom_gdbus_helper_emit_simcard_change(g_skeleton, "SIM CARD inserted!");
    else
        FIBO_LOG_ERROR("variable is NULL, dont send cellular info signal!\n");

    // step2: get sim card's mccmnc.
    mccmnc_id = mm_sim_get_operator_identifier(sim_obj);
    if (NULL == mccmnc_id)
    {
        FIBO_LOG_ERROR("mccmnc is NULL!\n");
        g_object_unref(sim_obj);
        return;
    }

    FIBO_LOG_ERROR("get valid mccmnc: %s\n", mccmnc_id);
    if (strcmp(g_local_mccmnc, mccmnc_id) != 0) {
        FIBO_LOG_DEBUG("local mccmnc changed from %s to %s\n", g_local_mccmnc, mccmnc_id);
        strncpy(g_local_mccmnc, mccmnc_id, strlen(mccmnc_id));

        if (g_skeleton != NULL)
            fibocom_gdbus_helper_emit_simcard_change(g_skeleton, "local mccmnc changed!");
        else
            FIBO_LOG_ERROR("variable is NULL, dont send cellular info signal!\n");
    }
    g_object_unref(sim_obj);

// further: this callback will be executed by mainloop, so that it cant blocked or wait! should use sync func to query network mccmnc!
/*
    // step3: get roaming area mccmnc.
    modem_3gpp =  mm_object_get_modem_3gpp(gmodem_object);
    if (modem_3gpp)
    {
        g_dbus_proxy_set_default_timeout (G_DBUS_PROXY (modem_3gpp), 30 * 1000);
    }
    else
    {
        printf("error: modem has no 3GPP capabilities\n");
        return;
    }

    //  wait modem status >= MM_MODEM_STATE_ENABLED
    sleep(10);

    mm_modem_3gpp_scan(modem_3gpp, NULL, (GAsyncReadyCallback)scan_ready, NULL);
*/
    return;
}

static void mm_plugin_object_removed_cb(MMManager *manager, MMObject *modem)
{
    int ret = RET_ERROR;
    int res = RET_ERROR;

    FIBO_LOG_DEBUG("enter!\n");

    // object remove event will be triggered when either modem removed or SIM card removed.
    // steo1: check modem state.
    ret = fibo_adapter_check_cellular(&res);
    if (ret != RET_OK || res != RET_OK) {
        FIBO_LOG_ERROR("Found cellular missing, do nothing cause udev will send cellular state signal!\n");
        return;
    }

    // step2: check whether SIM card inserted before.
    if (!g_sim_inserted_flag) {
        FIBO_LOG_DEBUG("Dont find SIM card inserted before, invalid object remove event!\n");
        return;
    }

    fibo_adapter_mutex_sim_insert_flag_operate_lock();
    g_sim_inserted_flag = FALSE;
    fibo_adapter_mutex_sim_insert_flag_operate_unlock();

    FIBO_LOG_ERROR("SIM card removed!\n");
    // check module state firstly, if module exist, then report sim card remove, otherwise will do nothing.
    // if module power down immediately, SIM card and module will miss at same time, add logic to avoid SIM card remove signal!
    if (g_skeleton != NULL)
        fibocom_gdbus_helper_emit_simcard_change(g_skeleton, "SIM CARD removed!");
    else
        FIBO_LOG_ERROR("variable is NULL, dont send cellular info signal!\n");

    return;
}

static gboolean emit_edl_flash_status_signal(const char* p)
{
    FIBO_LOG_ERROR("emit_edl_flash_status_signal invoked\n");

    if(g_skeleton != NULL)
    {
        if(p == NULL)
        {
            FIBO_LOG_ERROR("[%s]:g_skeleton is NULL\n", __func__);
        }
        else
        {
            FIBO_LOG_ERROR("[%s]:flash changed!:%s\n", __func__, p);
            fibocom_gdbus_helper_emit_edl_status(g_skeleton,(const char*)p);
        }
    }
    FIBO_LOG_ERROR("[%s]:flash ====== changed!\n", __func__);
    return FALSE;
}

static gboolean emit_fastboot_flash_status_signal(const char* p)
{
    FIBO_LOG_ERROR("enter\n");
    if(g_skeleton != NULL)
    {
        if(p == NULL)
        {
            FIBO_LOG_ERROR("[%s]:g_skeleton is NULL\n", __func__);
        }
        else
        {
            FIBO_LOG_ERROR("[%s]:flash changed!:%s\n", __func__, p);
            fibocom_gdbus_helper_emit_fastboot_status(g_skeleton,(const char*)p);
        }
    }
    FIBO_LOG_ERROR("[%s]:flash ====== changed!\n", __func__);
    return FALSE;
}

static gpointer
fibo_fastboot_monitor_msg(void *data)
{
    int ret = 0;
    while(TRUE)
    {
        helper_message_struct *fastboot_monitor_msgs = NULL;
        fastboot_monitor_msgs = (helper_message_struct *)malloc(2048 * sizeof(char));
        if (fastboot_monitor_msgs == NULL)
        {
            FIBO_LOG_ERROR("malloc failed!");
            return NULL;
        }

        memset(fastboot_monitor_msgs, 0, 2048);

        fibo_async_struct_type *fastboot_monitor_user_data   = NULL;

        ret = fibo_adapter_get_control_req_from_mbim(fastboot_monitor_msgs);

        fastboot_monitor_user_data = (fibo_async_struct_type *)fastboot_monitor_msgs->mtext;

        if(fastboot_monitor_user_data->cid == FLASH_FW_FASTBOOT)
        {
            if(strstr(fastboot_monitor_user_data->payload_str,"fastboot flashing...") != NULL)
            {
                FIBO_LOG_DEBUG("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
                emit_fastboot_flash_status_signal("fastboot flashing...");
            }
            else if(strstr(fastboot_monitor_user_data->payload_str,"fastboot flashing ok") != NULL)
            {
                FIBO_LOG_DEBUG("--------------------------------------------------------------------\n");
                emit_fastboot_flash_status_signal("fastboot flashing ok");
            }
            else
            {
                FIBO_LOG_ERROR("malloc failed!");
            }
        }
    }
}

/*--------------------------------------Above are Internal Funcs-------------------------------------------------------*/

/*--------------------------------------Below are External Funcs-------------------------------------------------------*/

void
fibo_helper_control_message_receiver(void)
{
    int                    ret        = RET_ERROR;
    helper_message_struct  *msgs      = NULL;
    fibo_async_struct_type *user_data = NULL;

    msgs = (helper_message_struct *)malloc(2048 * sizeof(char));
    if (msgs == NULL) {
        FIBO_LOG_ERROR("malloc failed!");
        return;
    }

    while(TRUE)
    {
        memset(msgs, 0, 2048);
        user_data = NULL;

        ret = fibo_adapter_get_control_req_from_mbim(msgs);
        if (ret != RET_OK) {
            // FIBO_LOG_DEBUG("Get control message failed!\n");
            continue;
        }

        user_data = (fibo_async_struct_type *)msgs->mtext;

        switch (user_data->cid) {
            case FLASH_FW_FASTBOOT:
                if(strstr(user_data->payload_str, "fastboot flashing...") != NULL) {
                    FIBO_LOG_DEBUG("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
                    emit_fastboot_flash_status_signal("fastboot flashing...");
                }
                else if(strstr(user_data->payload_str, "fastboot flashing ok") != NULL) {
                    FIBO_LOG_DEBUG("--------------------------------------------------------------------\n");
                    emit_fastboot_flash_status_signal("fastboot flashing ok");
                }
                else
                    FIBO_LOG_ERROR("Invalid payload str!\n");
                break;
            case CTL_MBIM_NO_RESP:
                FIBO_LOG_ERROR("fibo-helper-mbim no resp at all! will remove message seq and exit dbus!\n");
                if (msgs) {
                    free(msgs);
                    msgs = NULL;
                    user_data = NULL;
                }
                fibo_adapter_trigger_app_exit();
                break;
            default:
                FIBO_LOG_DEBUG("Unsupported control message cid:0x%04x\n", user_data->cid);
        }
    }

    if (msgs) {
        free(msgs);
        msgs = NULL;
        user_data = NULL;
    }
    return;
}

gint
alloc_and_send_resp_structure(gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str)
{
    return fibo_adapter_alloc_and_send_resp_structure(serviceid, cid, rtcode, payloadlen, payload_str);
}

void
fibo_mutex_keep_pointer_exist_unlock(void)
{
    fibo_adapter_mutex_keep_pointer_exist_unlock();
    FIBO_LOG_DEBUG ("finished!\n");
}

void
fibo_mutex_keep_pointer_exist_lock(void)
{
    fibo_adapter_mutex_keep_pointer_exist_lock();
    FIBO_LOG_DEBUG ("finished!\n");
}
void
fibo_mutex_force_sync_unlock(void)
{
    fibo_adapter_mutex_force_sync_unlock();
    FIBO_LOG_DEBUG ("finished!\n");
}

void
fibo_mutex_force_sync_lock(void)
{
    fibo_adapter_mutex_force_sync_lock();
    FIBO_LOG_DEBUG ("finished!\n");
}

gint
fibo_mutex_init(void)
{
    return fibo_adapter_all_mutex_init();
}

int
fibo_get_supported_module_number(void)
{
    return fibo_adapter_get_supported_module_number();
}

int
fibo_get_supported_module_info(void *module_info, int index)
{
    int list_len = RET_ERROR;
    int ret      = RET_ERROR;

    if (!module_info) {
        FIBO_LOG_ERROR("NULL pointer!\n");
        return RET_ERROR;
    }

    list_len = fibo_get_supported_module_number();
    if (index < 0 || index > list_len - 1) {
        FIBO_LOG_ERROR("NULL pointer!\n");
        return RET_ERROR;
    }

    ret = fibo_adapter_get_supported_module_info((Fibocom_module_info_type *)module_info, index);
    if (ret != RET_OK) {
        FIBO_LOG_ERROR("NULL pointer!\n");
        return RET_ERROR;
    }

    return RET_OK;
}

gboolean
fibo_check_supported_request_table(void)
{
    gint     table_len      =  RET_ERROR;
    gint     i              =  RET_ERROR;
    gboolean check_flag     =  TRUE;

    table_len = sizeof(supported_request_table) / sizeof(fibocom_request_table_type);

    for (i = 0; i < table_len; i++) {
        if (supported_request_table[i].cid >= ENUM_CID_MAX)
            check_flag = FALSE;
        break;
        if (supported_request_table[i].func_pointer == NULL)
            check_flag = FALSE;
        break;
        if (supported_request_table[i].func_type >= FUNC_TYPE_MAX)
            check_flag = FALSE;
        break;
        if (supported_request_table[i].func_type == SYNC_FUNCTION && supported_request_table[i].callback != NULL)
            check_flag = FALSE;
        break;
    }

    return check_flag;
}

gboolean
fibo_check_module_info_table(void)
{
    return fibo_adapter_check_module_info_table();
}

void fibo_register_module_event_signal(void)
{
    GError          *connerror  = NULL;
    GError          *proxyerror = NULL;
    GDBusConnection *conn       = NULL;
    char            data[8]     = {0};
    GMainLoop       *loop;

    FIBO_LOG_DEBUG("enter!\n");

    loop = g_main_loop_new(NULL, FALSE);
    #if !GLIB_CHECK_VERSION (2,35,0)
    g_type_init ();
    #endif

    // further: module more likely inserted in mechine, so here will check and trigger a module insert event.
    while (TRUE)
    {
        conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &connerror);

        if (connerror != NULL || conn == NULL)
        {
            FIBO_LOG_DEBUG("g_bus_get_sync connect error! %s \n", connerror->message);
            g_error_free(connerror);
            sleep(1);
            continue;
        }

        proxy = mm_manager_new_sync(conn, G_DBUS_OBJECT_MANAGER_CLIENT_FLAGS_DO_NOT_AUTO_START, NULL, &proxyerror);
        if (proxy == NULL || proxyerror != NULL)
        {
            FIBO_LOG_DEBUG("helper_com_fibocom_helper_proxy_new_sync error! %s \n", proxyerror->message);
            g_error_free(proxyerror);
            sleep(1);
            continue;
        }
        else
        {
            FIBO_LOG_DEBUG("connect modemmanager dbus success...\n");
            break;
        }
    }

    g_signal_connect(G_DBUS_OBJECT_MANAGER(proxy), "notify::g-name-owner", G_CALLBACK(owner_name_change_notify_cb), NULL);

    g_signal_connect(G_DBUS_OBJECT_MANAGER(proxy), "object-added", G_CALLBACK(mm_plugin_object_added_cb), NULL);

    g_signal_connect(G_DBUS_OBJECT_MANAGER(proxy), "object-removed", G_CALLBACK(mm_plugin_object_removed_cb), NULL);

    FIBO_LOG_DEBUG("register signal finished!\n");

    g_main_loop_run (loop);
    // before app end, undef proxy firstly.
    g_object_unref(proxy);

    FIBO_LOG_DEBUG("function exit!\n");
}

void
fibo_helper_device_check(void)
{
    gint                   ret               = RET_ERROR;
    gint                   res               = RET_ERROR;
    gint                   retry_flag        = 0;
    gint                   retrycount        = 0;
    GThread                *devcheck_thread  = NULL;

    while(retry_flag < 3)
    {
        retry_flag++;

        switch (retry_flag) {
            case 3:
                FIBO_LOG_ERROR ("reach max retry! drop all remained init process!\n");
                devcheck_thread = g_thread_new ("devicecheck", (GThreadFunc)fibo_adapter_device_Check, NULL);
                if (!devcheck_thread) {
                    FIBO_LOG_ERROR("thread init failed!\n");
                    return;
                }
                break;
            case 2:
                FIBO_LOG_ERROR ("dont find valid cellular twice, will trigger HW reboot!\n");
                // trigger HW reboot
            case 1:
                while (retrycount < 20) {
                    ret = fibo_adapter_check_cellular (&res);
                    if (ret == RET_OK && res == RET_OK) {
                        fibo_adapter_control_mbim_init();
                        // device check is used to monitor all devices' add and remove event through udev.
                        devcheck_thread = g_thread_new ("devicecheck", (GThreadFunc)fibo_adapter_device_Check, NULL);
                        if (!devcheck_thread) {
                            FIBO_LOG_ERROR("thread init failed!\n");
                        }
                        return;
                    }
                    FIBO_LOG_ERROR ("dont find valid cellular, will retry!\n");
                    g_usleep (1000 * 1000 * 3);
                }
                break;
            default:
                FIBO_LOG_ERROR ("Invalid flag, exit device check thread!\n");
                return;
        }
    }

    return;
}

gint fibo_helper_mmevent_register(void)
{
    GThread                *rcvsignal_thread = NULL;

    rcvsignal_thread = g_thread_new ("rcvsignal", (GThreadFunc)fibo_register_module_event_signal, NULL);
    if (!rcvsignal_thread) {
        FIBO_LOG_ERROR("thread init failed!\n");
        return RET_ERROR;
    }
    return RET_OK;
}

void
fibo_helper_main_receiver(void)
{
    gint                   ret              = RET_ERROR;
    helper_message_struct  *msgs            = NULL;
    fibo_async_struct_type *user_data       = NULL;

    // further: add a timer to keep if message cant be returned, there will be a default error from main analyzer to main loop.
    msgs = (helper_message_struct *)malloc(2048 * sizeof(char));
    if (msgs == NULL)
    {
        FIBO_LOG_ERROR("malloc failed!");
        // g_thread_stop(fibo_adapter_device_Check);
        return;
    }

    FIBO_LOG_DEBUG("Enter to loop: get request and deal!\n");
    while (TRUE)
    {
        memset(msgs, 0, 2048);

        // fibo_adapter_mutex_async_pointer_operate_lock();

	ret = fibo_adapter_get_normal_req_from_dbus(msgs);
	if (ret != RET_OK) {
	    // FIBO_LOG_DEBUG("Get message failed, continue anyway!\n");
	    continue;
	}

        FIBO_LOG_DEBUG("get valid request, call receiver!\n");

        fibo_mutex_force_sync_lock();
        user_data1 = (fibo_async_struct_type *)msgs->mtext;
        // g_data_updated = TRUE;
        request_analyzer((fibo_async_struct_type *)msgs->mtext);
        fibo_mutex_force_sync_unlock();

        // keep_pointer_exist mutex will be locked by default, so here will be blocked.
        fibo_mutex_keep_pointer_exist_lock();
    }

    free(msgs);
    msgs = NULL;

    return;
}
void fibo_helper_control_receiver(void)
{
    gint                   ret              = RET_ERROR;
    helper_message_struct  *msgs            = NULL;
    fibo_async_struct_type *user_data       = NULL;
    char                   mbimportname[FIBOCOM_MODULE_MBIMPORT_LEN];

    // further: add a timer to keep if message cant be returned, there will be a default error from main analyzer to main loop.
    msgs = (helper_message_struct *)malloc(2048 * sizeof(char));
    if (msgs == NULL)
    {
        FIBO_LOG_ERROR("malloc failed!");
        // g_thread_stop(fibo_adapter_device_Check);
        return;
    }

    FIBO_LOG_DEBUG("ready to get control message!\n");

    while (TRUE)
    {
        memset(msgs, 0, 2048);
        memset(mbimportname, 0, FIBOCOM_MODULE_MBIMPORT_LEN);
        user_data = NULL;

        ret = fibo_adapter_get_control_req_from_dbus(msgs);
        if (ret == RET_OK) {
            FIBO_LOG_DEBUG("Get control message!\n");
        }

        user_data = (fibo_async_struct_type *)msgs->mtext;
        if (!user_data->cid) {
            FIBO_LOG_ERROR("cid invalid!\n");
            continue;
        }

        switch (user_data->cid) {
            case CTL_MBIM_INIT:
                strncpy(mbimportname, user_data->payload_str, user_data->payloadlen);
                fibo_adapter_mbim_port_init(mbimportname);
                break;
            case CTL_MBIM_DEINIT:
                fibo_adapter_mbim_port_deinit();
                break;
            case CTL_MBIM_END:
                if (gMainLoop) {
                    FIBO_LOG_ERROR ("Caught signal, stopping fibo-helper-mbim...\n");
                    g_idle_add ((GSourceFunc) g_main_loop_quit, gMainLoop);
                }
                break;
            default:
                FIBO_LOG_ERROR("Invalid control cid! refuse to execute!\n");
        }
    }

    free(msgs);
    msgs = NULL;

    return;
}

int
fibo_register_helper_service(void)
{
    int owner_id = RET_ERROR;

    FIBO_LOG_DEBUG("enter!\n");

    // add a new conf on /etc/dbus-1/system.d path, otherwise it will go bus_required and bus_name_lost immediately.
    owner_id = g_bus_own_name (G_BUS_TYPE_SYSTEM, "com.fibocom.helper",
                              G_BUS_NAME_OWNER_FLAGS_NONE,
                              bus_acquired, bus_name_acquired, bus_name_lost, NULL, NULL);
    return owner_id;
}

int
fibo_set_linux_app_signals()
{
    return fibo_adapter_set_linux_app_signals();
}

void
fibo_udev_deinit(void)
{
    fibo_adapter_udev_deinit();
}

void
fibo_mbim_port_deinit(void)
{
    fibo_adapter_mbim_port_deinit();
}

int fibo_get_helper_seq_id(int seq)
{
    return fibo_adapter_get_helper_seq_id(seq);
}

int fibo_helper_queue_init(void)
{
    return fibo_adapter_helper_queue_init();
}

/* ---------------------------------Begin: add customized function.------------------------------------------ */

// all request functions dont need unlock keep_pointer_exist mutex, but need to call two result resp functions to trigger a default error resp to caller.
int
fibo_prase_sw_reboot(gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str, gpointer callback, char *req_cmd)
{
    // gchar                   req_cmd[]    = "AT+CFUN=1,1";
    gint                    ret          = RET_ERROR;
    fibo_async_struct_type  *user_data   = NULL;

    if (!callback) {
        FIBO_LOG_ERROR("Illegal param!\n");
        return RET_ERROR;
    }

    user_data = (fibo_async_struct_type *)malloc(sizeof(fibo_async_struct_type) + payloadlen + 1);
    if (user_data == NULL)
    {
        FIBO_LOG_ERROR("malloc failed!\n");
        return RET_ERROR;
    }

    memset(user_data, 0, sizeof(fibo_async_struct_type) + payloadlen + 1);

    if (payloadlen == 0) {
        user_data->payloadlen  = 0;
        user_data->payload_str[0] = 0;
    }
    else {
        user_data->payloadlen  = payloadlen;
        memcpy(user_data->payload_str, payload_str, payloadlen);
    }

    user_data->serviceid   = serviceid;
    user_data->cid         = cid;
    user_data->rtcode      = rtcode;

    ret = fibo_adapter_send_message_async(req_cmd, strlen(req_cmd), DEFAULT_TIMEOUT, (GAsyncReadyCallback)callback, user_data);
    // here wont free user_data cause callback will use it and free it!
    if (ret != RET_OK) {
        FIBO_LOG_ERROR("Send request failed, error:%d\n", ret);
        return RET_ERROR;
    }

    FIBO_LOG_DEBUG("Send request finished\n");
    return RET_OK;
}

// all request callback only unlock mutex on normal scenario, and on abnormal scenario should call two result resp functions to trigger a default error resp to caller.
void
fibo_prase_get_ap_version_ready (MbimDevice   *device,
                                 GAsyncResult *res,
                                 gpointer userdata)
{
    g_autoptr(GError)                   error          =  NULL;
    gchar                               error_resp[]   =  "ERROR";
    guint32                             ret_size       =  RET_ERROR;
    const guint8                        *ret_str       =  NULL;
    g_autoptr(MbimMessage)              response       =  NULL;
    guint8                              *resp_str      =  NULL;
    gint                                rtcode         =  RET_ERR_PROCESS;  // this value must be 1.
    gint                                ret            =  0;
    fibo_async_struct_type              *user_data     =  NULL;
    gint                                service_id     =  0;
    gint                                cid            =  0x1001;
    gboolean                            malloc_flag    =  TRUE;

    FIBO_LOG_DEBUG("enter!\n");

#ifdef MBIM_FUNCTION_SUPPORTED
    response = mbim_device_command_finish (device, res, &error);

    if (!response || !mbim_message_response_get_result (response, MBIM_MESSAGE_TYPE_COMMAND_DONE, &error)) {
        FIBO_LOG_ERROR ("error: operation failed: %s\n", error->message);
        fibo_resp_error_result_callback(device, res, userdata);
        return;
    }

    if (!mbim_message_fibocom_at_command_response_parse (
            response,
            &ret_size,
            &ret_str,
            &error)) {
        FIBO_LOG_ERROR ("error: couldn't parse response message: %s\n", error->message);

        malloc_flag = FALSE;
        ret_size = strlen(error_resp);
        resp_str = error_resp;
    }
    else {
        resp_str = malloc(ret_size + 1);
        if (!resp_str) {
            FIBO_LOG_ERROR("malloc space for resp data failed!\n");
            fibo_resp_error_result_callback(device, res, userdata);
            return;
        }
        memset(resp_str, 0, ret_size + 1);
        memcpy(resp_str, ret_str, ret_size);
    }

    FIBO_LOG_DEBUG ("%s\n", (char *)resp_str);
#endif

    user_data = (fibo_async_struct_type *)userdata;
    if (!user_data) {
        FIBO_LOG_ERROR ("NULL pointer!\n");
        fibo_resp_error_result_callback(device, res, userdata);
        return;
    }
    else {
        service_id = user_data->serviceid;
        cid        = user_data->cid;
        rtcode     = user_data->rtcode;
    }

#ifndef MBIM_FUNCTION_SUPPORTED
    ret_size = user_data->payloadlen;
    resp_str = malloc(ret_size + 1);
    if (!resp_str) {
        FIBO_LOG_ERROR("malloc space for resp data failed!\n");
        fibo_resp_error_result_callback(device, res, user_data);
        return;
    }
    memset(resp_str, 0, ret_size + 1);
    memcpy(resp_str, user_data->payload_str, ret_size);
#endif

    if (user_data) {
        free(user_data);
        user_data = NULL;
    }

    FIBO_LOG_DEBUG ("serviceid:%d, cid:0x%04x\n", service_id, cid);

    ret = alloc_and_send_resp_structure(service_id, cid, rtcode, ret_size, resp_str);

    // here will unlock previous mutex, let mbim analyzer's receiver thread get another packet from message seq.
    fibo_mutex_keep_pointer_exist_unlock();

    if (ret != RET_OK) {
        FIBO_LOG_ERROR("send resp to main loop failed!\n");
        // if send resp fail, means default error resp will return error as well, aka we cant do anything.
    }

    if (resp_str && malloc_flag)
        free(resp_str);

    return;
}

int
fibo_prase_get_ap_version(gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str, gpointer callback, char *req_cmd)
{
    // gchar                   req_cmd[]    = "AT+GTSAPFWVER?";
    gint                    ret          = RET_ERROR;
    fibo_async_struct_type  *user_data   = NULL;

    if (!callback) {
        FIBO_LOG_ERROR("Illegal param!\n");
        return RET_ERROR;
    }

    user_data = (fibo_async_struct_type *)malloc(sizeof(fibo_async_struct_type) + payloadlen + 1);
    if (user_data == NULL)
    {
        FIBO_LOG_ERROR("malloc failed!\n");
        return RET_ERROR;
    }

    memset(user_data, 0, sizeof(fibo_async_struct_type) + payloadlen + 1);

    if (payloadlen == 0) {
        user_data->payloadlen  = 0;
        user_data->payload_str[0] = 0;
    }
    else {
        user_data->payloadlen  = payloadlen;
        memcpy(user_data->payload_str, payload_str, payloadlen);
    }

    user_data->serviceid   = serviceid;
    user_data->cid         = cid;
    user_data->rtcode      = rtcode;

    // further: add logic to combine new cmd with input buffer.
    ret = fibo_adapter_send_message_async(req_cmd, strlen(req_cmd), DEFAULT_TIMEOUT, (GAsyncReadyCallback)callback, user_data);
    // here wont free user_data cause callback will use it and free it!
    if (ret != RET_OK) {
        FIBO_LOG_ERROR("Send request failed, error:%d\n", ret);
        return RET_ERROR;
    }

    FIBO_LOG_DEBUG("Send request finished\n");
    return RET_OK;
}

// if one callback called this callback, caller dont concern user_data cause here will free it!
void
fibo_resp_error_result_callback (MbimDevice   *device,
                                 GAsyncResult *res,
                                 gpointer     userdata)
{
    gint                                ret            =  0;
    fibo_async_struct_type              *user_data     =  NULL;
    gint                                service_id     =  -1;
    gint                                cid            =  -1;
    gint                                rtcode         =  RET_ERR_PROCESS;  // this value must be 1.
    guint8                              ret_str[]      =  "ERROR";
    guint32                             ret_size       =  strlen(ret_str);

    FIBO_LOG_DEBUG("enter!\n");

    user_data = (fibo_async_struct_type *)userdata;
    if (!user_data) {
        FIBO_LOG_ERROR ("NULL pointer!\n");
    }
    else {
        service_id = user_data->serviceid;
        cid = user_data->cid;
    }

    if (userdata) {
        free(userdata);
        userdata = NULL;
    }

    ret = alloc_and_send_resp_structure(service_id, cid, rtcode, ret_size, ret_str);

    // here will unlock previous mutex, let fibo-helper-mbim app's receiver thread get another packet from message seq.
    fibo_mutex_keep_pointer_exist_unlock();

    if (ret != RET_OK) {
        FIBO_LOG_ERROR("send resp to main loop failed!\n");
        return;
    }

    return;
}

int
fibo_resp_error_result(gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str, gpointer callback, char * req_cmd)
{
    gchar                               atrsp[]        = "ERROR";
    gint                                ret            =  RET_ERROR;

    FIBO_LOG_DEBUG("BEGIN TO Send default resp to caller!\n");

    ret = alloc_and_send_resp_structure(serviceid, cid, 1, strlen(atrsp), atrsp);

    // here will unlock previous mutex, let mbim analyzer's receiver thread get another packet from message seq.
    fibo_mutex_keep_pointer_exist_unlock();

    if (ret != RET_OK) {
        FIBO_LOG_ERROR("send resp to main loop failed!\n");
        return RET_ERROR;
    }

    return RET_OK;
}

/*shikangyu*/

void fibo_del_char(char str[],char c)
{
    int j=0;
    for(int i=0;str[i]!='\0';i++)
        if(str[i] != c)
            str[j++]=str[i];
    str[j]='\0';
}

int fibo_prase_send_atcmd_ready (MbimDevice   *device,
                                  GAsyncResult *res,
                                  gpointer userdata)
{
    g_autoptr(GError)                   error          =  NULL;
    guint32                             ret_size       =  0;
    const guint8                        *ret_str       =  NULL;
    g_autoptr(MbimMessage)              response       =  NULL;
    gchar                               *resp_str      =  NULL;
    gint                                cid            =  0;
    gint                                rtcode         =  0;
    gint                                payloadlen     =  0;
    gchar                               *atcommand_str =  NULL;
    char                                *p             =  NULL;
    int                                 ret            =  RET_ERROR;
    fibo_async_struct_type              *user_data     =  NULL;
    gint                                service_id     =  0;
    gboolean                            malloc_flag    =  TRUE;
    gchar                               error_resp[]   =  "ERROR";

#ifdef MBIM_FUNCTION_SUPPORTED
    response = mbim_device_command_finish (device, res, &error);

    if (!response || !mbim_message_response_get_result (response, MBIM_MESSAGE_TYPE_COMMAND_DONE, &error)) {
        FIBO_LOG_ERROR ("error: operation failed: %s\n", error->message);
        return RET_ERROR;
    }

    if (!mbim_message_fibocom_at_command_response_parse (
            response,
            &ret_size,
            &ret_str,
            &error)) {
        FIBO_LOG_ERROR ("error: couldn't parse response message: %s\n", error->message);

        malloc_flag = FALSE;
        ret_size = strlen(error_resp);
        resp_str = error_resp;
    }
    else {
        FIBO_LOG_DEBUG("%d    %d\n",ret_size,__LINE__);
        resp_str = malloc(ret_size + 1);
        if (!resp_str) {
            g_printerr ("error: malloc space for resp data failed!\n");
            fibo_resp_error_result_callback(device, res, userdata);
            return RET_ERROR;
        }
        memset(resp_str, 0, ret_size + 1);
        memcpy(resp_str, ret_str, ret_size);
    }
#endif

    user_data = (fibo_async_struct_type *)userdata;
    if (!user_data) {
        FIBO_LOG_ERROR ("NULL pointer!\n");
        fibo_resp_error_result_callback(device, res, userdata);
        return RET_ERROR;
    }
    else {
        service_id = user_data->serviceid;
        cid = user_data->cid;
    }

#ifndef MBIM_FUNCTION_SUPPORTED
    ret_size = user_data->payloadlen;
    resp_str = malloc(ret_size + 1);
    if (!resp_str) {
        FIBO_LOG_ERROR("malloc space for resp data failed!\n");
        fibo_resp_error_result_callback(device, res, user_data);
        user_data = NULL;
        return RET_ERROR;
    }
    memset(resp_str, 0, ret_size + 1);
    memcpy(resp_str, user_data->payload_str, ret_size);
#endif

    FIBO_LOG_DEBUG("%d   %d \n", cid ,__LINE__);
    FIBO_LOG_DEBUG("%s   %d \n", resp_str,__LINE__);

    if(strstr(resp_str,"Read Error") != NULL)
    {
        fibo_resp_error_result_callback(device, res, user_data);
        user_data = NULL;
        return RET_OK;
    }

    if((GET_AP_VERSION == cid) || (GET_OP_VERSION == cid) || (GET_OEM_VERSION == cid) || (GET_DEV_VERSION == cid) || (GET_OP_VERSION == cid)) /*"xxx"*/
    {
        p = strtok(resp_str,"\"");
        p = strtok(NULL,"\"");
        resp_str = p;
        FIBO_LOG_DEBUG("%s   %d \n", resp_str,__LINE__);
    }
    else if ((SET_BODYSAR_ENABLE == cid) || (GET_MD_VERSION == cid) || (GET_IMEI ==cid)) /*2line line1:\n line2:\r\n*/
    {
        p = strtok(resp_str,"\n");
        p = strtok(NULL,"\r\n");
        resp_str = p;
        FIBO_LOG_DEBUG("%s   %d \n", resp_str ,__LINE__);
    }
    else if((GET_BODYSAR_STATUS == cid) || (GET_BODYSAR_CTRL_MODE == cid)
            || (GET_BODYSAR_VER == cid) || (GET_ANTENNA_VER == cid) || (GET_ANTENNA_STATUS == cid) || (GET_ANTENNA_WORK_MODE == cid)
            || (GET_WDISABLE_STATUS == cid) || (GET_GNSS_STATUS == cid)  || (GET_ANTENNA_CTRL_MODE == cid)) /*: xxx*/
    {
        p = strtok(resp_str," ");
        p = strtok(NULL,"\r\n");
        resp_str = p;
        FIBO_LOG_DEBUG("%s   %d \n", resp_str ,__LINE__);
    }else if((GET_OEM_ID == cid) || (GET_MODEM_RANDOM_KEY == cid) || (GET_DISABLE_ESIM_STATUS == cid) || (GET_FCCLOCK_STATUS == cid)) /*:xxx*/
    {
        p = strtok(resp_str,":");
        p = strtok(NULL,"\r\n");
        resp_str = p;
        FIBO_LOG_DEBUG("%s   %d \n", resp_str ,__LINE__);
    }
    else if((SET_FCC_UNLOCK == cid))
    {
        p = strtok(resp_str,":");
        p = strtok(NULL,"\r\n");
        resp_str = p;
        FIBO_LOG_DEBUG("%s   %d \n", resp_str ,__LINE__);
        if (resp_str != NULL && strlen(resp_str) != 0) {
		if(strstr(resp_str,"1") != NULL)
		{
		    sprintf(resp_str,"success");
		}
		else if(strstr(resp_str,"0") != NULL)
		{
		    sprintf(resp_str,"failed");
		}
		else{

		}
	}
	else {
	    FIBO_LOG_DEBUG("found a NULL pointer!\n");
	}

    }else if ((SET_BODYSAR_INDEX == cid) || (SET_BODYSAR_VER ==cid) || (SET_ANTENNA_ENABLE == cid)
              || (SET_ANTENNA_CTRL_MODE ==cid) || (SET_ANTENNA_WORK_MODE == cid) || (SET_ANTENNA_VER == cid) || (SET_ANTENNA_INDEX == cid)
              || (SET_WDISABLE_ENABLE == cid) || (SET_GNSS_ENABLE == cid) || (SET_FCCLOCK_ENABLE == cid) || (RESET_MODEM_SW == cid))
    {
        p = strtok(resp_str,"\r\n");
        p = strtok(NULL,"\r\n");
        resp_str = p;
        FIBO_LOG_DEBUG("%s   %d \n", resp_str ,__LINE__);
    }
    else{

    }
    FIBO_LOG_DEBUG("%s   %d \n", resp_str ,__LINE__);

    if (resp_str == NULL || strlen(resp_str) == 0) {
        FIBO_LOG_DEBUG("found a NULL pointer!\n");
        fibo_resp_error_result_callback(device, res, user_data);
        user_data = NULL;
        return RET_OK;
    }

    if (user_data) {
        free(user_data);
        user_data = NULL;
    }

    if(strstr(resp_str,"ERROR") != NULL)
    {
        FIBO_LOG_ERROR("[%s]:at_cmd return error:%s\n", __func__, resp_str);
        rtcode = 1;
    }
    // further: add func to deal with AT resp.
    ret = alloc_and_send_resp_structure(service_id, cid, rtcode, strlen(resp_str), resp_str);

    fibo_mutex_keep_pointer_exist_unlock();

    if (ret != RET_OK) {
        FIBO_LOG_ERROR("send resp to main loop failed!\n");
    }

//    if (resp_str && malloc_flag)
//        free(resp_str);

    return RET_OK;
}

int
fibo_prase_send_req_atcmd(gint     serviceid,
                          gint     cid,
                          gint     rtcode,
                          gint     payloadlen,
                          gchar    *payload_str,
                          gpointer callback,
                          char *req_cmd)
{ // ((3, 0x3001), 0, 0, "")
    gint  ret        = RET_ERROR;
    fibo_async_struct_type *user_data = NULL;

    if (serviceid > ENUM_MAX || !payload_str || (payloadlen != 0 && payload_str[payloadlen] != '\0')  || !callback) {
        FIBO_LOG_ERROR("Illegal param, %d, %d!\n", payloadlen, (payload_str == NULL));
        return RET_ERROR;
    }

    user_data = (fibo_async_struct_type *)malloc(sizeof(fibo_async_struct_type) + payloadlen + 1);
    if (user_data == NULL)
    {
        FIBO_LOG_ERROR("malloc failed!\n");
        return RET_ERROR;
    }

    memset(user_data, 0, sizeof(fibo_async_struct_type) + payloadlen + 1);

    if (payloadlen == 0) {
        user_data->payloadlen  = 0;
        user_data->payload_str[0] = 0;
    }
    else {
        user_data->payloadlen  = payloadlen;
        memcpy(user_data->payload_str, payload_str, payloadlen + 1);
    }

    user_data->serviceid   = serviceid;
    user_data->cid         = cid;
    user_data->rtcode      = rtcode;

    ret = fibo_adapter_send_message_async(req_cmd, strlen(req_cmd), DEFAULT_TIMEOUT, (GAsyncReadyCallback)callback, user_data);
    if (ret != RET_OK) {
        FIBO_LOG_ERROR("Send request failed, error:%d\n", ret);
        return RET_ERROR;
    }

    FIBO_LOG_DEBUG("Send request finished\n");
    return RET_OK;
}

int
fibo_prase_get_fcc_status_ready (MbimDevice   *device,
                                 GAsyncResult *res,
                                 gpointer userdata)
{
    g_autoptr(GError)                   error             =  NULL;
    guint32                             ret_size          =  0;
    const guint8                        *ret_str          =  NULL;
    g_autoptr(MbimMessage)              response          =  NULL;
    gchar                               *resp_str         =  NULL;
    gint                                service_id         =  0;
    gint                                cid               =  0;
    gint                                rtcode            =  0;
    gchar                             *fcc_status    = NULL;
    const gchar                         *at_command_prefix = "+GTFCCEFFSTATUS:";
    gint                                    at_command_prefix_end_index = -1;
    fibo_async_struct_type              *user_data     =  NULL;
    gboolean                            malloc_flag    =  TRUE;
    gchar                               error_resp[]   =  "ERROR";
    int ret = 0;

#ifdef MBIM_FUNCTION_SUPPORTED
    response = mbim_device_command_finish (device, res, &error);

    if (!response || !mbim_message_response_get_result (response, MBIM_MESSAGE_TYPE_COMMAND_DONE, &error)) {
        FIBO_LOG_ERROR ("error: operation failed: %s\n", error->message);
        return RET_ERROR;
    }

    if (!mbim_message_fibocom_at_command_response_parse (
            response,
            &ret_size,
            &ret_str,
            &error)) {
        FIBO_LOG_ERROR ("error: couldn't parse response message: %s\n", error->message);

        malloc_flag = FALSE;
        ret_size = strlen(error_resp);
        resp_str = error_resp;
    }
    else {
        resp_str = malloc(ret_size + 1);
        if (!resp_str) {
            g_printerr ("error: malloc space for resp data failed!\n");
            fibo_resp_error_result_callback(device, res, userdata);
            return RET_ERROR;
        }
        memset(resp_str, 0, ret_size + 1);
        memcpy(resp_str, ret_str, ret_size);
    }
#endif

    user_data = (fibo_async_struct_type *)userdata;
    if (!user_data) {
        FIBO_LOG_ERROR ("NULL pointer!\n");
    }
    else {
        service_id = user_data->serviceid;
        cid = user_data->cid;
    }

#ifndef MBIM_FUNCTION_SUPPORTED
    ret_size = user_data->payloadlen;
    resp_str = malloc(ret_size + 1);
    if (!resp_str) {
        FIBO_LOG_ERROR("malloc space for resp data failed!\n");
        fibo_resp_error_result_callback(device, res, userdata);
        return RET_ERROR;
    }
    memset(resp_str, 0, ret_size + 1);
    memcpy(resp_str, user_data->payload_str, ret_size);
#endif

    if (userdata) {
        free(userdata);
        userdata = NULL;
    }

    FIBO_LOG_DEBUG("at:%s   %d \n", ret_str,__LINE__);

    if (strlen(at_command_prefix) + 3 > strlen(ret_str)) {
        rtcode = 1;
        return RET_ERROR;
    }

    for (int i = 0, j = 0;i < strlen(ret_str);i++) {
        if (j >= strlen(at_command_prefix)) {
            at_command_prefix_end_index = i;
            rtcode = 1;
            break;
        }
        if (at_command_prefix[j] == ret_str[i]) {
            j++;
        } else {

            j = 0;
        }
    }

    /* ex : ret_str[at_command_prefix_end_index] == "0,0" */

    if (at_command_prefix_end_index == -1 || at_command_prefix_end_index + 2 > strlen(ret_str)) {
        return RET_ERROR;
    }

    if (ret_str[at_command_prefix_end_index] == '0') {
        fcc_status = "nolock";
    }
    else if (ret_str[at_command_prefix_end_index] == '1') {
        if (ret_str[at_command_prefix_end_index + 2] == '0') {
            fcc_status = "lock";
        }
        if (ret_str[at_command_prefix_end_index + 2] == '1') {
            fcc_status = "unlock";
        }
    }

    if (fcc_status == NULL) {
        FIBO_LOG_ERROR ("at:%s\n", ret_str + at_command_prefix_end_index);
        return RET_ERROR;
    }

    FIBO_LOG_ERROR ("fcc_status: %s", fcc_status);
    ret = alloc_and_send_resp_structure(service_id, cid, rtcode, strlen(fcc_status), fcc_status);

    fibo_mutex_keep_pointer_exist_unlock();

    if (ret != RET_OK) {
        FIBO_LOG_ERROR("send resp to main loop failed!\n");
    }

    if (resp_str && malloc_flag)
        free(resp_str);


    return RET_OK;
}

int fibo_prase_send_set_atcmd(gint     serviceid,
                              gint     cid,
                              gint     rtcode,
                              gint     payloadlen,
                              gchar    *payload_str,
                              gpointer callback,
                              char *req_cmd)
{
    char * parameter_req_cmd = NULL;

    parameter_req_cmd = malloc(sizeof(char) * 128);
    if (parameter_req_cmd) {
        FIBO_LOG_ERROR("NULL pointer!\n");
    }
    memset(parameter_req_cmd, 0, sizeof(parameter_req_cmd));

    FIBO_LOG_DEBUG("%s   %d\n", payload_str, __LINE__);

    sprintf(parameter_req_cmd,"%s%s",req_cmd, payload_str);

    fibo_prase_send_req_atcmd(serviceid, cid, rtcode, payloadlen, payload_str, callback, parameter_req_cmd);

    FIBO_LOG_DEBUG("%s   %d\n", parameter_req_cmd, __LINE__);

    if(parameter_req_cmd)
        free(parameter_req_cmd);

    return RET_OK;
}

int fibocom_get_port_command_ready (gchar   *resp_str)
{
    g_autoptr(GError)                   error          =  NULL;
    guint32                             ret_size       =  0;
    const guint8                        *ret_str       =  NULL;
    g_autoptr(MbimMessage)              response       =  NULL;
    gint                                service_id      =  0;
    gint                                cid            =  0;
    gint                                rtcode         =  0;
    char *p = NULL;
    FILE *get_port_fp = NULL;
    char get_port_cmd[128] = "lsusb | awk -F ' ' 'NR=6 {print $6}'";
    int count = 1024;
    char buf[1024]= {0};
    gboolean                            malloc_flag    =  TRUE;
    fibo_async_struct_type              *user_data     =  NULL;
    int ret = 0;

    get_port_fp = popen(get_port_cmd,"r");
    if(get_port_fp == NULL) {
        FIBO_LOG_DEBUG("open get_port_cmd error\n");
    }

    sprintf(resp_str,"%s\n","noport");
    int support_usbvidpid_size = (sizeof(support_usbvidpid) / sizeof(Support_Usbvidpid));

    while(fgets(buf,256,get_port_fp) != NULL)
    {
        for(int i = 0; i < support_usbvidpid_size; i++)
        {
            if(strstr(buf,support_usbvidpid[i].vidpid) != NULL)
            {
                sprintf(resp_str,"%s\n","normalport");
                break;
            }
        }
        if(strstr(buf,"05c6:9008") != NULL)
        {
            sprintf(resp_str,"%s\n","flashport");
            break;
        }
        else if(strstr(buf,"2cb7:d00d") != NULL)
        {
            sprintf(resp_str,"%s\n","fastbootport");
            break;
        }
        else
        {
            FIBO_LOG_DEBUG("don't match subpidvid   %d    \n",__LINE__);
            continue;
        }
    }
    pclose(get_port_fp);

    FIBO_LOG_DEBUG("%s     %d    \n",resp_str,__LINE__);


    return RET_OK;
}

void fibo_fastboot_reboot()
{
    FILE *reboot_fp = NULL;
    int ret;
    reboot_fp = popen("fastboot reboot", "r");
    if (reboot_fp == NULL) {
        FIBO_LOG_ERROR ("[%s:]popen reboot_fp failed!\n",__func__);
        return ;
    }
    ret = pclose(reboot_fp);
    if (ret != RET_OK)
    {
        g_print("%s pclose reboot_fp error!\n", __func__);
        return;
    }
}

int fibocom_edl_flash_ready (MbimDevice   *device,
                                GAsyncResult *res,
                                gpointer userdata)
{
    g_autoptr(GError)                   error          =  NULL;
    guint32                             ret_size       =  0;
    const guint8                        *ret_str       =  NULL;
    g_autoptr(MbimMessage)              response       =  NULL;
    gchar                               *resp_str      =  NULL;
    gint                                service_id      =  0;
    gint                                cid            =  0;
    gint                                rtcode         =  0;
    gboolean                            malloc_flag    =  TRUE;
    fibo_async_struct_type              *user_data     =  NULL;
    char *payload = NULL;
    gint payloadlen = 0;
    int ret = 0;

    resp_str = malloc(ret_size + 1);
    if (!resp_str) {
        g_printerr ("error: malloc space for resp data failed!\n");
        fibo_resp_error_result_callback(device, res, userdata);
        return RET_ERROR;
    }
    memset(resp_str, 0, ret_size + 1);
    memcpy(resp_str, ret_str, ret_size);


    user_data = (fibo_async_struct_type *)userdata;

    if (!user_data) {
        FIBO_LOG_ERROR ("NULL pointer!\n");
    }
    else {
        service_id = user_data->serviceid;
        cid = user_data->cid;
        payload = user_data->payload_str;
        FIBO_LOG_DEBUG("%s     %d", payload,__LINE__);
    }

    if (userdata) {
        free(userdata);
        userdata = NULL;
    }

    char get_qdl_port_cmd[128] = "lsusb | grep \"QDL mode\" | awk -F ' ' 'NR=6 {print $6}'";
    FILE *get_port_fp =NULL;
    get_port_fp = popen(get_qdl_port_cmd,"r");
    if(get_port_fp == NULL) {
        FIBO_LOG_DEBUG("open get_port_cmd error\n");
    }
    while(fgets(resp_str, 256, get_port_fp) != NULL)
    {
        FIBO_LOG_DEBUG("%s    %d\n",resp_str,__LINE__);
    }
    pclose(get_port_fp);

    if((strstr(resp_str,"05c6:9008") != NULL))
    {
        sprintf(resp_str,"OK");
    } else{
        sprintf(resp_str,"ERROR");
    }

    ret = alloc_and_send_resp_structure(service_id, cid, rtcode, strlen(resp_str), resp_str);

    fibo_mutex_keep_pointer_exist_unlock();

    if (ret != RET_OK) {
        FIBO_LOG_ERROR("send resp to main loop failed!\n");
    }

    if (resp_str && malloc_flag)
        free(resp_str);

    FIBO_LOG_DEBUG("%s     %d", payload,__LINE__);
    GThread *gthread_qdl_flash = NULL;
    gthread_qdl_flash = g_thread_new("qdl_flash", edl_flashing_command, payload);

    return TRUE;
}

int fibocom_get_subsysid_ready (MbimDevice   *device,
                                 GAsyncResult *res,
                                 gpointer userdata)
{
    g_autoptr(GError)                   error          =  NULL;
    guint32                             ret_size       =  0;
    const guint8                        *ret_str       =  NULL;
    g_autoptr(MbimMessage)              response       =  NULL;
    gchar                               *resp_str      =  NULL;
    gint                                service_id      =  0;
    gint                                cid            =  0;
    gint                                rtcode         =  0;
    gint                                payloadlen     =  0;
    gchar                               *atcommand_str =  NULL;
    gboolean                            malloc_flag    =  TRUE;
    fibo_async_struct_type              *user_data     =  NULL;
    int ret = 0;
    char *p = NULL;
    FILE *get_port_fp = NULL;
    char get_port_cmd[128] = "lsusb | grep Fibocom | awk -F ' ' 'NR=6 {print $6}'";
    char get_qdl_port_cmd[128] = "lsusb | grep \"QDL mode\" | awk -F ' ' 'NR=6 {print $6}'";
    int count = 1024;
    char buf[1024]= {0};

#ifdef MBIM_FUNCTION_SUPPORTED
    response = mbim_device_command_finish (device, res, &error);

    if (!response || !mbim_message_response_get_result (response, MBIM_MESSAGE_TYPE_COMMAND_DONE, &error)) {
        FIBO_LOG_ERROR ("error: operation failed: %s\n", error->message);
        return RET_ERROR;
    }

    if (!mbim_message_fibocom_at_command_response_parse (
            response,
            &ret_size,
            &ret_str,
            &error)) {
        FIBO_LOG_ERROR ("error: couldn't parse response message: %s\n", error->message);

        malloc_flag = FALSE;

    }
    else {
        resp_str = malloc(ret_size + 1);
        if (!resp_str) {
            g_printerr ("error: malloc space for resp data failed!\n");
            fibo_resp_error_result_callback(device, res, userdata);
            return RET_ERROR;
        }
        memset(resp_str, 0, ret_size + 1);
        memcpy(resp_str, ret_str, ret_size);
    }
#endif

    user_data = (fibo_async_struct_type *)userdata;

    if (!user_data) {
        FIBO_LOG_ERROR ("NULL pointer!\n");
    }
    else {
        service_id = user_data->serviceid;
        cid = user_data->cid;
    }

#ifndef MBIM_FUNCTION_SUPPORTED
    ret_size = user_data->payloadlen;
    resp_str = malloc(ret_size + 1);
    if (!resp_str) {
        FIBO_LOG_ERROR("malloc space for resp data failed!\n");
        fibo_resp_error_result_callback(device, res, userdata);
        return RET_ERROR;
    }
    memset(resp_str, 0, ret_size + 1);
    memcpy(resp_str, user_data->payload_str, ret_size);
#endif

    if (userdata) {
        free(userdata);
        userdata = NULL;
    }

    get_port_fp = popen(get_port_cmd,"r");
    if(get_port_fp == NULL) {
        FIBO_LOG_DEBUG("open get_port_cmd error\n");
    }
    while(fgets(resp_str, 256, get_port_fp) != NULL)
    {

    }
    pclose(get_port_fp);
    if((strstr(resp_str,"2cb7,01a2") != NULL) || (strstr(resp_str,"2cb7,d00d") != NULL))
    {
        get_port_fp == NULL;
        get_port_fp = popen(get_qdl_port_cmd,"r");
        if(get_port_fp == NULL) {
            FIBO_LOG_DEBUG("open get_port_cmd error\n");
        }
        while(fgets(resp_str,256,get_port_fp) != NULL)
            pclose(get_port_fp);
        if((strstr(resp_str,"05c6:9008") == NULL))
        {
            sprintf(resp_str,"0000:0000");
        }
    }

    fibo_del_char(resp_str,':');
    fibo_del_char(resp_str,'\n');

    FIBO_LOG_DEBUG("%s     %d    \n",resp_str,__LINE__);

    ret = alloc_and_send_resp_structure(service_id, cid, rtcode, strlen(resp_str), resp_str);

    fibo_mutex_keep_pointer_exist_unlock();

    if (ret != RET_OK) {
        FIBO_LOG_ERROR("send resp to main loop failed!\n");
    }

    if (resp_str && malloc_flag)
        free(resp_str);


    return RET_OK;
}

/*--------------------------------------qdl flash && fastboot flash start----------------------------------------------*/

typedef struct {
    FILE *progress_fp;
    char progress_command[1024];
    char progress_title[128];
    char progress_text[128];
    char progress_percentage[32];
}File_Progress_Class;

typedef struct{
    int ap;
    int sbl;
    int modem;
    int dev;
    int oem;
    int op;
}Sub_Pratition_Len;

typedef struct {
    int ap;
    int modem;
    int dev;
    int oem;
    int op;
    int path;
}Partition_Flash_Flag;

typedef struct{
    char *ap_ver;
    char *modem_ver;
    char *dev_ver;
    char *dev_ver_path;
    char *oem_ver;
    char *oem_ver_path;
    char *op_ver;
    char *op_ver_path;
    char *flashpath;
}Payload_Analysis;

typedef struct
{
    char *lable;
    char *filename;
}fibocom_pratition;

fibocom_pratition ap_pratition[] = {
        /*lable            filename*/
        {"aboot","appsboot.mbn"},
        {"boot","sdxnightjar-boot.img"},
        {"system", "sdxnightjar-sysfs.ubi"},
        {"userdata", "sdxnightjar-usrfs.ubi"},
};

fibocom_pratition sbl_pratition[] = {{"sbl", "sbl1.mbn"}};

fibocom_pratition modem_pratition[] = {{"modem", "NON-HLOS.ubi"}};

fibocom_pratition dev_pratition[] = {
        {"devicepack", "devicepack.ubi"},
};

fibocom_pratition oem_pratition[] = {
        {"oempack", "oempack.ubi"},
};

fibocom_pratition op_pratition[] = {{"operatorpack", "operatorpack.ubi"}};

char* itoa(int num,char* str,int radix)
{
    char index[]="0123456789ABCDEF";
    unsigned unum;
    int i=0,j,k;

    if(radix==10&&num<0)
    {
        unum=(unsigned)-num;
        str[i++]='-';
    }
    else unum=(unsigned)num;

    do{
        str[i++]=index[unum%(unsigned)radix];
        unum/=radix;
    }while(unum);

    str[i]='\0';
    if(str[0]=='-')
        k=1;
    else
        k=0;

    for(j=k;j<=(i-1)/2;j++)
    {       char temp;
        temp=str[j];
        str[j]=str[i-1+k-j];
        str[i-1+k-j]=temp;
    }
    return str;
}
void fibo_program_payload_analysis(char * payload,Payload_Analysis *payload_analysis,Partition_Flash_Flag *partition_flash_flag)
{
    char *interpayload = NULL;
    interpayload = (char*)malloc(sizeof(char)*512);
    memset(interpayload , 0, sizeof(char)*512);

    char default_package_path[] = "/opt/fibocom/fibo_fw_pkg/FwPackage/";
    strcpy(interpayload, payload);
    FIBO_LOG_DEBUG("interpayload = %s %d\n",interpayload,__LINE__);

    interpayload = strtok(interpayload,";");
    FIBO_LOG_DEBUG("%s %d\n",interpayload,__LINE__);

    memcpy(payload_analysis->flashpath,default_package_path,strlen(default_package_path)+1);

    while(interpayload)
    {
        if(strstr(interpayload,"path"))
        {
            memcpy(payload_analysis->flashpath,interpayload,strlen(interpayload)+1);
            FIBO_LOG_DEBUG("payload_analysis->flashpath = %s %d\n",payload_analysis->flashpath,__LINE__);
            partition_flash_flag->path++;
        }else if(strstr(interpayload,"ap"))
        {
            memcpy(payload_analysis->ap_ver,interpayload,strlen(interpayload)+1);
            FIBO_LOG_DEBUG("payload_analysis->ap_ver = %s %d\n",payload_analysis->ap_ver,__LINE__);
            partition_flash_flag->ap++;
        }else if(strstr(interpayload,"md"))
        {
            memcpy(payload_analysis->modem_ver,interpayload,strlen(interpayload)+1);
            FIBO_LOG_DEBUG("%s %d\n",interpayload,__LINE__);
            FIBO_LOG_DEBUG("modem_ver = %s %d\n",payload_analysis->modem_ver,__LINE__);
            partition_flash_flag->modem++;
        }else if(strstr(interpayload,"dev"))
        {
            memcpy(payload_analysis->dev_ver,interpayload,strlen(interpayload)+1);
            FIBO_LOG_DEBUG("payload_analysis->dev_ver = %s %d\n",payload_analysis->dev_ver,__LINE__);
            partition_flash_flag->dev++;
        }else if(strstr(interpayload,"oem"))
        {
            memcpy(payload_analysis->oem_ver,interpayload,strlen(interpayload)+1);
            FIBO_LOG_DEBUG("payload_analysis->oem_ver = %s %d\n",payload_analysis->oem_ver,__LINE__);
            partition_flash_flag->oem++;
        }else if(strstr(interpayload,"op"))
        {
            memcpy(payload_analysis->op_ver,interpayload,strlen(interpayload)+1);
            FIBO_LOG_DEBUG("payload_analysis->op_ver = %s %d\n",payload_analysis->op_ver,__LINE__);
            partition_flash_flag->op++;
        }
        else
        {
            FIBO_LOG_DEBUG("[%s:]current field don't match partation and path\n",__func__);
        }
        interpayload = strtok(NULL,";");
        FIBO_LOG_DEBUG("interpayload = %s %d\n",interpayload,__LINE__);
    }


    if((partition_flash_flag->ap == 0) && (partition_flash_flag->modem == 0) && (partition_flash_flag->dev == 0) && (partition_flash_flag->oem == 0) && (partition_flash_flag->op == 0))
    {
        FIBO_LOG_ERROR("[%s:]don't match partation and path\n",__func__);
        fibo_fastboot_reboot();
        fibocom_gdbus_helper_emit_fastboot_status(g_skeleton,"don't match partation and path,rebooting module");
    }

    if(interpayload) {
        free(interpayload);
    }

    if(partition_flash_flag->path != 0) {
        payload_analysis->flashpath = strtok(payload_analysis->flashpath, ":");
        payload_analysis->flashpath = strtok(NULL, "\0");
    }
    FIBO_LOG_DEBUG("payload_analysis->flashpath = %s %d\n",payload_analysis->flashpath,__LINE__);

    if(partition_flash_flag->ap != 0)
    {
        payload_analysis->ap_ver = strtok(payload_analysis->ap_ver,":");
        payload_analysis->ap_ver = strtok(NULL,";");
        FIBO_LOG_DEBUG("payload_analysis->ap_ver = %s %d\n",payload_analysis->ap_ver,__LINE__);
    }

    if(partition_flash_flag->modem != 0)
    {
        payload_analysis->modem_ver = strtok(payload_analysis->modem_ver,":");
        payload_analysis->modem_ver = strtok(NULL,";");
        FIBO_LOG_DEBUG("payload_analysis->modem_ver = %s %d\n",payload_analysis->modem_ver,__LINE__);
    }
    if(partition_flash_flag->dev != 0)
    {
        payload_analysis->dev_ver = strtok(payload_analysis->dev_ver,":");
        payload_analysis->dev_ver = strtok(NULL,";");
        sprintf(payload_analysis->dev_ver_path,"%s",payload_analysis->dev_ver);
        FIBO_LOG_DEBUG("payload_analysis->dev_ver_path = %s %d\n",payload_analysis->dev_ver_path,__LINE__);
    }
    if(partition_flash_flag->oem != 0)
    {
        payload_analysis->oem_ver = strtok(payload_analysis->oem_ver,":");
        payload_analysis->oem_ver = strtok(NULL,";");
        sprintf(payload_analysis->oem_ver_path,"%s%s","OEM_OTA_",payload_analysis->oem_ver);
        FIBO_LOG_DEBUG("payload_analysis->oem_ver_path = %s %d\n",payload_analysis->oem_ver_path,__LINE__);
    }
    if(partition_flash_flag->op != 0)
    {
        payload_analysis->op_ver = strtok(payload_analysis->op_ver,":");
        payload_analysis->op_ver = strtok(NULL,";");
        sprintf(payload_analysis->op_ver_path,"%s%s","OP_OTA_",payload_analysis->op_ver);
        FIBO_LOG_DEBUG("payload_analysis->op_ver_path = %s %d\n",payload_analysis->op_ver_path,__LINE__);
    }
}

int fibocom_get_zenity_environment_variable(char zenity_environment_variable[],int length)
{
    FILE *get_zenity_environment_variable_fp = NULL;
    char get_zenity_environment_variable_cmd[] = "find /run/user -name \".mutter-Xwaylandauth*\" 2>/dev/null | head -1";
    int ret = 0;

    get_zenity_environment_variable_fp = popen(get_zenity_environment_variable_cmd,"r");
    if(NULL == get_zenity_environment_variable_fp)
    {
        perror("get_zenity_environment_variable error");
        FIBO_LOG_ERROR("open zenity_environment_variable error\n");
        return RET_ERROR;
    }

    ret = fread(zenity_environment_variable,sizeof(char),length,get_zenity_environment_variable_fp);
    if(!ret)
    {
        FIBO_LOG_ERROR("read zenity_environment_variable error\n");
        pclose(get_zenity_environment_variable_fp);
        return RET_ERROR;
    }

    pclose(get_zenity_environment_variable_fp);

    return RET_OK;
}

void fibocom_strcat_zenity_environment_variable(char zenity_environment_variable[],char set_zenity_environment_variable[])
{
    sprintf(set_zenity_environment_variable,"export DISPLAY=\":0\"\nexport XDG_CURRENT_DESKTOP=\"ubuntu:GNOME\"\nexport XAUTHORITY=%s\n",zenity_environment_variable);
}

gpointer fibocom_fastboot_flash_command(gpointer payload) {
    guint8 bootloader_reboot_str[] = "fastboot reboot\r\n";

    Sub_Pratition_Len sub_pratition_len = {0};
    FILE *fp = NULL;
    int ret = 0;

    char command_rsp[256] = {0};
    char command[256] = {0};
    File_Progress_Class fastboot_flash = {0};
    Partition_Flash_Flag partition_flash_flag = {0};
    Payload_Analysis payload_analysis = {0};

    char zenity_environment_variable[64] = {0};
    int environment_variable_length = 64;
    char set_zenity_environment_variable[256] = {0};

    memset(&fastboot_flash, 0 ,sizeof(File_Progress_Class));
    payload_analysis.ap_ver = (char*)malloc(sizeof(char)*64);
    payload_analysis.modem_ver = (char*)malloc(sizeof(char)*64);
    payload_analysis.dev_ver = (char*)malloc(sizeof(char)*64);
    payload_analysis.dev_ver_path = (char*)malloc(sizeof(char)*64);
    payload_analysis.oem_ver = (char*)malloc(sizeof(char)*64);
    payload_analysis.oem_ver_path = (char*)malloc(sizeof(char)*64);
    payload_analysis.op_ver = (char*)malloc(sizeof(char)*64);
    payload_analysis.op_ver_path = (char*)malloc(sizeof(char)*64);
    payload_analysis.flashpath = (char*)malloc(sizeof(char)*256);

    memset(payload_analysis.ap_ver, 0, sizeof(char)*64);
    memset(payload_analysis.modem_ver, 0, sizeof(char)*64);
    memset(payload_analysis.dev_ver, 0, sizeof(char)*64);
    memset(payload_analysis.dev_ver_path, 0, sizeof(char)*64);
    memset(payload_analysis.oem_ver, 0, sizeof(char)*64);
    memset(payload_analysis.oem_ver_path, 0, sizeof(char)*64);
    memset(payload_analysis.op_ver_path, 0, sizeof(char)*64);
    memset(payload_analysis.flashpath, 0, sizeof(char)*256);

    char *flashpath_bak = payload_analysis.flashpath;
    char *ap_ver_bak = payload_analysis.ap_ver;
    char *modem_ver_bak = payload_analysis.modem_ver;
    char *dev_ver_bak = payload_analysis.dev_ver;
    char *dev_ver_path_bak = payload_analysis.dev_ver_path;
    char *oem_ver_bak = payload_analysis.oem_ver;
    char *oem_ver_path_bak = payload_analysis.oem_ver_path;
    char *op_ver_bak = payload_analysis.op_ver;
    char *op_ver_path_bak = payload_analysis.op_ver_path;


    fibo_program_payload_analysis(payload,&payload_analysis,&partition_flash_flag);


    sub_pratition_len.ap = sizeof(ap_pratition) / sizeof(fibocom_pratition);
    sub_pratition_len.sbl = sizeof(sbl_pratition) / sizeof(fibocom_pratition);
    sub_pratition_len.modem = sizeof(modem_pratition) / sizeof(fibocom_pratition);
    sub_pratition_len.dev = sizeof(dev_pratition) / sizeof(fibocom_pratition);
    sub_pratition_len.oem = sizeof(oem_pratition) / sizeof(fibocom_pratition);
    sub_pratition_len.op = sizeof(op_pratition) /sizeof(fibocom_pratition);

    ret = fibocom_get_zenity_environment_variable(zenity_environment_variable,environment_variable_length);
    if(ret != RET_OK)
    {
        FIBO_LOG_ERROR("get zenity_environment_variable path error\n");
        /*If the progress bar envronment variable fails to be read,the burn proceduce is still executed
        return NULL;
        */
    }
    fibocom_strcat_zenity_environment_variable(zenity_environment_variable,set_zenity_environment_variable);

    FIBO_LOG_DEBUG("%s\n",set_zenity_environment_variable);

    fastboot_flash.progress_fp = NULL;
    strcpy(fastboot_flash.progress_title,"fwswitch_flash");
    strcpy(fastboot_flash.progress_text,"flash_start");
    sprintf(fastboot_flash.progress_command,
            "%s /usr/bin/zenity --progress --text=\"%s\" --percentage=%d --auto-close --no-cancel --width=600 --title=\"%s\"",
            set_zenity_environment_variable,fastboot_flash.progress_text, 10,fastboot_flash.progress_title);

    fastboot_flash.progress_fp = popen(fastboot_flash.progress_command,"w");
    g_usleep(1000*1000*2);

    int flash_pratition_num = 0;

    if(partition_flash_flag.ap!= 0)
        flash_pratition_num += 5;
    if(partition_flash_flag.modem!= 0)
        flash_pratition_num += 1;
    if(partition_flash_flag.dev!= 0)
        flash_pratition_num += 1;
    if(partition_flash_flag.oem!= 0)
        flash_pratition_num += 1;
    if(partition_flash_flag.op!= 0)
        flash_pratition_num += 1;

    int flash_pratition_percent = 99 / flash_pratition_num;
    int present_flash_pratition_percent = 0;

    if(partition_flash_flag.ap != 0) {
        for (int i = 0; i < sub_pratition_len.ap; i++) {
            switch (i) {
                case 0:
                    strcpy(fastboot_flash.progress_text, "#flash aboot,img_name=appsboot.mbn\n");
                    break;
                case 1:
                    strcpy(fastboot_flash.progress_text, "#flash boot,img_name=sdxnightjar-boot.img\n");
                    break;
                case 2:
                    strcpy(fastboot_flash.progress_text, "#flash system,img_name=sdxnightjar-sysfs.ubi\n");
                    break;
                case 3:
                    strcpy(fastboot_flash.progress_text, "#flash userdata,img_name=sdxnightjar-usrfs.ubi\n");
                    break;
                default:
                    break;
            }

            present_flash_pratition_percent += flash_pratition_percent;
            itoa(present_flash_pratition_percent, fastboot_flash.progress_percentage, 10);
            sprintf(fastboot_flash.progress_percentage, "%s", fastboot_flash.progress_percentage);
            fwrite(fastboot_flash.progress_text, sizeof(char), strlen(fastboot_flash.progress_text), fastboot_flash.progress_fp);
            fwrite(fastboot_flash.progress_percentage, sizeof(char), strlen(fastboot_flash.progress_percentage), fastboot_flash.progress_fp);

            fp = NULL;


            FIBO_LOG_DEBUG("payload_analysis->flashpath = %s %d\n",payload_analysis.flashpath,__LINE__);
            FIBO_LOG_DEBUG("payload_analysis->ap_ver = %s %d\n",payload_analysis.ap_ver,__LINE__);

            sprintf(command, "fastboot flash %s %s%s/%s", ap_pratition[i].lable, payload_analysis.flashpath, payload_analysis.ap_ver,
            ap_pratition[i].filename);
            FIBO_LOG_DEBUG("command = %s %d\n", command, __LINE__);

            fp = popen(command, "r");
            if (fp == NULL) {
                FIBO_LOG_DEBUG("command = %s %d\n", command, __LINE__);
                continue;
            }

            ret = pclose(fp);
            if (ret != RET_OK) {
                FIBO_LOG_DEBUG("command = %s %d\n", command, __LINE__);
                continue;
            }

            FIBO_LOG_DEBUG("fastboot_flash.progress_command = %s %d\n", fastboot_flash.progress_command, __LINE__);
            fflush(fastboot_flash.progress_fp);
            g_usleep(1000*1000*1);
        }

        if(ap_ver_bak) {
            free(ap_ver_bak);
        }
    }


    if(partition_flash_flag.ap != 0) {
        for (int i = 0; i < sub_pratition_len.sbl; i++) {
            switch (i) {
                case 0:
                    strcpy(fastboot_flash.progress_text, "#flash sbl,img_name=sbl1.mbn\n");
                    break;
                default:
                    break;
            }

            present_flash_pratition_percent += flash_pratition_percent;
            itoa(present_flash_pratition_percent, fastboot_flash.progress_percentage, 10);
            sprintf(fastboot_flash.progress_percentage, "%s\n", fastboot_flash.progress_percentage);
            fwrite(fastboot_flash.progress_text, sizeof(char), strlen(fastboot_flash.progress_text), fastboot_flash.progress_fp);
            fwrite(fastboot_flash.progress_percentage, sizeof(char), strlen(fastboot_flash.progress_percentage), fastboot_flash.progress_fp);

            fp = NULL;
            sprintf(command, "fastboot flash %s %s%s/%s", sbl_pratition[i].lable, payload_analysis.flashpath, "basic_update_img",
                    sbl_pratition[i].filename);

            FIBO_LOG_DEBUG("command = %s %d\n", command, __LINE__);

            fp = popen(command, "r");
            if (fp == NULL) {
                FIBO_LOG_DEBUG("command = %s %d\n", command, __LINE__);
                continue;
            }

            ret = pclose(fp);
            if (ret != RET_OK) {
                FIBO_LOG_DEBUG("%s command return error! %d\n", __func__, __LINE__);
                FIBO_LOG_DEBUG("command = %s %d\n", command, __LINE__);
                continue;
            }

            FIBO_LOG_DEBUG("fastboot_flash.progress_command = %s %d\n", fastboot_flash.progress_command, __LINE__);
            fflush(fastboot_flash.progress_fp);
            g_usleep(1000*1000*1);
        }
    }

    if(partition_flash_flag.modem != 0)
    {
        for (int i = 0; i < sub_pratition_len.modem; i++)
        {
            switch (i) {
                case 0:
                    strcpy(fastboot_flash.progress_text, "#flash modem,img_name=NON-HLOS.ubi\n");
                    fwrite(fastboot_flash.progress_text, sizeof(char), strlen(fastboot_flash.progress_text), fastboot_flash.progress_fp);
                    present_flash_pratition_percent += flash_pratition_percent;
                    itoa(present_flash_pratition_percent, fastboot_flash.progress_percentage, 10);
                    sprintf(fastboot_flash.progress_percentage, "%s\n", fastboot_flash.progress_percentage);
                    fwrite(fastboot_flash.progress_percentage, sizeof(char), strlen(fastboot_flash.progress_percentage), fastboot_flash.progress_fp);
                    fflush(fastboot_flash.progress_fp);
                    break;
                default:
                    break;
            }
            fp = NULL;
            sprintf(command, "fastboot flash %s %s%s/%s", modem_pratition[i].lable, payload_analysis.flashpath, payload_analysis.modem_ver, modem_pratition[i].filename);
            fp = popen(command, "r");
            if (fp == NULL)
            {
                FIBO_LOG_DEBUG("[%s]: execute command failed!\n", __func__);
                continue;
            }

            while(fgets(command_rsp, AT_COMMAND_LEN, fp) != NULL);

            ret = pclose(fp);
            if (ret != RET_OK)
            {
                FIBO_LOG_DEBUG("%s command return error! %d\n", __func__,__LINE__);
                continue;
            }
            fflush(fastboot_flash.progress_fp);
            g_usleep(1000*1000*1);
            if(modem_ver_bak) {
                free(modem_ver_bak);
            }
        }

        FIBO_LOG_DEBUG("fastboot_flash.progress_command = %s %d\n", fastboot_flash.progress_command, __LINE__);
    }

    if(partition_flash_flag.dev != 0)
    {
        strcpy(fastboot_flash.progress_text, "#flash dev,img_name=devicepack.ubi\n");
        fwrite(fastboot_flash.progress_text, sizeof(char), strlen(fastboot_flash.progress_text), fastboot_flash.progress_fp);
        fflush(fastboot_flash.progress_fp);

        for (int i = 0; i < sub_pratition_len.dev; i++)
        {
            switch (i) {
                case 0:
                    strcpy(fastboot_flash.progress_text, "#flash modem,img_name=devicepack.ubi\n");
                    fwrite(fastboot_flash.progress_text, sizeof(char), strlen(fastboot_flash.progress_text), fastboot_flash.progress_fp);
                    present_flash_pratition_percent += flash_pratition_percent;
                    itoa(present_flash_pratition_percent, fastboot_flash.progress_percentage, 10);
                    sprintf(fastboot_flash.progress_percentage, "%s\n", fastboot_flash.progress_percentage);
                    fwrite(fastboot_flash.progress_percentage, sizeof(char), strlen(fastboot_flash.progress_percentage), fastboot_flash.progress_fp);
                    fflush(fastboot_flash.progress_fp);
                    break;
                default:
                    break;
            }
            fp = NULL;
            sprintf(command, "fastboot flash %s %sDEV_OTA_PACKAGE/%s/%s", dev_pratition[i].lable, payload_analysis.flashpath, payload_analysis.dev_ver_path, dev_pratition[i].filename);
            fp = popen(command, "r");
            if (fp == NULL)
            {
                FIBO_LOG_DEBUG("[%s]: execute command failed!\n", __func__);
                continue;
            }

            while(fgets(command_rsp, AT_COMMAND_LEN, fp) != NULL);

            ret = pclose(fp);
            if (ret != RET_OK)
            {
                FIBO_LOG_DEBUG("%s command return error! %d\n", __func__,__LINE__);
                continue;
            }
        }
        FIBO_LOG_DEBUG("fastboot_flash.progress_command = %s %d\n", fastboot_flash.progress_command, __LINE__);
        fflush(fastboot_flash.progress_fp);
        g_usleep(1000*1000*1);
        if(dev_ver_bak) {
            free(dev_ver_bak);
        }
        if(dev_ver_path_bak) {
            free(dev_ver_path_bak);
        }
    }

    if(partition_flash_flag.oem != 0)
    {
        for (int i = 0; i < sub_pratition_len.oem; i++)
        {
            switch (i) {
                case 0:
                    strcpy(fastboot_flash.progress_text, "#flash oem,img_name=oempack.ubi\n");
                    fwrite(fastboot_flash.progress_text, sizeof(char), strlen(fastboot_flash.progress_text), fastboot_flash.progress_fp);
                    present_flash_pratition_percent += flash_pratition_percent;
                    itoa(present_flash_pratition_percent, fastboot_flash.progress_percentage, 10);
                    sprintf(fastboot_flash.progress_percentage, "%s\n", fastboot_flash.progress_percentage);
                    fwrite(fastboot_flash.progress_percentage, sizeof(char), strlen(fastboot_flash.progress_percentage), fastboot_flash.progress_fp);
                    fflush(fastboot_flash.progress_fp);
                    break;
                default:
                    break;
            }
            fp = NULL;
            sprintf(command, "fastboot flash %s %s%s/%s", oem_pratition[i].lable, payload_analysis.flashpath, payload_analysis.oem_ver_path, oem_pratition[i].filename);
            FIBO_LOG_DEBUG("command = %s %d\n", command, __LINE__);
            fp = popen(command, "r");
            if (fp == NULL)
            {
                FIBO_LOG_DEBUG("[%s]: execute command failed!\n", __func__);
                continue;
            }

            while(fgets(command_rsp, AT_COMMAND_LEN, fp) != NULL);

            ret = pclose(fp);
            if (ret != RET_OK)
            {
                FIBO_LOG_DEBUG("%s command return error! %d\n", __func__,__LINE__);
                continue;
            }
        }
        FIBO_LOG_DEBUG("fastboot_flash.progress_command = %s %d\n", fastboot_flash.progress_command, __LINE__);
        g_usleep(1000*1000*1);
        if(oem_ver_bak) {
            free(oem_ver_bak);
        }
        if(oem_ver_path_bak) {
            free(oem_ver_path_bak);
        }
    }

    if(partition_flash_flag.op != 0)
    {
        for (int i = 0; i < sub_pratition_len.op; i++)
        {
            switch (i) {
                case 0:
                    strcpy(fastboot_flash.progress_text, "#flash op,img_name=operatorpack.ubi\n");
                    fwrite(fastboot_flash.progress_text, sizeof(char), strlen(fastboot_flash.progress_text), fastboot_flash.progress_fp);
                    present_flash_pratition_percent += flash_pratition_percent;
                    itoa(present_flash_pratition_percent, fastboot_flash.progress_percentage, 10);
                    sprintf(fastboot_flash.progress_percentage, "%s\n", fastboot_flash.progress_percentage);
                    fwrite(fastboot_flash.progress_percentage, sizeof(char), strlen(fastboot_flash.progress_percentage), fastboot_flash.progress_fp);
                    fflush(fastboot_flash.progress_fp);
                    break;
                default:
                    break;
            }
            fp = NULL;
            sprintf(command, "fastboot flash %s %s%s/%s", op_pratition[i].lable, payload_analysis.flashpath, payload_analysis.op_ver_path, op_pratition[i].filename);
            fp = popen(command, "r");
            if (fp == NULL)
            {
                FIBO_LOG_DEBUG("[%s]: execute command failed!\n", __func__);
                continue;
            }

            while(fgets(command_rsp, AT_COMMAND_LEN, fp) != NULL);

            ret = pclose(fp);
            if (ret != RET_OK)
            {
                FIBO_LOG_DEBUG("%s command return error! %d\n", __func__,__LINE__);
                continue;
            }
        }
        FIBO_LOG_DEBUG("fastboot_flash.progress_command = %s %d\n", fastboot_flash.progress_command, __LINE__);
        fflush(fastboot_flash.progress_fp);
        g_usleep(1000*1000*1);
        if(op_ver_bak) {
            free(op_ver_bak);
        }
        if(op_ver_path_bak) {
            free(op_ver_path_bak);
        }
    }

    if(flashpath_bak) {
        free(flashpath_bak);
    }

    fibo_fastboot_reboot();

    strcpy(fastboot_flash.progress_text, "#flash successful\n");
    sprintf(fastboot_flash.progress_percentage, "%s\n", "99");
    fwrite(fastboot_flash.progress_text, sizeof(char), strlen(fastboot_flash.progress_text), fastboot_flash.progress_fp);
    fwrite(fastboot_flash.progress_percentage, sizeof(char), strlen(fastboot_flash.progress_percentage), fastboot_flash.progress_fp);
    fflush(fastboot_flash.progress_fp);
    g_usleep(1000*1000*2);
    ret = pclose(fastboot_flash.progress_fp);
    if (ret != RET_OK) {
        FIBO_LOG_DEBUG("%s command return error! %d\n", __func__, __LINE__);
    }

    return NULL;
}

gpointer fibocom_qdl_flash_command(gpointer payload)
{
    char *qdl_falash_path = "/opt/fibocom/fibo_fw_pkg/FwPackage/";
    char prog_nand_firehose_path[256] = {0};
    char rawprogram_nand_path[256] = {0};
    char patch_p2K_path[256] = {0};
    char qdl_flash_cmd[1024 + 512] = {0};
    FILE *qdl_fp = NULL;

    File_Progress_Class qdl_flash = {0};
    int qdl_flash_progress_current_percentage = 0;
    int count = 128;
    char buf[1024]= {0};
    int i = 0;

    int ret = 0;
    char zenity_environment_variable[64] = {0};
    int environment_variable_length = 64;
    char set_zenity_environment_variable[256] = {0};

    sprintf(prog_nand_firehose_path,"%sdownload_agent/prog_nand_firehose_9x55.mbn",qdl_falash_path);
    sprintf(rawprogram_nand_path,"%srawprogram_nand_p2K_b128K.xml",qdl_falash_path);
    sprintf(patch_p2K_path,"%sdownload_agent/patch_p2K_b128K.xml",qdl_falash_path);
    sprintf(qdl_flash_cmd,"/opt/fibocom/fibo_helper_service/fibo_helper_tools/qdl --storage nand --include %s %s %s %s",qdl_falash_path,prog_nand_firehose_path,rawprogram_nand_path,patch_p2K_path);

    ret = fibocom_get_zenity_environment_variable(zenity_environment_variable,environment_variable_length);
    if(ret != RET_OK)
    {
        FIBO_LOG_ERROR("get zenity_environment_variable path error\n");
        /*If the progress bar envronment variable fails to be read,the burn proceduce is still executed
        return NULL;
        */
    }
    fibocom_strcat_zenity_environment_variable(zenity_environment_variable,set_zenity_environment_variable);
    FIBO_LOG_DEBUG("%s %d\n",qdl_flash_cmd,__LINE__);

    strcpy(qdl_flash.progress_title,"recovery image");
    strcpy(qdl_flash.progress_text,"erase image\n");
    sprintf(qdl_flash.progress_command,
            "%s/usr/bin/zenity --progress --text=\"%s\" --percentage=%d --auto-close --no-cancel --width=600 --title=\"%s\"",
            set_zenity_environment_variable,qdl_flash.progress_text, qdl_flash.progress_percentage[0] ,qdl_flash.progress_title);

    usleep(1000*1000*1);
    qdl_flash.progress_fp = popen(qdl_flash.progress_command,"w");
    if (qdl_flash.progress_fp == NULL) {
        FIBO_LOG_DEBUG("[%s]: execute command failed!\n", __func__);
    }

    qdl_fp = popen(qdl_flash_cmd,"r");
    if (qdl_fp == NULL) {
        FIBO_LOG_DEBUG("[%s]: execute command failed!\n", __func__);
    }

    while(fgets(buf,count,qdl_fp)!=NULL)
    {
        if(strstr(buf,"Waiting for EDL device") != NULL)
        {
            strcpy(qdl_flash.progress_text,"#don't match 9008 port,exit program\n");
            fwrite(qdl_flash.progress_text, sizeof(char), strlen(qdl_flash.progress_text), qdl_flash.progress_fp);
            fflush(qdl_flash.progress_fp);
            g_usleep(1000*1000*1);
            pclose(qdl_fp);
            return NULL;
        }
        if(strstr(buf,"start_sector 0") != NULL)
        {
            FIBO_LOG_DEBUG("%s %d\n", buf,__LINE__);
            strcpy(qdl_flash.progress_text,"#erase partition successful,starting program image\n");
            qdl_flash_progress_current_percentage = 10;
            itoa(qdl_flash_progress_current_percentage, qdl_flash.progress_percentage, 10);
            sprintf(qdl_flash.progress_percentage, "%s\n", qdl_flash.progress_percentage);
            fwrite(qdl_flash.progress_text, sizeof(char), strlen(qdl_flash.progress_text), qdl_flash.progress_fp);
            fwrite(qdl_flash.progress_percentage, sizeof(char), strlen(qdl_flash.progress_percentage), qdl_flash.progress_fp);
            fflush(qdl_flash.progress_fp);
            g_usleep(1000*1000*1);
        }

        if(strstr(buf,"Finished sector address") != NULL)
        {
            i++;
            FIBO_LOG_DEBUG("%s %d\n", buf,__LINE__);
            switch(i)
            {
                case 1:
                    strcpy(qdl_flash.progress_text,"#starting program image SBL,filename=sbl1.mbn\n");
                    qdl_flash_progress_current_percentage = 15;
                    FIBO_LOG_DEBUG("%s %d\n", buf,__LINE__);
                    break;
                case 2:
                    strcpy(qdl_flash.progress_text,"#starting program image MIBIB,filename=partition_complete_p2K_b128K.mbn\n");
                    qdl_flash_progress_current_percentage = 20;
                    FIBO_LOG_DEBUG("%s %d\n", buf,__LINE__);
                    break;
                case 3:
                    strcpy(qdl_flash.progress_text,"#starting program image EFS2,filename=cefs.mbn\n");
                    qdl_flash_progress_current_percentage = 25;
                    break;
                case 4:
                    strcpy(qdl_flash.progress_text,"#starting program image efs2bak,filename=efs2bak.bin\n");
                    qdl_flash_progress_current_percentage = 30;
                    break;
                case 5:
                    strcpy(qdl_flash.progress_text,"#starting program image oeminfo,filename=oeminfo.bin\n");
                    qdl_flash_progress_current_percentage = 35;
                    break;
                case 6:
                    strcpy(qdl_flash.progress_text,"#starting program image TZ,filename=tz.mbn\n");
                    qdl_flash_progress_current_percentage = 40;
                    break;
                case 7:
                    strcpy(qdl_flash.progress_text,"#starting program image DEVCFG,filename=devcfg.mbn\n");
                    qdl_flash_progress_current_percentage = 45;
                    break;
                case 8:
                    strcpy(qdl_flash.progress_text,"#starting program image RPM,filename=rpm.mbn\n");
                    qdl_flash_progress_current_percentage = 50;
                    break;
                case 9:
                    strcpy(qdl_flash.progress_text,"#starting program image aboot,filename=appsboot.mbn\n");
                    qdl_flash_progress_current_percentage = 55;
                    break;
                case 10:
                    strcpy(qdl_flash.progress_text,"#starting program image boot,filename=sdxnightjar-boot.img\n");
                    qdl_flash_progress_current_percentage = 60;
                    break;
                case 11:
                    strcpy(qdl_flash.progress_text,"#starting program image modem,filename=NON-HLOS.ubi\n");
                    qdl_flash_progress_current_percentage = 70;
                    break;
                case 12:
                    strcpy(qdl_flash.progress_text,"#starting program image sec,filename=sec.dat\n");
                    qdl_flash_progress_current_percentage = 75;
                    break;
                case 13:
                    strcpy(qdl_flash.progress_text,"#starting program image system,filename=sdxnightjar-sysfs.ubi\n");
                    qdl_flash_progress_current_percentage = 85;
                    break;
                case 14:
                    strcpy(qdl_flash.progress_text,"#starting program image operatorpack,filename=operatorpack.ubi\n");
                    qdl_flash_progress_current_percentage = 90;
                    break;
                case 15:
                    strcpy(qdl_flash.progress_text,"#starting program image userdata,filename=sdxnightjar-usrfs.ubi\n");
                    qdl_flash_progress_current_percentage = 95;
                    break;
                case 16:
                    strcpy(qdl_flash.progress_text,"#starting program image oempack,filename=oempack.ubi\n");
                    qdl_flash_progress_current_percentage = 99;
                    break;
                default:
                    FIBO_LOG_DEBUG("%s %d\n","program error",__LINE__);
                    break;
            }

            itoa(qdl_flash_progress_current_percentage, qdl_flash.progress_percentage, 10);
            sprintf(qdl_flash.progress_percentage, "%s\n", qdl_flash.progress_percentage);
            fwrite(qdl_flash.progress_text, sizeof(char), strlen(qdl_flash.progress_text), qdl_flash.progress_fp);
            fwrite(qdl_flash.progress_percentage, sizeof(char), strlen(qdl_flash.progress_percentage), qdl_flash.progress_fp);
            fflush(qdl_flash.progress_fp);
            g_usleep(1000*1000*1);
        }

        if(16 == i)
        {
            strcpy(qdl_flash.progress_text,"#progress successful,rebooting module\n");
            qdl_flash_progress_current_percentage = 99;
            itoa(qdl_flash_progress_current_percentage, qdl_flash.progress_percentage, 10);
            sprintf(qdl_flash.progress_percentage, "%s\n", qdl_flash.progress_percentage);
            fwrite(qdl_flash.progress_text, sizeof(char), strlen(qdl_flash.progress_text), qdl_flash.progress_fp);
            fwrite(qdl_flash.progress_percentage, sizeof(char), strlen(qdl_flash.progress_percentage), qdl_flash.progress_fp);
            fflush(qdl_flash.progress_fp);
        }
    }
    g_usleep(1000*1000*1);
    pclose(qdl_fp);
    if (qdl_fp == NULL) {
        FIBO_LOG_DEBUG("[%s]: execute command failed!\n", __func__);
    }

    pclose(qdl_flash.progress_fp);
    if (qdl_flash.progress_fp == NULL) {
        FIBO_LOG_DEBUG("[%s]: execute command failed!\n", __func__);
    }

    return NULL;
}

gpointer edl_flashing_command(void *data)
{
    FIBO_LOG_ERROR("[%s]: ===========================================:%s\n",__func__, (char *)data);
    emit_edl_flash_status_signal("flashing...");
    if((char *)data)
    {
        FIBO_LOG_ERROR("[%s]: ===========================================:%s\n",__func__, (char *)data);
    }
    fibocom_qdl_flash_command((char *)data);
    emit_edl_flash_status_signal("flashing ok");
    FIBO_LOG_ERROR("[%s]:======================================== :%s\n",__func__, (char *)data);
}

gpointer fastboot_flashing_command(void *data)
{
    FIBO_LOG_ERROR("[%s]: ===========================================:%s\n",__func__, (char *)data);
    fibo_adapter_send_control_message_to_dbus(FLASH_FW_FASTBOOT, (int)strlen("fastboot flashing..."), "fastboot flashing...");
    //emit_fastboot_flash_status_signal("fastboot flashing...");
    if((char *)data)
    {
        fibocom_fastboot_flash_command((char *)data);
        fibo_adapter_send_control_message_to_dbus(FLASH_FW_FASTBOOT, (int)strlen("fastboot flashing ok"), "fastboot flashing ok");
        //emit_fastboot_flash_status_signal("fastboot flashing ok");
        FIBO_LOG_ERROR("[%s]:======================================== :%s\n",__func__, (char *)data);
    }
    if(data)
    {
        free(data);
    }
}


int fibocom_fastboot_flash_ready (MbimDevice   *device,
                             GAsyncResult *res,
                             gpointer userdata)
{
    g_autoptr(GError)                   error          =  NULL;
    guint32                             ret_size       =  0;
    const guint8                        *ret_str       =  NULL;
    g_autoptr(MbimMessage)              response       =  NULL;
    gchar                               resp_str[64]      =  {0};
    gint                                service_id      =  0;
    gint                                cid            =  0;
    gint                                rtcode         =  0;
    gboolean                            malloc_flag    =  TRUE;
    fibo_async_struct_type              *user_data     =  NULL;
    char *payload = NULL;
    gint payloadlen = 0;
    int ret = 0;


    FIBO_LOG_ERROR ("===============enter!\n");
    payload = malloc(sizeof(char) * 512);
    memset(payload,0,sizeof(char) * 512);

    user_data = (fibo_async_struct_type *)userdata;

    if (!user_data) {
        FIBO_LOG_ERROR ("NULL pointer!\n");
    }
    else {
        service_id = user_data->serviceid;
        cid = user_data->cid;
        memcpy(payload,user_data->payload_str, user_data->payloadlen);
        FIBO_LOG_DEBUG("%s     %d", payload,__LINE__);
    }

    if (userdata) {
        free(userdata);
        userdata = NULL;
    }

    char get_qdl_port_cmd[128] = "lsusb | grep \"Fibocom Fibocom FM101 Modem\" | awk -F ' ' 'NR=6 {print $6}'";
    FILE *get_port_fp =NULL;
    get_port_fp = popen(get_qdl_port_cmd,"r");
    usleep(1000*1000*3);
    if(get_port_fp == NULL) {
        FIBO_LOG_DEBUG("open get_port_cmd error\n");
    }
    pclose(get_port_fp);

    sprintf(resp_str,"fastboot_flashing");

    ret = alloc_and_send_resp_structure(service_id, cid, rtcode, strlen(resp_str), resp_str);

    fibo_mutex_keep_pointer_exist_unlock();

    if (ret != RET_OK) {
        FIBO_LOG_ERROR("send resp to main loop failed!\n");
    }

    FIBO_LOG_DEBUG("%s     %d", payload,__LINE__);
    GThread *gthread_fastboot_flash = NULL;
    gthread_fastboot_flash = g_thread_new("fastboot_flash", fastboot_flashing_command, payload);

    return TRUE;
}
/*--------------------------------------qdl flash && fastboot flash end------------------------------------------------*/

/*--------------------------------------Above are External Funcs-------------------------------------------------------*/

