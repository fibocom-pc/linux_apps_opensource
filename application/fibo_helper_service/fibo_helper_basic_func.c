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
#include <fcntl.h>
#include <sys/stat.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

fibocom_request_table_type supported_request_table[] = {

    {RESET_MODEM_SW,                       fibo_parse_send_req_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+CFUN=15"},
    {CTL_MBIM_INIT,                        fibo_resp_error_result,         NULL,                                                 ""},
    {CTL_MBIM_DEINIT,                      fibo_resp_error_result,         NULL,                                                 ""},
    {CTL_MBIM_NO_RESP,                     fibo_resp_error_result,         NULL,                                                 ""},

    {CTL_MBIM_SUBSCRIBER_READY_QUERY,      fibo_resp_error_result,         NULL,                                                 ""},
    {CTL_MBIM_HOME_PROVIDER_QUERY,         fibo_resp_error_result,         NULL,                                                 ""},
    {CTL_MBIM_REGISTER_STATE_QUERY,        fibo_resp_error_result,         NULL,                                                 ""},
    {CTL_MBIM_SLOT_INFO_QUERY,             fibo_resp_error_result,         NULL,                                                 ""},
    {CTL_MBIM_SLOT_MAPPING_QUERY,          fibo_resp_error_result,         NULL,                                                 ""},
    {CTL_MBIM_SLOT_MAPPING_SET,            fibo_resp_error_result,         NULL,                                                 ""},

    /* FWswitch service command list */
    {GET_AP_VERSION,                       fibo_parse_send_req_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+GTSAPFWVER?"},
    {GET_MD_VERSION,                       fibo_parse_send_req_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+CGMR"},
    {GET_OP_VERSION,                       fibo_parse_send_req_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+GTCUSTPACKVER?"},
    {GET_OEM_VERSION,                      fibo_parse_send_req_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+GTCFGELEMVER?"},
    {GET_DEV_VERSION,                      fibo_parse_send_req_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+GTDEVPACKVER?"},
    {GET_IMEI,                             fibo_parse_send_req_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+CGSN"},
    {GET_MCCMNC,                           fibo_parse_mbim_request,        fibo_helperm_get_local_mccmnc_ready,                  ""},
    {GET_SUBSYSID,                         fibo_parse_send_req_atcmd,      fibocom_get_subsysid_ready,                           "AT"},
    {SET_ATTACH_APN,                       fibo_parse_send_req_atcmd,      NULL,                                                 ""},
    {FLASH_FW_FASTBOOT,                    fibo_parse_send_req_atcmd,      fibocom_fastboot_flash_ready,                         "at+syscmd=sys_reboot bootloader"},

    /* FWrecovery service command list */
    {GET_PORT_STATE,                       fibo_resp_error_result,         NULL,                                                 "AT"},
    {GET_OEM_ID,                           fibo_parse_send_req_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+GTOEMUSBID?"},
    {RESET_MODEM_HW,                       fibo_resp_error_result,         NULL,                                                 ""},
    {FLASH_FW_EDL,                         fibo_resp_error_result,         NULL,                                                 "at+syscmd=sys_reboot edl"},

    /* MA service command list */
    {GET_FCCLOCK_STATUS,                   fibo_parse_send_req_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+GTFCCEFFSTATUS?"},
    {GET_MODEM_RANDOM_KEY,                 fibo_parse_send_req_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+GTFCCLOCKGEN"},
    {SET_FCC_UNLOCK,                       fibo_parse_send_set_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+GTFCCLOCKVER="},

    /* config service command list */
    {SET_BODYSAR_ENABLE,                   fibo_parse_send_set_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+BODYSAREN="},
    {GET_BODYSAR_STATUS,                   fibo_parse_send_req_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+BODYSAREN?"},
    {GET_BODYSAR_CTRL_MODE,                fibo_parse_send_req_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+BODYSARMODE?"},
    {SET_BODYSAR_CTRL_MODE,                fibo_parse_send_set_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+BODYSARMODE="},
    {SET_BODYSAR_INDEX,                    fibo_parse_send_set_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+BODYSARON=1,"},
    {SET_BODYSAR_CFG_DATA,                 fibo_resp_error_result,         NULL,                                                 "AT+BODYSARCFG="},
    {SET_BODYSAR_VER,                      fibo_parse_send_set_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+BODYSARVER="},
    {GET_BODYSAR_VER,                      fibo_parse_send_req_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+BODYSARVER?"},
    {SET_ANTENNA_ENABLE,                   fibo_parse_send_set_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+GTANTTUNINGEN="},
    {GET_ANTENNA_STATUS,                   fibo_parse_send_req_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+GTANTTUNINGEN?"},
    {SET_ANTENNA_CTRL_MODE,                fibo_parse_send_set_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+GTANTCTRLMODE="},
    {GET_ANTENNA_CTRL_MODE,                fibo_parse_send_req_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+GTANTCTRLMODE?"},
    {SET_ANTENNA_WORK_MODE,                fibo_parse_send_set_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+GTANTTUNEMODE="},
    {GET_ANTENNA_WORK_MODE,                fibo_parse_send_req_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+GTANTTUNEMODE?"},
    {SET_ANTENNA_VER,                      fibo_parse_send_set_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+GTANTVER="},
    {GET_ANTENNA_VER,                      fibo_parse_send_req_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+GTANTVER?"},
    {SET_ANTENNA_INDEX,                    fibo_parse_send_set_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+GTANTPROFILE="},
    {SET_FCCLOCK_ENABLE,                   fibo_parse_send_set_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+GTFCCLOCKMODE="},
    {GET_NET_WORK_TYPE,                    fibo_parse_send_req_atcmd,      fibo_parse_send_atcmd_ready,                          ""},
    {SET_WDISABLE_ENABLE,                  fibo_parse_send_set_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+GTFMODE="},
    {GET_WDISABLE_STATUS,                  fibo_parse_send_req_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+GTFMODE?"},
    {SET_GNSS_ENABLE,                      fibo_parse_send_set_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+GTGPSPOWER="},
    {GET_GNSS_STATUS,                      fibo_parse_send_req_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+GTGPSPOWER?"},
    {GET_DISABLE_ESIM_STATUS,              fibo_parse_send_req_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+GTESIMCFG?"},
    {SET_DISABLE_ESIM,                     fibo_parse_send_set_atcmd,      fibo_parse_send_atcmd_ready,                          "AT+GTESIMCFG="},
    {GET_FW_INFO,                          fibo_parse_send_req_atcmd,      fibo_parse_send_atcmd_ready,                          "ATI7"},
    {GET_NETWORK_MCCMNC,                   fibo_parse_mbim_request,        fibo_helperm_get_network_mccmnc_ready,                ""},
    {GET_SIM_SLOTS_STATUS,                 fibo_parse_mbim_request,        fibo_helperm_get_work_slot_id_ready,                  ""},
    {SET_SIM_SLOTS,                        fibo_parse_mbim_request,        fibo_helperm_get_work_slot_id_ready,                  ""},
    /* config service list is not finished. */

    {ENUM_CID_MAX,                         fibo_resp_error_result,         NULL,                                                 ""}
};

/* 全局变量 */
FibocomGdbusHelper     *skeleton           = NULL;
extern GMainLoop       *gMainLoop;
gboolean               g_data_updated      = FALSE;
fibo_async_struct_type *user_data1         = NULL;
FibocomGdbusHelper     *g_skeleton         = NULL;
static MMManager       *proxy              = NULL;
gchar                  g_local_mccmnc[8]   = {0};
gchar                  g_roam_mccmnc[8]    = {0};
static gboolean        g_sim_inserted_flag = FALSE;
gint                   g_current_svcid     = 0;
gint                   g_current_cid       = 0;

static int g_hwreset_gpio = 0;

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

typedef struct {
    int oemid;
    char *pidvid;
    char *skuid;
    int gpio;
}Machine_Skuid_Gpio;

Machine_Skuid_Gpio machine_skuid_gpio[] = {
        {1, "", "0CB2", 717},
        {1, "", "0CB3", 717},
        {1, "", "0CB4", 595},
        {1, "", "0CC1", 883},
        {1, "", "0CC4", 883},
        {1, "", "0CC5", 595},
        {1, "", "0CC3", 595},
        {1, "", "0CB5", 717},
        {1, "", "0CB7", 595},
        {1, "", "0CB9", 717},
        {1, "", "0CBA", 717},
        {1, "", "0CBB", 717},
        {1, "", "0CBC", 595},
        {1, "", "0CBD", 883},
        {1, "", "0CBF", 883},
        {1, "", "0C99", 647},
        {1, "", "0C9A", 647},
        {1, "", "0C97", 596},
        {1, "", "0C98", 596},
        {1, "", "0CC0", 0},
        /*The following are test models*/
        {1, "", "0C0D", 595},
        {1, "", "0B03", 595},
        {1, "", "0C0B", 595},
};

/*--------------------------------------Below are Internal Funcs-------------------------------------------------------*/

int fibocom_get_skuid(char *skuid)
{
    int ret = 0;
    FILE *get_skuid_fp = NULL;
    char get_skuid_cmd[64] = "dmidecode -t 1 | grep SKU | awk -F ' ' '{print$3}'";
    get_skuid_fp = popen(get_skuid_cmd, "r");
    if(get_skuid_fp == NULL){
        FIBO_LOG_CRITICAL("popen get_skuid_cmd error");
        return RET_ERROR;
    }

    ret = fread(skuid, sizeof(char), 32, get_skuid_fp);
    if(ret == RET_ERROR){
        FIBO_LOG_CRITICAL("fread get_skuid_cmd error\n");
        return RET_ERROR;
    }

    FIBO_LOG_CRITICAL("get_skuid_cmd == %s\n", skuid);

    pclose(get_skuid_fp);

    return RET_OK;
}


int fibocom_get_current_mackine_hwreset_gpio(char *skuid, int *gpio)
{
    int machine_skuid_gpio_len = sizeof(machine_skuid_gpio) / sizeof(Machine_Skuid_Gpio);
    int i = 0;

    if (skuid == NULL){
        FIBO_LOG_CRITICAL("skuid is null\n");
        return RET_ERROR;
    }

    for (i = 0; i < machine_skuid_gpio_len; ++i){
        if(strstr(skuid, machine_skuid_gpio[i].skuid) == NULL){
            continue;
        }else{
            *gpio = machine_skuid_gpio[i].gpio;
            FIBO_LOG_DEBUG("find skuid form machine_skuid_gpio\n");
            break;
        }
    }

    if(i == machine_skuid_gpio_len){
        FIBO_LOG_DEBUG("don't find skuid form machine_skuid_gpio\n");
        return RET_ERROR;
    }

    return RET_OK;
}

int fibocom_hwreset_gpio_set(int gpio, int type)
{
    FILE *set_gpio_fp = NULL;
    char set_gpio_cmd[64] = {0};
    int ret = 0;

    if(type == 1 || type == 0) {
        sprintf(set_gpio_cmd, "echo %d > /sys/class/gpio/gpio%d/value", type, gpio);
    }
    else{
        FIBO_LOG_CRITICAL("invalid type\n");
        return RET_ERROR;
    }

    set_gpio_fp = popen(set_gpio_cmd, "r");
    if(set_gpio_fp == NULL){
        FIBO_LOG_CRITICAL("popen ste_gpio_fp error\n");
        perror("popen ste_gpio_fp error\n");
        return RET_ERROR;
    }

    pclose(set_gpio_fp);
    return RET_OK;
}

int fibocom_hwreset_gpio_init_sub(int gpio)
{
    FILE *gpio_init_fp = NULL;
    char gpio_init_cmd[64] = {0};
    int ret = 0;

    if(0 == access("/sys/class/gpio/export", F_OK)) {
        FIBO_LOG_WARNING("/sys/class/gpio/export exists.\n");
    } else {
        FIBO_LOG_WARNING("/sys/class/gpio/export does not exist.\n");
    }

    sprintf(gpio_init_cmd,"echo %d > /sys/class/gpio/export",gpio);
    gpio_init_fp = popen(gpio_init_cmd, "w");
    if(gpio_init_fp == NULL){
        FIBO_LOG_CRITICAL("popen gpio_init_fp error\n");
        perror("popen gpio_init_fp error\n");
        return RET_ERROR;
    }

    ret = fibocom_hwreset_gpio_set(gpio, 1);
    if(ret == RET_ERROR){
        FIBO_LOG_CRITICAL("set gpio %d error", gpio);
        return RET_ERROR;
    }

    sprintf(gpio_init_cmd,"echo out > /sys/class/gpio/gpio%d/direction",gpio);
    ret = fwrite(gpio_init_cmd,sizeof(char),strlen(gpio_init_cmd) + 1,gpio_init_fp);
    if(ret == 0){
        FIBO_LOG_CRITICAL("fwrite gpio_init_fp error\n");
        perror("fwrite gpio_init_fp error\n");
        return RET_ERROR;
    }

    pclose(gpio_init_fp);

    return RET_OK;
}

int fibocom_hwreset_gpio_init(void)
{
    int ret = 0;
    char skuid[32] = {0};

    ret = fibocom_get_skuid(skuid);
    if(ret == RET_ERROR){
        FIBO_LOG_CRITICAL("Get Skuid error\n");
        return ret;
    }

    ret = fibocom_get_current_mackine_hwreset_gpio(skuid, &g_hwreset_gpio);
    if(ret == RET_ERROR){
        FIBO_LOG_CRITICAL("Get hwreset gpio error\n");
        return ret;
    }

    ret = fibocom_hwreset_gpio_init_sub(g_hwreset_gpio);
    if(ret == RET_ERROR){
        FIBO_LOG_CRITICAL("set gpio %d error\n", g_hwreset_gpio);
        return ret;
    }
    return ret;
}

int fibocom_reset_modem_hw_ready(void)
{
    char *skuid = NULL;
    int ret = 0;

    ret = fibocom_hwreset_gpio_set(g_hwreset_gpio, 0);
    if(ret == RET_ERROR){
        FIBO_LOG_CRITICAL("set hwreset gpio %d to 0 error\n", g_hwreset_gpio);
        return ret;
    }

    ret = fibocom_hwreset_gpio_set(g_hwreset_gpio, 1);
    if(ret == RET_ERROR){
        FIBO_LOG_CRITICAL("set hwreset gpio %d to 1 error\n", g_hwreset_gpio);
        return ret;
    }

    return ret;
}

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
    FIBO_LOG_DEBUG("rtcode: %d\n", rtcode);
    FIBO_LOG_DEBUG("len: %d\n", payloadlen);
    FIBO_LOG_DEBUG("str: \"%s\"\n", payload_str);

    table_len = sizeof(supported_request_table) / sizeof(fibocom_request_table_type);

    // further: add customized tables on different modules, try check commands on its customized tables, if fail, check commands on common tables secondly.
    // if one module has customized AT command, should add it to customized tables only.
    for (i = 0; i < table_len; i++) {
        if (supported_request_table[i].cid == cid) {
            matched_flag = TRUE;
            ret = supported_request_table[i].func_pointer(serviceid, cid, rtcode, payloadlen, payload_str, supported_request_table[i].callback, supported_request_table[i].at_amd);
            break;
        }
    }

    if (ret != RET_OK || !matched_flag) {
        FIBO_LOG_ERROR("Execute error or not matched! will call default resp!\n");
        fibo_resp_error_result(serviceid, cid, rtcode, payloadlen, payload_str, NULL, NULL);
        return RET_ERROR;
    }

    FIBO_LOG_DEBUG("finished!\n");
    return RET_OK;
}

static gint
request_transmitter(FibocomGdbusHelper     *skeleton,
                      GDBusMethodInvocation  *invocation,
                      GVariant               *str)
{
    int                    ret             = RET_ERROR;
    helper_message_struct  *msgs           = NULL;
    fibo_async_struct_type *user_data      = NULL;

    gint                   serviceid       = RET_ERROR;
    gint                   cid             = RET_ERROR;
    gint                   rtcode          = RET_ERR_PROCESS;
    gint                   payloadlen      = 0;
    gchar                  *payload_str    = NULL;
    GVariant               *resp_str       = NULL;
    gboolean               mismatched_flag = FALSE;

    FIBO_LOG_DEBUG("enter! helper get request! req struct size: %ld\n", sizeof(fibo_async_struct_type));

    g_variant_get(str, "((ii)iis)", &serviceid, &cid, &rtcode, &payloadlen, &payload_str);

    user_data = (fibo_async_struct_type *)malloc(sizeof(fibo_async_struct_type) + payloadlen + 1);
    if (user_data == NULL)
    {
        FIBO_LOG_ERROR("malloc failed!\n");
        rtcode = RET_ERR_PROCESS;
        fibo_adapter_helperd_send_resp_to_dbus(skeleton, g_object_ref(invocation), serviceid, cid, rtcode, payloadlen, payload_str);
        // g_variant_unref(str);
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

    switch(user_data->cid)
    {
        case GET_PORT_STATE: {
            char *get_port_resp_str = NULL;
            get_port_resp_str = (char *) malloc(sizeof(char) * 16);
            memset(get_port_resp_str, 0, 16);
            fibocom_get_port_command_ready(get_port_resp_str);
            payloadlen = strlen(get_port_resp_str);
            fibo_adapter_helperd_send_resp_to_dbus(skeleton, g_object_ref(invocation), user_data->serviceid,
                                                   user_data->cid, user_data->rtcode, payloadlen, get_port_resp_str);
            if (get_port_resp_str) {
                free(get_port_resp_str);
            }

            if (user_data) {
                free(user_data);
                user_data = NULL;
            }

            // g_variant_unref(str);
            return RET_OK;
        }

        case RESET_MODEM_HW: {
            ret = fibocom_reset_modem_hw_ready();
            if (ret == RET_ERROR)
            {
                memcpy(payload_str,"reset_modem_hw_fail", strlen("reset_modem_hw_fail") + 1);
                payloadlen = strlen("reset_modem_hw_fail") + 1;
                user_data->rtcode = 1;
            }
            else{
                memcpy(payload_str,"reset_modem_hw_success", strlen("reset_modem_hw_success") + 1);
                payloadlen = strlen("reset_modem_hw_success") + 1;
            }
            fibo_adapter_helperd_send_resp_to_dbus(skeleton, g_object_ref(invocation), user_data->serviceid, user_data->cid, user_data->rtcode,payloadlen, payload_str);
            if(user_data) {
                free(user_data);
                user_data = NULL;
            }

            return RET_OK;
        }
        case FLASH_FW_EDL: {
            char qdl_resp_str[32] = "edl flashing";
            char *qdl_port_status = NULL;
            char *edl_payload  = NULL;

            edl_payload = malloc(sizeof(char) * 64);
            memset(edl_payload, 0, 64);
            memcpy(edl_payload,payload_str,user_data->payloadlen);

            payloadlen = (gint)strlen(qdl_resp_str);

            qdl_port_status = malloc(sizeof(char) * 64);
            memset(qdl_port_status,0,64);
            fibocom_get_port_command_ready(qdl_port_status);

            if (strstr(qdl_port_status,"flashport") != NULL) {
                GThread *gthread_edl_flash = NULL;
                gthread_edl_flash = g_thread_new("edl_flash", edl_flashing_command, edl_payload);
                fibo_adapter_helperd_send_resp_to_dbus(skeleton, g_object_ref(invocation), serviceid, cid, rtcode, payloadlen, qdl_resp_str);

                if(user_data) {
                    free(user_data);
                    user_data = NULL;
                }
                return RET_OK;
            }
        }
        default:
            FIBO_LOG_DEBUG("Not special req, send req to helperm to deal!\n");
    }

    msgs = (helper_message_struct *)malloc(2048 * sizeof(char));
    if (msgs == NULL)
    {
        FIBO_LOG_ERROR("malloc failed!\n");
        rtcode = RET_ERR_PROCESS;
        fibo_adapter_helperd_send_resp_to_dbus(skeleton, g_object_ref(invocation), serviceid, cid, rtcode, payloadlen, payload_str);
        if(user_data) {
            free(user_data);
            user_data = NULL;
        }

        // g_variant_unref(str);
        return RET_ERROR;
    }
    memset(msgs, 0, 2048);

    memcpy(msgs->mtext, user_data, sizeof(fibo_async_struct_type) + payloadlen);
    msgs->mtype = 1;

    ret = fibo_adapter_helperd_send_req_to_helperm(msgs, 2048);
    if (ret != RET_OK) {

        FIBO_LOG_ERROR("Send message failed!\n");
        free(msgs);
        msgs = NULL;

        // if msgsnd func return error, will trigger a default resp func to caller.
        rtcode = RET_ERR_PROCESS;
        fibo_adapter_helperd_send_resp_to_dbus(skeleton, g_object_ref(invocation), serviceid, cid, rtcode, payloadlen, payload_str);
        // g_variant_unref(str);
        return RET_ERROR;
    }

    //below two global variables are only used on timer callback, aims to send resp to helperd itself.
    g_current_svcid = serviceid;
    g_current_cid   = cid;

    if (user_data) {
        free(user_data);
        user_data = NULL;
    }

    // add a workaround logic on below scenario:
    // step 1. helperd send request to helperm.
    // step 2. helperd crash or user restart helperd, helperm is working at same time.
    // step 3. helperd init message queue finished, then helperm send resp to message queue.
    // step 4. helperd get new request, send message to helperm and get previous resp.
    // step 5. helperd return error and get new request, helperm solve previous request, repeat step 4.
    // this will cause helperd always return mismatched error and can't work at all.
    // so here add mechanism as below:
    // 1. if helperd get mismatched message first time, will retry to get response message again.
    // 2. based on 1, if helperd get mismatched secondly, will send error directly.
    // 3. based on 1, if helperd get correct resp secondly, will exit do-while and executed normally.
    // 4. on normal scenario, flag is set to false by default, and won't get mismatched message, so normal logic can work as expect.
    // 5. Cause helperd is strictly synchronized function, there will be 2 messages at most(one is previous message, then helperd restart and get new message).

    do {
        fibo_adapter_helperd_timer_handle();

        memset(msgs, 0, 2048);

        ret = fibo_adapter_helperd_get_normal_msg_from_helperm(msgs);
        fibo_adapter_helperd_timer_close();
        if (RET_ERROR == ret)
        {
            FIBO_LOG_DEBUG("Get message failed!\n");
            free(msgs);
            msgs = NULL;

            // if msgrcv func return error, will trigger a default resp func to caller.
            rtcode = RET_ERR_PROCESS;
            fibo_adapter_helperd_send_resp_to_dbus(skeleton, g_object_ref(invocation), serviceid, cid, rtcode, payloadlen, payload_str);
            // g_variant_unref(str);
            return RET_ERROR;
        }

        user_data = (fibo_async_struct_type *)msgs->mtext;

        FIBO_LOG_DEBUG("len:%d\n", user_data->payloadlen);

        rtcode = user_data->rtcode;

        if (user_data->cid != cid || user_data->serviceid != serviceid) {
            if (mismatched_flag == FALSE) {
                FIBO_LOG_ERROR("Get mismatched message, drop it and retry to get response!\n");
                mismatched_flag = TRUE;
            }
            else {
                FIBO_LOG_ERROR("Get mismatched message again! return error to dbus!\n");
                rtcode = RET_ERR_PROCESS;
                break;
            }
        } else {
            mismatched_flag = FALSE;
        }
    } while (mismatched_flag == TRUE);

    fibo_adapter_helperd_send_resp_to_dbus(skeleton, g_object_ref(invocation), serviceid, cid, rtcode, user_data->payloadlen, user_data->payload_str);

    free(msgs);
    msgs = NULL;
    user_data = NULL;

    FIBO_LOG_DEBUG("Helper send resp!\n");
    // g_variant_unref(str);
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
        FIBO_LOG_ERROR("NULL pointer! won't register any signal!\n");
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
        FIBO_LOG_ERROR("NULL pointer! won't register any signal!\n");
        return;
    }

    GError             *error             = NULL;
    GThread            *receive_thread    = NULL;
    // FibocomGdbusHelper *skeleton          = NULL;

    g_skeleton = fibocom_gdbus_helper_skeleton_new();

    // main loop will send message to message queue and wait for return value, so main loop will be blocked.
    g_signal_connect(g_skeleton, "handle-send-mesg", G_CALLBACK(request_transmitter), NULL);

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
        // further:
        // 1. if modemmanager missing, free global handle.
        // 2. if modemmanager existed, re-connect it to modemmananger.
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
        FIBO_LOG_ERROR("don't get current network mccmnc!\n");
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
    MMModem3gpp *modem_3gpp  = NULL;
    int         ret          = RET_ERROR;

    FIBO_LOG_DEBUG("enter!\n");

    // although object add event will be triggered on module insert and sim card insert, we don't deal with modem insert cause modemmanager will get modem firstly and get sim card secondly!
    if (NULL == gmodem_object)
    {
        printf("can't get modem object, so consider no change on SIM card!\n");
        return;
    }

    // if local mccmnc changed, emit local mccmnc change signal.
    modem = mm_object_peek_modem(gmodem_object);

    // step1: verify whether sim card is inserted.
    sim_obj = mm_modem_get_sim_sync(modem, NULL, &error);
    if (NULL == sim_obj)
    {
        FIBO_LOG_ERROR("Can't find sim card!\n");
        return;
    }

    FIBO_LOG_ERROR("SIM card inserted!\n");

    fibo_adapter_mutex_sim_insert_flag_operate_lock();
    g_sim_inserted_flag = TRUE;
    fibo_adapter_mutex_sim_insert_flag_operate_unlock();

    if (g_skeleton != NULL)
        fibocom_gdbus_helper_emit_simcard_change(g_skeleton, "SIM CARD inserted!");
    else
        FIBO_LOG_ERROR("variable is NULL, don't send cellular info signal!\n");

    // step2: get sim card's mccmnc.
    // further: use mbim message to get local mccmnc.
/*
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
            FIBO_LOG_ERROR("variable is NULL, don't send cellular info signal!\n");
    }
*/

    // signal callback only send request to control pipe, notice helperm to use mbim message to check local mccmnc, it should not be NULL.
    // and helperm will send resp to control pipe, helperd should check NULL, update it to global variable and emit a signal to higher service.
    ret = fibo_adapter_helperd_send_control_message_to_helperm(CTL_MBIM_HOME_PROVIDER_QUERY, 0, NULL);
    if (ret != RET_OK) {
        FIBO_LOG_ERROR("send control message failed!\n");
    }
    g_object_unref(sim_obj);

// further: this callback will be executed by mainloop, so that it can't blocked or wait! should use sync func to query network mccmnc!
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

// object remove event will be triggered when either modem removed or SIM card removed.
static void mm_plugin_object_removed_cb(MMManager *manager, MMObject *modem)
{
    int ret = RET_ERROR;
    int res = RET_ERROR;

    FIBO_LOG_DEBUG("enter!\n");

    // check module state firstly, if module exist, then report sim card remove, otherwise will do nothing.
    ret = fibo_adapter_check_cellular(&res);
    if (ret != RET_OK || res != RET_OK) {
        FIBO_LOG_ERROR("Found cellular missing, do nothing cause udev will send cellular state signal!\n");
        return;
    }

    // step2: check whether SIM card inserted before.
    if (!g_sim_inserted_flag) {
        FIBO_LOG_DEBUG("don't find SIM card inserted before, invalid object remove event!\n");
        return;
    }

    fibo_adapter_mutex_sim_insert_flag_operate_lock();
    g_sim_inserted_flag = FALSE;
    fibo_adapter_mutex_sim_insert_flag_operate_unlock();

    FIBO_LOG_ERROR("SIM card removed!\n");

    if (g_skeleton != NULL)
        fibocom_gdbus_helper_emit_simcard_change(g_skeleton, "SIM CARD removed!");
    else
        FIBO_LOG_ERROR("variable is NULL, don't send cellular info signal!\n");

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
    FIBO_LOG_ERROR("[%s]:flash changed!\n", __func__);
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
    FIBO_LOG_ERROR("[%s]:flash changed!\n", __func__);
    return FALSE;
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

        ret = fibo_adapter_helperd_get_control_msg_from_helperm(msgs);
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
                else if(strstr(user_data->payload_str, "fastboot flash ok") != NULL) {
                    FIBO_LOG_DEBUG("--------------------------------------------------------------------\n");
                    emit_fastboot_flash_status_signal("fastboot flash ok");
                }
                else if(strstr(user_data->payload_str, "fastboot flash fail") != NULL) {
                    FIBO_LOG_DEBUG("--------------------------------------------------------------------\n");
                    emit_fastboot_flash_status_signal("fastboot flash fail");
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
            case CTL_MBIM_HOME_PROVIDER_IND:
                FIBO_LOG_DEBUG("get HOME_PROVIDER resp!\n");
                if (user_data->payloadlen == 0) {
                    FIBO_LOG_ERROR("NULL pointer!\n");
                    continue;
                }

                if (strcmp(g_local_mccmnc, user_data->payload_str) == 0) {
                    FIBO_LOG_DEBUG("same local mccmnc, abort signal emit process!\n");
                    continue;
                }

                FIBO_LOG_DEBUG("local mccmnc changed from %s to %s\n", g_local_mccmnc, user_data->payload_str);
                memset(g_local_mccmnc, 0, sizeof(g_local_mccmnc));
                strncpy(g_local_mccmnc, user_data->payload_str, user_data->payloadlen);

                if (g_skeleton != NULL)
                    fibocom_gdbus_helper_emit_simcard_change(g_skeleton, "local mccmnc changed!");
                else
                    FIBO_LOG_ERROR("variable is NULL, don't send local mccmnc change signal!\n");
                break;
            case CTL_MBIM_REGISTER_STATE_IND:
                FIBO_LOG_DEBUG("get REGISTER_STATE resp!\n");
                if (user_data->payloadlen == 0) {
                    FIBO_LOG_ERROR("NULL pointer!\n");
                    continue;
                }

                if (strcmp(g_roam_mccmnc, user_data->payload_str) == 0) {
                    FIBO_LOG_DEBUG("same roam mccmnc, abort signal emit process!\n");
                    continue;
                }

                FIBO_LOG_DEBUG("roam mccmnc changed from %s to %s\n", g_roam_mccmnc, user_data->payload_str);
                memset(g_roam_mccmnc, 0, sizeof(g_roam_mccmnc));
                strncpy(g_roam_mccmnc, user_data->payload_str, user_data->payloadlen);

                if (g_skeleton != NULL)
                    fibocom_gdbus_helper_emit_roam_region(g_skeleton, "roam mccmnc changed!");
                else
                    FIBO_LOG_ERROR("variable is NULL, don't send roam mccmnc change signal!\n");
                break;
            case CTL_MBIM_SUBSCRIBER_READY_IND:
                FIBO_LOG_DEBUG("get SUBSCRIBER_READY_STATUS resp!\n");
                if (user_data->payloadlen == 0) {
                    FIBO_LOG_ERROR("NULL pointer!\n");
                    continue;
                }

                if (g_skeleton != NULL) {
                    fibocom_gdbus_helper_emit_simcard_change(g_skeleton, user_data->payload_str);
                }
                else
                    FIBO_LOG_ERROR("variable is NULL, don't send SIM card change signal!\n");
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
        conn = NULL;

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

gboolean               device_exist_flag = FALSE;

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
        retrycount = 0;

        switch (retry_flag) {
            case 3:
                FIBO_LOG_ERROR ("reach max retry! drop all remained init process!\n");
                devcheck_thread = g_thread_new ("devicecheck", (GThreadFunc)fibo_adapter_device_Check, (gpointer)&device_exist_flag);
                if (!devcheck_thread) {
                    FIBO_LOG_ERROR("thread init failed!\n");
                    return;
                }
                break;
            case 2:
                FIBO_LOG_ERROR ("don't find valid cellular twice, will trigger HW reboot!\n");
                // trigger HW reboot
            case 1:
                while (retrycount < 20) {
                    ret = fibo_adapter_check_cellular (&res);
                    if (ret == RET_OK && res == RET_OK) {
                        device_exist_flag = TRUE;
                        fibo_adapter_control_mbim_init();

                        // if retrycount = 0, means service restart while module already exist, so service need to check whether sim card is ready!
                        // cause home provider don't support indication, helperm will have to check secondly.
                        // if module already connected to network, service will miss register state indication, helperm should check it!
                        if (retrycount == 0)
                            fibo_adapter_helperd_send_control_message_to_helperm(CTL_MBIM_SUBSCRIBER_READY_QUERY, 0, NULL);

                        if (g_skeleton != NULL) {
                            fibocom_gdbus_helper_emit_cellular_state(g_skeleton, "[ModemState]cellular existed!");
                        }
                        else
                            FIBO_LOG_ERROR("variable is NULL, don't send cellular info signal!\n");

                        // device check is used to monitor all devices' add and remove event through udev.
                        devcheck_thread = g_thread_new ("devicecheck", (GThreadFunc)fibo_adapter_device_Check, (gpointer)&device_exist_flag);
                        if (!devcheck_thread) {
                            FIBO_LOG_ERROR("thread init failed!\n");
                        }
                        return;
                    }
                    FIBO_LOG_ERROR ("don't find valid cellular, will retry!\n");
                    g_usleep (1000 * 1000 * 3);
                    retrycount++;
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

    // further: add a timer to keep if message can't be returned, there will be a default error from main analyzer to main loop.
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

        ret = fibo_adapter_helperm_get_normal_msg_from_helperd(msgs);
        if (ret != RET_OK) {
            // FIBO_LOG_DEBUG("Get message failed, continue anyway!\n");
            continue;
        }

        FIBO_LOG_DEBUG("get valid request, call receiver!\n");

        request_analyzer((fibo_async_struct_type *)msgs->mtext);

#ifndef MBIM_FUNCTION_SUPPORTED
        // pure AT command must be sync function, so both function and callback must be whole finished.
        // if internal func abnormal cause keep_pointer mutex still lock, here will unlock it.
        fibo_mutex_keep_pointer_exist_unlock();
#endif

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

    // further: add a timer to keep if message can't be returned, there will be a default error from main analyzer to main loop.
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

        ret = fibo_adapter_helperm_get_control_msg_from_helperd(msgs);
        if (ret == RET_OK) {
            FIBO_LOG_DEBUG("Get control message!\n");
        }

        user_data = (fibo_async_struct_type *)msgs->mtext;
        if (!user_data->cid) {
            // FIBO_LOG_ERROR("cid invalid!\n");
            continue;
        }

        switch (user_data->cid) {
            case CTL_MBIM_INIT:
                strncpy(mbimportname, user_data->payload_str, user_data->payloadlen);
                fibo_adapter_mbim_port_init(mbimportname);
                break;
            case CTL_MBIM_DEINIT:
                fibo_adapter_helperm_get_subscriber_ready_status((GAsyncReadyCallback)fibo_adapter_helperm_deinit_get_subscriber_ready_status_ready, NULL);
                break;
            case CTL_MBIM_END:
                if (gMainLoop) {
                    FIBO_LOG_ERROR ("Caught signal, stopping fibo-helper-mbim...\n");
                    g_idle_add ((GSourceFunc) g_main_loop_quit, gMainLoop);
                }
                break;
            case CTL_MBIM_SUBSCRIBER_READY_QUERY:
                fibo_adapter_helperm_get_subscriber_ready_status((GAsyncReadyCallback)fibo_adapter_helperm_control_get_subscriber_ready_status_ready, NULL);
                break;
            case CTL_MBIM_HOME_PROVIDER_QUERY:
                fibo_adapter_helperm_get_local_mccmnc((GAsyncReadyCallback)fibo_adapter_helperm_control_get_local_mccmnc_ready, NULL);
                break;
            case CTL_MBIM_REGISTER_STATE_QUERY:
                fibo_adapter_helperm_get_network_mccmnc((GAsyncReadyCallback)fibo_adapter_helperm_control_get_network_mccmnc_ready, NULL);
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
    if (owner_id < 0)
        return RET_ERROR;
    else
        return RET_OK;
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

// all request functions don't need unlock keep_pointer_exist mutex, but need to call two result resp functions to trigger a default error resp to caller.
int
fibo_parse_sw_reboot(gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str, gpointer callback, char *req_cmd)
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

// this callback will be executed on helperm's mainloop, so it will block mainloop less than 11s on worst scenario.
void
fibo_helperm_get_network_mccmnc_ready (MbimDevice   *device,
                                 GAsyncResult *res,
                                 gpointer userdata)
{
    g_autoptr(GError)                   error          =  NULL;
    g_autoptr(MbimMessage)              response       =  NULL;
    gint                                ret            =  RET_ERROR;
    MbimRegisterState                   register_state = MBIM_REGISTER_STATE_UNKNOWN;
    g_autofree gchar                    *provider_id   = NULL;
    fibo_async_struct_type              *user_data     =  NULL;
    gint                                service_id     =  0;
    gint                                cid            =  0;

    FIBO_LOG_DEBUG("enter!\n");

    user_data = (fibo_async_struct_type *)userdata;
    if (!user_data) {
        FIBO_LOG_ERROR ("NULL pointer!\n");
        fibo_resp_error_result_callback(device, res, userdata);
        return;
    }
    else {
        service_id = user_data->serviceid;
        cid = user_data->cid;
    }

    response = mbim_device_command_finish (device, res, &error);

    if (!response || !mbim_message_response_get_result (response, MBIM_MESSAGE_TYPE_COMMAND_DONE, &error)) {
        FIBO_LOG_ERROR ("error: operation failed: %s\n", error->message);
        fibo_resp_error_result_callback(device, res, userdata);
        return;
    }

    if (!mbim_message_register_state_response_parse (
            response,
            NULL, /* nw error */
            &register_state,
            NULL, /* register_mode */
            NULL, /* available_data_classses */
            NULL, /* current_cellular_class */
            &provider_id,
            NULL, /* provider_name */
            NULL, /* roaming_text */
            NULL, /* registration_flag */
            &error)) {

        FIBO_LOG_ERROR ("error: couldn't parse response message: %s\n", error->message);
        fibo_resp_error_result_callback(device, res, userdata);
        return;
    }

    if (!provider_id) {
        FIBO_LOG_DEBUG("register state: %s\n", mbim_register_state_get_string (register_state));
        FIBO_LOG_DEBUG("don't get valid roam mccmnc!\n");
        fibo_resp_error_result_callback(device, res, userdata);
        return;
    }

    FIBO_LOG_DEBUG("provider id: %s\n", provider_id);
    ret = alloc_and_send_resp_structure(service_id, cid, 0, strlen(provider_id), provider_id);

    fibo_mutex_keep_pointer_exist_unlock();
    return;
}

void
fibo_helperm_get_local_mccmnc_ready (MbimDevice   *device,
                                 GAsyncResult *res,
                                 gpointer userdata)
{
    g_autoptr(GError)                   error          =  NULL;
    g_autoptr(MbimMessage)              response       =  NULL;
    gint                                ret            =  RET_ERROR;
    MbimProvider                        *out_provider  =  NULL;
    fibo_async_struct_type              *user_data     =  NULL;
    gint                                service_id     =  0;
    gint                                cid            =  0;

    FIBO_LOG_DEBUG("enter!\n");

    user_data = (fibo_async_struct_type *)userdata;
    if (!user_data) {
        FIBO_LOG_ERROR ("NULL pointer!\n");
        fibo_resp_error_result_callback(device, res, userdata);
        return;
    }
    else {
        service_id = user_data->serviceid;
        cid = user_data->cid;
    }

    response = mbim_device_command_finish (device, res, &error);

    if (!response || !mbim_message_response_get_result (response, MBIM_MESSAGE_TYPE_COMMAND_DONE, &error)) {
        FIBO_LOG_ERROR ("error: operation failed: %s\n", error->message);
        fibo_resp_error_result_callback(device, res, userdata);
        return;
    }

    if (!mbim_message_home_provider_response_parse (
            response,
            &out_provider,
            &error)) {
        FIBO_LOG_ERROR ("error: couldn't parse response message: %s\n", error->message);
        fibo_resp_error_result_callback(device, res, userdata);
        return;
    }
    else {
        FIBO_LOG_DEBUG("get local mccmnc:%s\n", out_provider->provider_id);
    }

    ret = alloc_and_send_resp_structure(service_id, cid, 0, strlen(out_provider->provider_id), out_provider->provider_id);
    fibo_mutex_keep_pointer_exist_unlock();

    if (out_provider)
        mbim_provider_free(out_provider);

    return;
}

// this callback will be executed on helperm's mainloop.
void
fibo_helperm_get_work_slot_id_ready (MbimDevice   *device,
                                 GAsyncResult *res,
                                 gpointer userdata)
{
    g_autoptr(GError)                   error          =  NULL;
    g_autoptr(MbimMessage)              response       =  NULL;
    gint                                ret            =  RET_ERROR;
    guint32                             out_map_count  =  0;
    g_autofree MbimSlotArray            *out_slot_map  =  NULL;
    fibo_async_struct_type              *user_data     =  NULL;
    gint                                service_id     =  0;
    gint                                cid            =  0;
    gchar                               resp_str[32]   =  {0};

    FIBO_LOG_DEBUG("enter!\n");

    user_data = (fibo_async_struct_type *)userdata;
    if (!user_data) {
        FIBO_LOG_ERROR ("NULL pointer!\n");
        fibo_resp_error_result_callback(device, res, userdata);
        return;
    }
    else {
        service_id = user_data->serviceid;
        cid = user_data->cid;
    }

    response = mbim_device_command_finish (device, res, &error);

    if (!response || !mbim_message_response_get_result (response, MBIM_MESSAGE_TYPE_COMMAND_DONE, &error)) {
        FIBO_LOG_ERROR ("error: operation failed: %s\n", error->message);
        fibo_resp_error_result_callback(device, res, userdata);
        return;
    }

    if (!mbim_message_ms_basic_connect_extensions_device_slot_mappings_response_parse
                               (response,
                                &out_map_count,
                                &out_slot_map,
                                &error)) {
        FIBO_LOG_ERROR ("error: couldn't parse response message: %s\n", error->message);
        fibo_resp_error_result_callback(device, res, userdata);
        return;
    }

    if (out_map_count != 1) {
        FIBO_LOG_DEBUG("work slot not 1! Actual:%d\n", out_map_count);
        fibo_resp_error_result_callback(device, res, userdata);
        return;
    }

    FIBO_LOG_DEBUG("found work slot:%d\n", out_slot_map[0]->slot);
    sprintf(resp_str, "%d", out_slot_map[0]->slot);
    ret = alloc_and_send_resp_structure(service_id, cid, 0, strlen(resp_str), resp_str);

    fibo_mutex_keep_pointer_exist_unlock();

    return;
}

int
fibo_parse_mbim_request(gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str, gpointer callback, char *req_cmd)
{
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
    switch (cid) {
        case GET_MCCMNC:
            ret = fibo_adapter_helperm_get_local_mccmnc((GAsyncReadyCallback)callback, user_data);
        break;
        case GET_NETWORK_MCCMNC:
            ret = fibo_adapter_helperm_get_network_mccmnc((GAsyncReadyCallback)callback, user_data);
        break;
        case GET_SIM_SLOTS_STATUS:
            ret = fibo_adapter_helperm_get_work_slot_info((GAsyncReadyCallback)callback, user_data);
        break;
        case SET_SIM_SLOTS:
            ret = fibo_adapter_helperm_switch_work_slot((GAsyncReadyCallback)callback, user_data);
        break;
        default:
            FIBO_LOG_ERROR("Not supported cid!\n");
            if (user_data) {
                free(user_data);
                user_data = NULL;
            }
            return RET_ERROR;
    }

    // here wont free user_data cause callback will use it and free it!
    if (ret != RET_OK) {
        FIBO_LOG_ERROR("Send request failed, error:%d\n", ret);
        if (user_data) {
            free(user_data);
            user_data = NULL;
        }
        return RET_ERROR;
    }

    FIBO_LOG_DEBUG("Send request finished\n");
    return RET_OK;
}

// if one callback called this callback, caller don't concern user_data cause here will free it!
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

int fibo_parse_send_atcmd_ready (MbimDevice   *device,
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

    if((GET_AP_VERSION == cid) || (GET_OP_VERSION == cid) || (GET_OEM_VERSION == cid) || (GET_DEV_VERSION == cid)){/*"xxx"*/
        p = strtok(resp_str,"\"");
        p = strtok(NULL,"\"");
        resp_str = p;
        FIBO_LOG_DEBUG("%s   %d \n", resp_str,__LINE__);
    }
    else if ((SET_BODYSAR_ENABLE == cid) || (GET_MD_VERSION == cid) || (GET_IMEI ==cid) || (RESET_MODEM_SW == cid)|| (SET_ANTENNA_ENABLE == cid)){/*2line line1:\n line2:\r\n*/
        p = strtok(resp_str,"\n");
        p = strtok(NULL,"\r\n");
        resp_str = p;
        FIBO_LOG_DEBUG("%s   %d \n", resp_str ,__LINE__);
    }
    else if((GET_BODYSAR_STATUS == cid) || (GET_BODYSAR_CTRL_MODE == cid)
            || (GET_BODYSAR_VER == cid) || (GET_ANTENNA_VER == cid) || (GET_ANTENNA_STATUS == cid) || (GET_ANTENNA_WORK_MODE == cid)
            || (GET_WDISABLE_STATUS == cid) || (GET_GNSS_STATUS == cid)  || (GET_ANTENNA_CTRL_MODE == cid)){ /*: xxx*/
        p = strtok(resp_str," ");
        p = strtok(NULL,"\r\n");
        resp_str = p;
        FIBO_LOG_DEBUG("%s   %d \n", resp_str ,__LINE__);
    }else if((GET_OEM_ID == cid) || (GET_MODEM_RANDOM_KEY == cid) || (GET_DISABLE_ESIM_STATUS == cid) || (GET_FCCLOCK_STATUS == cid)){ /*:xxx*/
        p = strtok(resp_str,":");
        p = strtok(NULL,"\r\n");
        resp_str = p;
        FIBO_LOG_DEBUG("%s   %d \n", resp_str ,__LINE__);
    }
    else if((SET_FCC_UNLOCK == cid)){
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
        } else {
            FIBO_LOG_DEBUG("found a NULL pointer!\n");
        }

    }else if ((SET_BODYSAR_INDEX == cid) || (SET_BODYSAR_VER ==cid)
              || (SET_ANTENNA_CTRL_MODE ==cid) || (SET_ANTENNA_WORK_MODE == cid) || (SET_ANTENNA_VER == cid) || (SET_ANTENNA_INDEX == cid)
              || (SET_WDISABLE_ENABLE == cid) || (SET_GNSS_ENABLE == cid) || (SET_FCCLOCK_ENABLE == cid)){
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

    if(strstr(resp_str,"ERROR") != NULL){
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
fibo_parse_send_req_atcmd(gint     serviceid,
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
    if (user_data == NULL){
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
        if (user_data) {
            free(user_data);
            user_data = NULL;
        }
        return RET_ERROR;
    }

    FIBO_LOG_DEBUG("Send request finished\n");
    return RET_OK;
}

int
fibo_parse_get_fcc_status_ready (MbimDevice   *device,
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

    FIBO_LOG_DEBUG("at:%s   %d \n", resp_str,__LINE__);

    if (strlen(at_command_prefix) + 3 > strlen(resp_str)) {
        rtcode = 1;
        return RET_ERROR;
    }

    for (int i = 0, j = 0;i < strlen(resp_str);i++) {
        if (j >= strlen(at_command_prefix)) {
            at_command_prefix_end_index = i;
            rtcode = 1;
            break;
        }
        if (at_command_prefix[j] == resp_str[i]) {
            j++;
        } else {
            j = 0;
        }
    }

    /* ex : resp_str[at_command_prefix_end_index] == "0,0" */

    if (at_command_prefix_end_index == -1 || at_command_prefix_end_index + 2 > strlen(resp_str)) {
        return RET_ERROR;
    }

    if (resp_str[at_command_prefix_end_index] == '0') {
        fcc_status = "nolock";
    }
    else if (resp_str[at_command_prefix_end_index] == '1') {
        if (resp_str[at_command_prefix_end_index + 2] == '0') {
            fcc_status = "lock";
        }
        if (resp_str[at_command_prefix_end_index + 2] == '1') {
            fcc_status = "unlock";
        }
    }

    if (fcc_status == NULL) {
        FIBO_LOG_ERROR ("at:%s\n", resp_str + at_command_prefix_end_index);
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

int fibo_parse_send_set_atcmd(gint     serviceid,
                              gint     cid,
                              gint     rtcode,
                              gint     payloadlen,
                              gchar    *payload_str,
                              gpointer callback,
                              char *req_cmd)
{
    char * parameter_req_cmd = NULL;
    int    ret               = RET_ERROR;

    parameter_req_cmd = malloc(sizeof(char) * 128);
    if (parameter_req_cmd) {
        FIBO_LOG_ERROR("NULL pointer!\n");
    }
    memset(parameter_req_cmd, 0, sizeof(parameter_req_cmd));

    FIBO_LOG_DEBUG("%s   %d\n", payload_str, __LINE__);

    sprintf(parameter_req_cmd,"%s%s",req_cmd, payload_str);

    ret = fibo_parse_send_req_atcmd(serviceid, cid, rtcode, payloadlen, payload_str, callback, parameter_req_cmd);
    if (ret != RET_OK) {
        FIBO_LOG_ERROR("command executed failed!\n");
        if(parameter_req_cmd) {
            free(parameter_req_cmd);
            parameter_req_cmd = NULL;
        }
        return RET_ERROR;
    }

    FIBO_LOG_DEBUG("%s   %d\n", parameter_req_cmd, __LINE__);

    if(parameter_req_cmd) {
        free(parameter_req_cmd);
        parameter_req_cmd = NULL;
    }
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

    char buf[512]= {0};
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
        FIBO_LOG_DEBUG("%s     %d    \n",buf,__LINE__);
        for(int i = 0; i < support_usbvidpid_size; i++){
            if(strstr(buf,support_usbvidpid[i].vidpid) != NULL){
                sprintf(resp_str,"%s\n","normalport");
                break;
            }
        }
        if(strstr(buf,"05c6:9008") != NULL){
            sprintf(resp_str,"%s\n","flashport");
            break;
        }
        else if(strstr(buf,"2cb7:d00d") != NULL){
            sprintf(resp_str,"%s\n","fastbootport");
            break;
        }
        else{
            FIBO_LOG_DEBUG("don't match subpidvid   %d    \n",__LINE__);
            continue;
        }
    }
    pclose(get_port_fp);
    FIBO_LOG_DEBUG("%s     %d    \n",buf,__LINE__);
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
    if (ret != RET_OK){
        g_print("%s pclose reboot_fp error!\n", __func__);
        return;
    }
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
    while(fgets(resp_str, 256, get_port_fp) != NULL){

    }
    pclose(get_port_fp);
    if((strstr(resp_str,"2cb7,01a2") != NULL) || (strstr(resp_str,"2cb7,d00d") != NULL)){
        get_port_fp == NULL;
        get_port_fp = popen(get_qdl_port_cmd,"r");
        if(get_port_fp == NULL) {
            FIBO_LOG_DEBUG("open get_port_cmd error\n");
        }
        while(fgets(resp_str,256,get_port_fp) != NULL)
            pclose(get_port_fp);
        if((strstr(resp_str,"05c6:9008") == NULL)){
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
}Sub_Partition_Len;

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
}fibocom_partition;

fibocom_partition ap_partition[] = {
        /*lable            filename*/
        {"aboot","appsboot.mbn"},
        {"boot","sdxnightjar-boot.img"},
        {"system", "sdxnightjar-sysfs.ubi"},
        {"userdata", "sdxnightjar-usrfs.ubi"},
};

fibocom_partition sbl_partition[] = {{"sbl", "sbl1.mbn"}};

fibocom_partition modem_partition[] = {{"modem", "NON-HLOS.ubi"}};

fibocom_partition dev_partition[] = {
        {"devicepack", "devicepack.ubi"},
};

fibocom_partition oem_partition[] = {
        {"oempack", "oempack.ubi"},
};

fibocom_partition op_partition[] = {{"operatorpack", "operatorpack.ubi"}};

char* itoa(int num,char* str,int radix)
{
    char index[]="0123456789ABCDEF";
    unsigned unum;
    int i=0,j,k;

    if(radix==10&&num<0){
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

    for(j=k;j<=(i-1)/2;j++){
        char temp;
        temp=str[j];
        str[j]=str[i-1+k-j];
        str[i-1+k-j]=temp;
    }
    return str;
}
void fibo_program_payload_analysis(char * payload,Payload_Analysis *payload_analysis,Partition_Flash_Flag *partition_flash_flag,int *default_dev_flag)
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
        if(strstr(interpayload,"path")){
            memcpy(payload_analysis->flashpath,interpayload,strlen(interpayload)+1);
            FIBO_LOG_DEBUG("payload_analysis->flashpath = %s %d\n",payload_analysis->flashpath,__LINE__);
            partition_flash_flag->path++;
        }else if(strstr(interpayload,"ap")){
            memcpy(payload_analysis->ap_ver,interpayload,strlen(interpayload)+1);
            FIBO_LOG_DEBUG("payload_analysis->ap_ver = %s %d\n",payload_analysis->ap_ver,__LINE__);
            partition_flash_flag->ap++;
        }else if(strstr(interpayload,"md")){
            memcpy(payload_analysis->modem_ver,interpayload,strlen(interpayload)+1);
            FIBO_LOG_DEBUG("%s %d\n",interpayload,__LINE__);
            FIBO_LOG_DEBUG("modem_ver = %s %d\n",payload_analysis->modem_ver,__LINE__);
            partition_flash_flag->modem++;
        }else if(strstr(interpayload,"dev")){
            memcpy(payload_analysis->dev_ver,interpayload,strlen(interpayload)+1);
            FIBO_LOG_DEBUG("payload_analysis->dev_ver = %s %d\n",payload_analysis->dev_ver,__LINE__);
            partition_flash_flag->dev++;
        }else if(strstr(interpayload,"oem")){
            memcpy(payload_analysis->oem_ver,interpayload,strlen(interpayload)+1);
            FIBO_LOG_DEBUG("payload_analysis->oem_ver = %s %d\n",payload_analysis->oem_ver,__LINE__);
            partition_flash_flag->oem++;
        }else if(strstr(interpayload,"op")){
            memcpy(payload_analysis->op_ver,interpayload,strlen(interpayload)+1);
            FIBO_LOG_DEBUG("payload_analysis->op_ver = %s %d\n",payload_analysis->op_ver,__LINE__);
            partition_flash_flag->op++;
        }else{
            FIBO_LOG_DEBUG("[%s:]current field don't match partation and path\n",__func__);
        }
        interpayload = strtok(NULL,";");
        FIBO_LOG_DEBUG("interpayload = %s %d\n",interpayload,__LINE__);
    }


    if((partition_flash_flag->ap == 0) && (partition_flash_flag->modem == 0) && (partition_flash_flag->dev == 0) && (partition_flash_flag->oem == 0) && (partition_flash_flag->op == 0)){
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

    if(partition_flash_flag->ap != 0){
        payload_analysis->ap_ver = strtok(payload_analysis->ap_ver,":");
        payload_analysis->ap_ver = strtok(NULL,";");
        FIBO_LOG_DEBUG("payload_analysis->ap_ver = %s %d\n",payload_analysis->ap_ver,__LINE__);
    }

    if(partition_flash_flag->modem != 0){
        payload_analysis->modem_ver = strtok(payload_analysis->modem_ver,":");
        payload_analysis->modem_ver = strtok(NULL,";");
        FIBO_LOG_DEBUG("payload_analysis->modem_ver = %s %d\n",payload_analysis->modem_ver,__LINE__);
    }
    if(partition_flash_flag->dev != 0){
        payload_analysis->dev_ver = strtok(payload_analysis->dev_ver,":");
        payload_analysis->dev_ver = strtok(NULL,";");
        if(strstr(payload_analysis->dev_ver,"default"))
        {
            payload_analysis->dev_ver = strtok(payload_analysis->dev_ver, "_");
            payload_analysis->dev_ver = strtok(NULL, ";");
            *default_dev_flag = 1;
            sprintf(payload_analysis->dev_ver_path,"%s%s","OEM_OTA_",payload_analysis->dev_ver);
        }
        else{
            sprintf(payload_analysis->dev_ver_path,"%s",payload_analysis->dev_ver);
        }
        FIBO_LOG_DEBUG("payload_analysis->dev_ver_path = %s %d\n",payload_analysis->dev_ver_path,__LINE__);
    }
    if(partition_flash_flag->oem != 0){
        payload_analysis->oem_ver = strtok(payload_analysis->oem_ver,":");
        payload_analysis->oem_ver = strtok(NULL,";");
        sprintf(payload_analysis->oem_ver_path,"%s%s","OEM_OTA_",payload_analysis->oem_ver);
        FIBO_LOG_DEBUG("payload_analysis->oem_ver_path = %s %d\n",payload_analysis->oem_ver_path,__LINE__);
    }
    if(partition_flash_flag->op != 0){
        payload_analysis->op_ver = strtok(payload_analysis->op_ver,":");
        payload_analysis->op_ver = strtok(NULL,";");
        sprintf(payload_analysis->op_ver_path,"%s%s","OP_OTA_",payload_analysis->op_ver);
        FIBO_LOG_DEBUG("payload_analysis->op_ver_path = %s %d\n",payload_analysis->op_ver_path,__LINE__);
    }
}

int fibocom_get_zenity_environment_variable(char zenity_environment_variable[],int length)
{
    FILE *get_zenity_environment_variable_fp = NULL;
    FILE *get_zenity_environment_variable_x11_fp = NULL;
    char get_zenity_environment_variable_cmd[] = "find /run/user -name \".mutter-Xwaylandauth*\" 2>/dev/null | head -1";
    char get_zenity_environment_variable_x11_cmd[] = "find /run/user/ -name \"Xauthority\" 2>/dev/null | head -1";
    int ret = 0;

    get_zenity_environment_variable_fp = popen(get_zenity_environment_variable_cmd,"r");
    if(NULL == get_zenity_environment_variable_fp){
        perror("get_zenity_environment_variable error");
        FIBO_LOG_ERROR("open zenity_environment_variable error\n");
        return RET_ERROR;
    }

    ret = fread(zenity_environment_variable,sizeof(char),length,get_zenity_environment_variable_fp);
    if(!ret){
        FIBO_LOG_ERROR("read zenity_environment_variable error\n");
        pclose(get_zenity_environment_variable_fp);

        get_zenity_environment_variable_x11_fp = popen(get_zenity_environment_variable_x11_cmd,"r");
        if(NULL == get_zenity_environment_variable_x11_fp){
            perror("get_zenity_environment_variable_x11 error");
            FIBO_LOG_ERROR("open get_zenity_environment_variable_x11 error\n");
            return RET_ERROR;
        }
        ret = fread(zenity_environment_variable,sizeof(char),length,get_zenity_environment_variable_x11_fp);
        if(!ret){
            FIBO_LOG_ERROR("read zenity_environment_variable_x11 error\n");
            pclose(get_zenity_environment_variable_x11_fp);
            return RET_ERROR;
        }
        pclose(get_zenity_environment_variable_x11_fp);
    }else{
        pclose(get_zenity_environment_variable_fp);
    }

    return RET_OK;
}

void fibocom_strcat_zenity_environment_variable(char zenity_environment_variable[],char set_zenity_environment_variable[])
{
    sprintf(set_zenity_environment_variable,"export DISPLAY=\":0\"\nexport XDG_CURRENT_DESKTOP=\"ubuntu:GNOME\"\nexport XAUTHORITY=%s\n",zenity_environment_variable);
}

gpointer fibocom_fastboot_flash_command(gpointer payload, int *fastboot_success_flag) {
    Sub_Partition_Len sub_partition_len = {0};
    FILE *fp = NULL;
    int ret = 0;

    char command_rsp[256] = {0};
    char command[256] = {0};
    char buf[256] = {0};
    File_Progress_Class fastboot_flash = {0};
    Partition_Flash_Flag partition_flash_flag = {0};
    Payload_Analysis payload_analysis = {0};

    char zenity_environment_variable[64] = {0};
    int environment_variable_length = 64;
    char set_zenity_environment_variable[256] = {0};
    int default_dev_flag = 0;

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

    fibo_program_payload_analysis(payload,&payload_analysis,&partition_flash_flag,&default_dev_flag);

    sub_partition_len.ap = sizeof(ap_partition) / sizeof(fibocom_partition);
    sub_partition_len.sbl = sizeof(sbl_partition) / sizeof(fibocom_partition);
    sub_partition_len.modem = sizeof(modem_partition) / sizeof(fibocom_partition);
    sub_partition_len.dev = sizeof(dev_partition) / sizeof(fibocom_partition);
    sub_partition_len.oem = sizeof(oem_partition) / sizeof(fibocom_partition);
    sub_partition_len.op = sizeof(op_partition) /sizeof(fibocom_partition);

    ret = fibocom_get_zenity_environment_variable(zenity_environment_variable,environment_variable_length);
    if(ret != RET_OK){
        FIBO_LOG_ERROR("get zenity_environment_variable path error\n");
        /*If the progress bar envronment variable fails to be read,the burn proceduce is still executed
        return NULL;
        */
    }
    fibocom_strcat_zenity_environment_variable(zenity_environment_variable,set_zenity_environment_variable);

    FIBO_LOG_DEBUG("%s\n",set_zenity_environment_variable);

    fastboot_flash.progress_fp = NULL;
    strcpy(fastboot_flash.progress_title,"ModemUpgrade");
    strcpy(fastboot_flash.progress_text,"<span font='13'>Downloading ...\\n\\n</span><span foreground='red' font='16'>Do not shut down or restart</span>");
    sprintf(fastboot_flash.progress_command,
            "%s/usr/bin/zenity --progress --text=\"%s\" --percentage=%d --auto-close --no-cancel --width=600 --title=\"%s\"",
            set_zenity_environment_variable,fastboot_flash.progress_text, 10,fastboot_flash.progress_title);

    fastboot_flash.progress_fp = popen(fastboot_flash.progress_command,"w");
    g_usleep(1000*1000*2);

    int flash_partition_num = 0;

    if(partition_flash_flag.ap!= 0)
        flash_partition_num += 5;
    if(partition_flash_flag.modem!= 0)
        flash_partition_num += 1;
    if(partition_flash_flag.dev!= 0)
        flash_partition_num += 1;
    if(partition_flash_flag.oem!= 0)
        flash_partition_num += 1;
    if(partition_flash_flag.op!= 0)
        flash_partition_num += 1;

    int flash_partition_percent = 99 / flash_partition_num;
    int present_flash_partition_percent = 0;

    if(partition_flash_flag.ap != 0) {
        for (int i = 0; i < sub_partition_len.ap; i++) {
            present_flash_partition_percent += flash_partition_percent;
            itoa(present_flash_partition_percent, fastboot_flash.progress_percentage, 10);
            sprintf(fastboot_flash.progress_percentage, "%s", fastboot_flash.progress_percentage);
            strcat(fastboot_flash.progress_percentage,"\n");
            fwrite(fastboot_flash.progress_percentage, sizeof(char), strlen(fastboot_flash.progress_percentage), fastboot_flash.progress_fp);

            fp = NULL;

            FIBO_LOG_DEBUG("payload_analysis->flashpath = %s %d\n",payload_analysis.flashpath,__LINE__);
            FIBO_LOG_DEBUG("payload_analysis->ap_ver = %s %d\n",payload_analysis.ap_ver,__LINE__);

            sprintf(command, "fastboot flash %s %s%s/%s 2>&1", ap_partition[i].lable, payload_analysis.flashpath, payload_analysis.ap_ver,
            ap_partition[i].filename);
            FIBO_LOG_DEBUG("command = %s %d\n", command, __LINE__);

            fp = popen(command, "r");
            if (fp == NULL) {
                FIBO_LOG_DEBUG("command = %s %d\n", command, __LINE__);
                continue;
            }

            memset(buf,0,sizeof(buf));

            ret = fread(buf, sizeof(char), sizeof(buf), fp);
            if(ret == RET_ERROR){
                memcpy(buf,"fread error", strlen("fread error") + 1);
                FIBO_LOG_CRITICAL("fread fp error\n");
            }

            if(strstr(buf, "Finished. Total time:") != NULL){
                *fastboot_success_flag += 1;
            }
            else{
                FIBO_LOG_CRITICAL("flash error %s\n", ap_partition[i].lable);
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
        for (int i = 0; i < sub_partition_len.sbl; i++) {
            present_flash_partition_percent += flash_partition_percent;
            itoa(present_flash_partition_percent, fastboot_flash.progress_percentage, 10);
            sprintf(fastboot_flash.progress_percentage, "%s", fastboot_flash.progress_percentage);
            strcat(fastboot_flash.progress_percentage, "\n");
            fwrite(fastboot_flash.progress_percentage, sizeof(char), strlen(fastboot_flash.progress_percentage), fastboot_flash.progress_fp);

            fp = NULL;
            sprintf(command, "fastboot flash %s %s%s/%s 2>&1", sbl_partition[i].lable, payload_analysis.flashpath, "basic_update_img",
                    sbl_partition[i].filename);

            FIBO_LOG_DEBUG("command = %s %d\n", command, __LINE__);

            fp = popen(command, "r");
            if (fp == NULL) {
                FIBO_LOG_DEBUG("command = %s %d\n", command, __LINE__);
                continue;
            }

            memset(buf,0,sizeof(buf));

            ret = fread(buf, sizeof(char), sizeof(buf), fp);
            if(ret == RET_ERROR){
                memcpy(buf,"fread error", strlen("fread error") + 1);
                FIBO_LOG_CRITICAL("fread fp error\n");
            }

            if(strstr(buf, "Finished. Total time:") != NULL){
                *fastboot_success_flag += 1;
            }
            else{
                FIBO_LOG_CRITICAL("flash error %s\n", sbl_partition[i].lable);
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

    if(partition_flash_flag.modem != 0){
        for (int i = 0; i < sub_partition_len.modem; i++){
            present_flash_partition_percent += flash_partition_percent;
            itoa(present_flash_partition_percent, fastboot_flash.progress_percentage, 10);
            sprintf(fastboot_flash.progress_percentage, "%s", fastboot_flash.progress_percentage);
            strcat(fastboot_flash.progress_percentage, "\n");
            fwrite(fastboot_flash.progress_percentage, sizeof(char), strlen(fastboot_flash.progress_percentage), fastboot_flash.progress_fp);
            fflush(fastboot_flash.progress_fp);

            fp = NULL;
            sprintf(command, "fastboot flash %s %s%s/%s 2>&1", modem_partition[i].lable, payload_analysis.flashpath, payload_analysis.modem_ver, modem_partition[i].filename);
            FIBO_LOG_DEBUG("command = %s %d\n", command, __LINE__);
            fp = popen(command, "r");
            if (fp == NULL){
                FIBO_LOG_DEBUG("[%s]: execute command failed!\n", __func__);
                continue;
            }

            memset(buf,0,sizeof(buf));

            ret = fread(buf, sizeof(char), sizeof(buf), fp);
            if(ret == RET_ERROR){
                memcpy(buf,"fread error", strlen("fread error") + 1);
                FIBO_LOG_CRITICAL("fread fp error\n");
            }

            if(strstr(buf, "Finished. Total time:") != NULL){
                *fastboot_success_flag += 1;
            }
            else{
                FIBO_LOG_CRITICAL("flash error %s\n", modem_partition[i].lable);
            }

            ret = pclose(fp);
            if (ret != RET_OK){
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

    if(partition_flash_flag.dev != 0){
        for (int i = 0; i < sub_partition_len.dev; i++){
            present_flash_partition_percent += flash_partition_percent;
            itoa(present_flash_partition_percent, fastboot_flash.progress_percentage, 10);
            sprintf(fastboot_flash.progress_percentage, "%s", fastboot_flash.progress_percentage);
            strcat(fastboot_flash.progress_percentage, "\n");
            fwrite(fastboot_flash.progress_percentage, sizeof(char), strlen(fastboot_flash.progress_percentage), fastboot_flash.progress_fp);
            fflush(fastboot_flash.progress_fp);

            fp = NULL;

            if(1 == default_dev_flag){
                sprintf(command, "fastboot flash %s %s%s/%s 2>&1", dev_partition[i].lable, payload_analysis.flashpath, payload_analysis.dev_ver_path, dev_partition[i].filename);
            }
            else{
                sprintf(command, "fastboot flash %s %sDEV_OTA_PACKAGE/%s/%s 2>&1", dev_partition[i].lable, payload_analysis.flashpath, payload_analysis.dev_ver_path, dev_partition[i].filename);
            }
            FIBO_LOG_DEBUG("command = %s %d\n", command, __LINE__);

            fp = popen(command, "r");
            if (fp == NULL)
            {
                FIBO_LOG_DEBUG("[%s]: execute command failed!\n", __func__);
                continue;
            }

            memset(buf,0,sizeof(buf));

            ret = fread(buf, sizeof(char), sizeof(buf), fp);
            if(ret == RET_ERROR){
                memcpy(buf,"fread error", strlen("fread error") + 1);
                FIBO_LOG_CRITICAL("fread fp error\n");
            }

            if(strstr(buf, "Finished. Total time:") != NULL){
                *fastboot_success_flag += 1;
            }
            else{
                FIBO_LOG_CRITICAL("flash error %s\n", dev_partition[i].lable);
            }

            ret = pclose(fp);
            if (ret != RET_OK){
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

    if(partition_flash_flag.oem != 0){
        for (int i = 0; i < sub_partition_len.oem; i++){
            present_flash_partition_percent += flash_partition_percent;
            itoa(present_flash_partition_percent, fastboot_flash.progress_percentage, 10);
            sprintf(fastboot_flash.progress_percentage, "%s", fastboot_flash.progress_percentage);
            strcat(fastboot_flash.progress_percentage, "\n");
            fwrite(fastboot_flash.progress_percentage, sizeof(char), strlen(fastboot_flash.progress_percentage), fastboot_flash.progress_fp);
            fflush(fastboot_flash.progress_fp);

            fp = NULL;
            sprintf(command, "fastboot flash %s %s%s/%s 2>&1", oem_partition[i].lable, payload_analysis.flashpath, payload_analysis.oem_ver_path, oem_partition[i].filename);
            FIBO_LOG_DEBUG("command = %s %d\n", command, __LINE__);
            fp = popen(command, "r");
            if (fp == NULL){
                FIBO_LOG_DEBUG("[%s]: execute command failed!\n", __func__);
                continue;
            }

            memset(buf,0,sizeof(buf));

            ret = fread(buf, sizeof(char), sizeof(buf), fp);
            if(ret == RET_ERROR){
                memcpy(buf,"fread error", strlen("fread error") + 1);
                FIBO_LOG_CRITICAL("fread fp error\n");
            }

            if(strstr(buf, "Finished. Total time:") != NULL){
                *fastboot_success_flag += 1;
            }
            else{
                FIBO_LOG_CRITICAL("flash error %s\n", oem_partition[i].lable);
            }

            ret = pclose(fp);
            if (ret != RET_OK){
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

    if(partition_flash_flag.op != 0){
        for (int i = 0; i < sub_partition_len.op; i++){
            present_flash_partition_percent += flash_partition_percent;
            itoa(present_flash_partition_percent, fastboot_flash.progress_percentage, 10);
            sprintf(fastboot_flash.progress_percentage, "%s", fastboot_flash.progress_percentage);
            strcat(fastboot_flash.progress_percentage, "\n");
            fwrite(fastboot_flash.progress_percentage, sizeof(char), strlen(fastboot_flash.progress_percentage), fastboot_flash.progress_fp);
            fflush(fastboot_flash.progress_fp);

            fp = NULL;
            sprintf(command, "fastboot flash %s %s%s/%s 2>&1", op_partition[i].lable, payload_analysis.flashpath, payload_analysis.op_ver_path, op_partition[i].filename);
            FIBO_LOG_DEBUG("command = %s %d\n", command, __LINE__);
            fp = popen(command, "r");
            if (fp == NULL){
                FIBO_LOG_DEBUG("[%s]: execute command failed!\n", __func__);
                continue;
            }

            memset(buf,0,sizeof(buf));

            ret = fread(buf, sizeof(char), sizeof(buf), fp);
            if(ret == RET_ERROR){
                memcpy(buf,"fread error", strlen("fread error") + 1);
                FIBO_LOG_CRITICAL("fread fp error\n");
            }

            if(strstr(buf, "Finished. Total time:") != NULL){
                *fastboot_success_flag += 1;
            }
            else{
                FIBO_LOG_CRITICAL("flash error %s\n", op_partition[i].lable);
            }

            ret = pclose(fp);
            if (ret != RET_OK){
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

    if(*fastboot_success_flag == flash_partition_num){
        *fastboot_success_flag = 1;
        strcpy(fastboot_flash.progress_text, "#The Modem upgrade Success!\\n\\n\n");
    }else{
        *fastboot_success_flag = 0;
        strcpy(fastboot_flash.progress_text, "#The Modem upgrade failed!\\n\\n\n");
    }

    sprintf(fastboot_flash.progress_percentage, "%s\n", "99");
    fwrite(fastboot_flash.progress_text, sizeof(char), strlen(fastboot_flash.progress_text), fastboot_flash.progress_fp);
    fwrite(fastboot_flash.progress_percentage, sizeof(char), strlen(fastboot_flash.progress_percentage), fastboot_flash.progress_fp);
    fflush(fastboot_flash.progress_fp);
    g_usleep(1000*1000*3);

    ret = pclose(fastboot_flash.progress_fp);
    if (ret != RET_OK) {
        FIBO_LOG_DEBUG("%s command return error! %d\n", __func__, __LINE__);
    }

    return NULL;
}

int qdl_payload_analysis(char *payload, char *qdl_apver, char*qdl_mdver)
{
    char interpayload[128] = {0};
    char *p = NULL;

    if(NULL == payload){
        FIBO_LOG_CRITICAL("payload == NULL\n");
        return RET_ERROR;
    }
    sprintf(interpayload,"%s",payload);

    p = strtok(interpayload,";");

    while(p){
        if(strstr(p, "ap")){
            strcpy(qdl_apver, p);
        }
        else if(strstr(p, "md")){
            strcpy(qdl_mdver, p);
        }
        p = strtok(NULL, ";");
    }

    if(qdl_apver) {
        p = strtok(qdl_apver, ":");
        strcpy(qdl_apver, strtok(NULL, ";"));
    } else{
        FIBO_LOG_CRITICAL("qdl_apver == NULL\n");
        return RET_ERROR;
    }

    if(qdl_mdver) {
        p = strtok(qdl_mdver, ":");
        strcpy(qdl_mdver, strtok(NULL, ";"));
    } else{
        FIBO_LOG_CRITICAL("qdl_mdver == NULL\n");
        return RET_ERROR;
    }
    return RET_OK;
}

int copy_image(char *qdl_falash_path, char *qdl_appath, char *qdl_mdpath, char *qdl_work_space)
{
    char qdl_copy_apimage_cmd[128] = {0};
    char qdl_copy_mdimage_cmd[128] = {0};
    char qdl_copy_basicimage_cmd[128] = {0};
    char qdl_copy_downagent_cmd[128] = {0};
    char qdl_copy_rawprogram_nand_cmd[128] = {0};
    int ret = 0;

    sprintf(qdl_copy_apimage_cmd,"cp %s/* %s", qdl_appath, qdl_work_space);
    sprintf(qdl_copy_mdimage_cmd,"cp %s/* %s", qdl_mdpath, qdl_work_space);
    sprintf(qdl_copy_basicimage_cmd,"cp %s%s/* %s", qdl_falash_path, "basic_update_img", qdl_work_space);
    sprintf(qdl_copy_downagent_cmd,"cp %s%s/* %s", qdl_falash_path, "download_agent", qdl_work_space);
    sprintf(qdl_copy_rawprogram_nand_cmd,"cp %s%s %s", qdl_falash_path, "rawprogram_nand_p2K_b128K.xml", qdl_work_space);
    ret = system(qdl_copy_apimage_cmd);
    if(RET_OK != ret){
        FIBO_LOG_CRITICAL("copy ap image error\n");
        return RET_ERROR;
    }

    FIBO_LOG_CRITICAL("%s\n",qdl_copy_mdimage_cmd);
    ret = system(qdl_copy_mdimage_cmd);
    if(RET_OK != ret){
        FIBO_LOG_CRITICAL("copy md image error\n");
        return RET_ERROR;
    }

    FIBO_LOG_CRITICAL("%s\n",qdl_copy_basicimage_cmd);

    ret = system(qdl_copy_basicimage_cmd);
    if(RET_OK != ret){
        FIBO_LOG_CRITICAL("copy basic image error\n");
        return RET_ERROR;
    }

    ret = system(qdl_copy_downagent_cmd);
    if(RET_OK != ret){
        FIBO_LOG_CRITICAL("copy downagent error\n");
        return RET_ERROR;
    }

    ret = system(qdl_copy_rawprogram_nand_cmd);
    if(RET_OK != ret){
        FIBO_LOG_CRITICAL("copy rawprogram_nand_p2K_b128K.xml error\n");
        return RET_ERROR;
    }

    return RET_OK;
}

int qdl_rmdir(const char *path)
{
    char rm_dir[128] = {0};
    int ret = 0;
    sprintf(rm_dir,"rm -rf %s",path);
    ret = system(rm_dir);
    if(RET_OK != ret){
        FIBO_LOG_CRITICAL("rmdir %s error\n",path);
        return RET_ERROR;
    }
    return  RET_OK;
}

int fibocom_creat_qdl_work_space(char *qdl_falash_path, char *qdl_work_space, char *qdl_apver, char *qdl_mdver)
{
    char find_rawprogram_nand_cmd[128] = {0};
    size_t ret = 0;
    char qdl_apimage_path[128] = {0};
    char qdl_mdimage_path[128] = {0};

    ret = mkdir(qdl_work_space,666 | O_CREAT | O_TRUNC);
    if(RET_ERROR == ret){
        FIBO_LOG_CRITICAL("mkdir error\n");
        return RET_ERROR;
    }

    sprintf(qdl_apimage_path,"%s%s",qdl_falash_path,qdl_apver);
    sprintf(qdl_mdimage_path,"%s%s",qdl_falash_path,qdl_mdver);

    ret = copy_image(qdl_falash_path, qdl_apimage_path, qdl_mdimage_path, qdl_work_space);
    if(RET_OK !=ret){
        FIBO_LOG_CRITICAL("copy_image error\n");
        FIBO_LOG_CRITICAL("%s\n",qdl_work_space);
        qdl_rmdir(qdl_work_space);
        return RET_ERROR;
    }
    return RET_OK;
}

static void qdl_search_filename(xmlNode *a_node, char* segment, int *filename_num)
{
    xmlNode *cur_node = NULL;
    xmlChar *filename = NULL;

    for (cur_node = a_node; cur_node != NULL; cur_node = cur_node->next){
        if(XML_ELEMENT_NODE == cur_node->type) {
            if(!xmlStrcmp(cur_node->name, (const xmlChar *) "program")){
                filename = xmlGetProp(cur_node,(const xmlChar*)segment);
                if(strlen(filename) != 0){
                    *filename_num += 1;
                }
            }
        }
        qdl_search_filename(cur_node->children, segment, filename_num);
    }
}

int find_segment_from_xml(char* segment,char *docname, int *filename_num)
{
    xmlDocPtr doc;
    xmlNodePtr cur;

    doc = xmlParseFile(docname);
    if (doc == NULL ){
        fprintf(stderr,"Document not parsed successfully. \n");
        return RET_ERROR;
    }

    cur = xmlDocGetRootElement(doc);
    if (cur == NULL){
        fprintf(stderr,"empty document\n");
        xmlFreeDoc(doc);
        return RET_ERROR;
    }

    qdl_search_filename(cur, segment, filename_num);

    xmlFreeDoc(doc);
    xmlCleanupParser();
    return RET_OK;
}

gpointer fibocom_qdl_flash_command(gpointer payload,int *qdl_success_flag)
{
    char *qdl_falash_path = "/opt/fibocom/fibo_fw_pkg/FwPackage/";
    char qdl_work_space[128] = {0};
    char prog_nand_firehose_path[256] = {0};
    char rawprogram_nand_path[256] = {0};
    char patch_p2K_path[256] = {0};
    char qdl_flash_cmd[1024 + 512] = {0};
    FILE *qdl_fp = NULL;
    char qdl_apver[8] = {0};
    char qdl_mdver[32] = {0};

    File_Progress_Class qdl_flash = {0};
    int qdl_flash_progress_current_percentage = 0;
    int count = 128;
    char buf[1024]= {0};
    int i = 0;

    int ret = 0;
    char zenity_environment_variable[64] = {0};
    int environment_variable_length = 64;
    char set_zenity_environment_variable[256] = {0};

    int image_num = 0;
    int qdl_flash_partition_percent = 0;


    ret = qdl_payload_analysis(payload,qdl_apver,qdl_mdver);
    if(RET_OK != ret){
        FIBO_LOG_CRITICAL("qdl_payload_analysis error\n");
        *qdl_success_flag = 0;
        return NULL;
    }
    if(payload){
        free(payload);
    }

    sprintf(qdl_work_space,"%sMaincode/", qdl_falash_path);

    if(0 == access(qdl_work_space, F_OK)) {
        FIBO_LOG_WARNING("Directory exists.\n");
        qdl_rmdir(qdl_work_space);
    } else {
        FIBO_LOG_INFO("Directory does not exist.\n");
    }

    ret = fibocom_creat_qdl_work_space(qdl_falash_path, qdl_work_space, qdl_apver, qdl_mdver);
    if(RET_OK != ret){
        FIBO_LOG_CRITICAL("fibocom_creat_qdl_work_space error\n");
        *qdl_success_flag = 0;
        return NULL;
    }

    sprintf(prog_nand_firehose_path,"%sprog_nand_firehose_9x55.mbn",qdl_work_space);
    sprintf(rawprogram_nand_path,"%srawprogram_nand_p2K_b128K.xml",qdl_work_space);
    sprintf(patch_p2K_path,"%spatch_p2K_b128K.xml",qdl_work_space);
    sprintf(qdl_flash_cmd,"/opt/fibocom/fibo_helper_service/fibo_helper_tools/qdl --storage nand --include %s %s %s %s 2>&1",qdl_work_space,prog_nand_firehose_path,rawprogram_nand_path,patch_p2K_path);

    ret = find_segment_from_xml("filename", rawprogram_nand_path, &image_num);
    if(RET_ERROR == ret){
        FIBO_LOG_ERROR("find segment from xml error\n");
        return NULL;
    }
    FIBO_LOG_DEBUG("%d\n",image_num);

    if(image_num != 0) {
        qdl_flash_partition_percent = 99 / image_num;
    }

    ret = fibocom_get_zenity_environment_variable(zenity_environment_variable,environment_variable_length);
    if(ret != RET_OK){
        FIBO_LOG_ERROR("get zenity_environment_variable path error\n");
        /*If the progress bar envronment variable fails to be read,the burn proceduce is still executed
        return NULL;
        */
    }
    fibocom_strcat_zenity_environment_variable(zenity_environment_variable,set_zenity_environment_variable);
    FIBO_LOG_DEBUG("%s %d\n",qdl_flash_cmd,__LINE__);

    strcpy(qdl_flash.progress_title,"ModemUpgrade");
    strcpy(qdl_flash.progress_text,"<span font='13'>Downloading ...\\n\\n</span><span foreground='red' font='16'>Do not shut down or restart</span>");
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
        FIBO_LOG_CRITICAL("%s\n",qdl_work_space);
        qdl_rmdir(qdl_work_space);
        *qdl_success_flag = 0;
        FIBO_LOG_DEBUG("[%s]: execute command failed!\n", __func__);
        return NULL;
    }

    FIBO_LOG_CRITICAL("qdl_flash_cmd run success\n");

    while(fgets(buf,count,qdl_fp)!=NULL){
        FIBO_LOG_CRITICAL("read from qdl_fp == %s\n", buf);
        if(strstr(buf,"Waiting for EDL device") != NULL){
            strcpy(qdl_flash.progress_text,"#don't match 9008 port,exit program\n");
            fwrite(qdl_flash.progress_text, sizeof(char), strlen(qdl_flash.progress_text), qdl_flash.progress_fp);
            fflush(qdl_flash.progress_fp);
            g_usleep(1000*1000*1);
            pclose(qdl_fp);
            *qdl_success_flag = 0;
            FIBO_LOG_CRITICAL("%s\n",qdl_work_space);
            ret = qdl_rmdir(qdl_work_space);
            return NULL;
        }

        if(strstr(buf,"successfully") != NULL) {
            i++;
            qdl_flash_progress_current_percentage += qdl_flash_partition_percent;
            itoa(qdl_flash_progress_current_percentage, qdl_flash.progress_percentage, 10);
            sprintf(qdl_flash.progress_percentage, "%s", qdl_flash.progress_percentage);
            strcat(qdl_flash.progress_percentage, "\n");
            fwrite(qdl_flash.progress_percentage, sizeof(char), strlen(qdl_flash.progress_percentage),
                   qdl_flash.progress_fp);
            FIBO_LOG_DEBUG("buf =====  %s    progress_percentage === %s\n", buf, qdl_flash.progress_percentage);
            fflush(qdl_flash.progress_fp);
            g_usleep(1000 * 1000 * 1);
        }
    }

    if(image_num == i ){
        FIBO_LOG_CRITICAL("qdl flash success\n");
        strcpy(qdl_flash.progress_text,"#The Modem upgrade Success!\\n\\n\n");
        *qdl_success_flag = 1;
    }else{
        FIBO_LOG_CRITICAL("qdl flash fail\n");
        strcpy(qdl_flash.progress_text,"#The Modem upgrade failed!\\n\\n\n");
        *qdl_success_flag = 0;
    }

    fwrite(qdl_flash.progress_text, sizeof(char), strlen(qdl_flash.progress_text), qdl_flash.progress_fp);
    fflush(qdl_flash.progress_fp);

    g_usleep(1000*1000*3);

    FIBO_LOG_CRITICAL("%s\n",qdl_work_space);
    ret = qdl_rmdir(qdl_work_space);
    if(RET_OK != ret){
        FIBO_LOG_CRITICAL("close qdl work space fail\n");
    }else{
        FIBO_LOG_CRITICAL("close qdl work space sueecss\n");
    }

    pclose(qdl_fp);
    pclose(qdl_flash.progress_fp);
    return NULL;
}

gpointer edl_flashing_command(void *data)
{
    int qdl_success_flag = 0;
    emit_edl_flash_status_signal("flashing...");
    if((char *)data){
        FIBO_LOG_CRITICAL("[%s]: \n",__func__);
    }
    fibocom_qdl_flash_command(data,&qdl_success_flag);
    if(qdl_success_flag == 1){
        emit_edl_flash_status_signal("flash ok");
    }else{
        emit_edl_flash_status_signal("flash fail");
    }

    FIBO_LOG_ERROR("[%s]:%s\n",__func__, (char *)data);
}

gpointer fastboot_flashing_command(void *data)
{
    int fastboot_success_flag = 0;
    FIBO_LOG_ERROR("[%s]: %s\n",__func__, (char *)data);
    fibo_adapter_helperm_send_control_message_to_helperd(FLASH_FW_FASTBOOT, (int)strlen("fastboot flashing..."), "fastboot flashing...");
    //emit_fastboot_flash_status_signal("fastboot flashing...");
    if((char *)data){
        fibocom_fastboot_flash_command((char *)data, &fastboot_success_flag);
        if(fastboot_success_flag == 1){
            fibo_adapter_helperm_send_control_message_to_helperd(FLASH_FW_FASTBOOT, (int)strlen("fastboot flash ok"), "fastboot flash ok");
        }else{
            fibo_adapter_helperm_send_control_message_to_helperd(FLASH_FW_FASTBOOT, (int)strlen("fastboot flash fail"), "fastboot flash fail");
        }

        //emit_fastboot_flash_status_signal("fastboot flashing ok");
        FIBO_LOG_ERROR("[%s]:%s\n",__func__, (char *)data);
    }
    if(data){
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

    payload = malloc(sizeof(char) * 512);
    memset(payload,0,sizeof(char) * 512);

    user_data = (fibo_async_struct_type *)userdata;

    if (!user_data) {
        FIBO_LOG_ERROR ("NULL pointer!\n");
    }else {
        service_id = user_data->serviceid;
        cid = user_data->cid;
        memcpy(payload,user_data->payload_str, user_data->payloadlen);
        FIBO_LOG_DEBUG("%s     %d", payload,__LINE__);
    }

    if (userdata) {
        free(userdata);
        userdata = NULL;
    }

    usleep(1000*1000*3);

    char get_qdl_port_cmd[128] = "lsusb | grep \"Fibocom Fibocom FM101 Modem\" | awk -F ' ' 'NR=6 {print $6}'";
    FILE *get_port_fp =NULL;
    char buf[32] = {0};

    for (int i = 0; i < 5; ++i) {
        get_port_fp = NULL;
        memset(buf,0,sizeof(buf));
        sprintf(buf,"init%d",i);

        get_port_fp = popen(get_qdl_port_cmd,"r");
        if(get_port_fp == NULL) {
            FIBO_LOG_DEBUG("open get_port_cmd error\n");
            usleep(1000 * 1000 * 1);
            continue;
        }

        ret = fread(buf, sizeof(char), sizeof(buf), get_port_fp);
        if(ret == RET_ERROR){
            FIBO_LOG_DEBUG("fread get_port_cmd error\n");
            memcpy(buf, "don't match fastboot port", strlen("don't match fastboot port") + 1);
        }else{
            FIBO_LOG_DEBUG("%s\n",buf);
            if(strstr(buf, "2cb7:d00d")){
                FIBO_LOG_CRITICAL("match d00d\n");
                break;
            }
            usleep(1000 * 1000 * 1);
        }
    }

    pclose(get_port_fp);

    if(strstr(buf, "2cb7:d00d") != NULL){
        sprintf(resp_str,"fastboot_flashing");
    }else{
        sprintf(resp_str,"fastboot_switch_port");
        rtcode = 1;
    }

    ret = alloc_and_send_resp_structure(service_id, cid, rtcode, strlen(resp_str), resp_str);

    fibo_mutex_keep_pointer_exist_unlock();

    if (ret != RET_OK) {
        FIBO_LOG_ERROR("send resp to main loop failed!\n");
    }

    if(strstr(buf, "2cb7:d00d") != NULL){
        FIBO_LOG_DEBUG("%s     %d", payload,__LINE__);
        GThread *gthread_fastboot_flash = NULL;
        gthread_fastboot_flash = g_thread_new("fastboot_flash", fastboot_flashing_command, payload);
    }
    return TRUE;
}
/*--------------------------------------qdl flash && fastboot flash end------------------------------------------------*/

/*--------------------------------------Above are External Funcs-------------------------------------------------------*/

