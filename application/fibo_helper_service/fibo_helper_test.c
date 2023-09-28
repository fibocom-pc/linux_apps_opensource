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
 * @file fibo_flash_main.c
 * @author rick.chen@fibocom.com (chenhaotian)
 * @brief
 * @version 1.0
 * @date 2023-09-23
 *
 *
 **/

#include "fibo_helper_test.h"
#include "libmbim-glib.h"
#include "mbim-fibocom.h"
#include "fibo_helper_basic_func.h"
#include "fibo_helper_test.h"

int
fibo_prase_test_func(FibocomGdbusHelper *skeleton,
                            GDBusMethodInvocation  *invocation,
                            GVariant *str,
                            gpointer callback)
{
    gint                                serviceid      =  0;
    gint                                cid            =  0;
    gint                                rtcode         =  0;
    gint                                payloadlen     =  0;
    gchar                               *atcommand_str =  NULL;
    gchar                               atrsp[]        = "AT:OK";
    GVariant                            *resp_str      = NULL;

    FIBO_LOG_DEBUG("enter fibo_prase_test_func!\n");

    g_variant_get(str, "((ii)iis)", &serviceid, &cid, &rtcode, &payloadlen, &atcommand_str);
    if (!atcommand_str) {
        FIBO_LOG_DEBUG("NULL pointer: atcommand_str\n");
    }

    resp_str = g_variant_new("((ii)iis)", serviceid, cid, 1, strlen(atrsp), atrsp);
    fibocom_gdbus_helper_complete_send_mesg (skeleton, invocation, resp_str);

    FIBO_LOG_DEBUG("exit fibo_prase_test_func!\n");

    fibo_mutex_keep_pointer_exist_unlock();
    return RET_OK;
}

void
fibocom_test_at_ready (MbimDevice   *device,
                       GAsyncResult *res,
                       gpointer     userdata)
{
    g_autoptr(GError)                   error          = NULL;
    guint32                             ret_size       = 0;
    const guint8                        *ret_str       = NULL;
    g_autoptr(MbimMessage)              response       = NULL;
    guint8                              *resp_str      = NULL;
    gint                                ret            = RET_ERROR;
    fibo_async_struct_type              *user_data     =  NULL;

    // int *service_id = (int *)serviceid;
    gint service_id = 0;
    gint cid        = 0x1001;

    FIBO_LOG_DEBUG("enter!\n");
    response = mbim_device_command_finish (device, res, &error);

    if (!response || !mbim_message_response_get_result (response, MBIM_MESSAGE_TYPE_COMMAND_DONE, &error)) {
        g_printerr ("error: operation failed: %s\n", error->message);
        return;
    }

    if (!mbim_message_fibocom_at_command_response_parse (
            response,
            &ret_size,
            &ret_str,
            &error)) {
        g_printerr ("error: couldn't parse response message: %s\n", error->message);
        return;
    }

    resp_str = malloc(ret_size + 1);
    if (!resp_str) {
        g_printerr ("error: malloc space for resp data failed!\n");
        return;
    }

    memset(resp_str, 0, ret_size + 1);
    memcpy(resp_str, ret_str, ret_size);

    g_print ("%s\n", (char *)resp_str);

    user_data = (fibo_async_struct_type *)userdata;
    if (!user_data) {
        FIBO_LOG_CRITICAL ("NULL pointer!\n");
        return;
    }
    service_id = user_data->serviceid;
    cid = user_data->cid;

    free(userdata);
    userdata = NULL;

    ret = alloc_and_send_resp_structure(service_id, cid, 0, ret_size, resp_str);

    fibo_mutex_keep_pointer_exist_unlock();

    if (ret != RET_OK) {
        FIBO_LOG_CRITICAL("send resp to main loop failed!\n");
        return;
    }

    if (resp_str)
        free(resp_str);

    return;
}

void
test_at_command2(void)
{
    gint     serviceid       = FWSWITCHSRV;
    gint     cid             = GET_AP_VERSION;
    gint     rtcode          = RET_ERROR;
    gint     payloadlen      = 0;
    gchar    *atcommand_str  = NULL;
    GVariant *original_str   = NULL;
    gint     ret             = RET_ERROR;

    original_str = g_variant_new("((ii)iii)", serviceid, cid, rtcode, payloadlen, atcommand_str);
    if (atcommand_str)
        original_str = g_variant_new("((ii)iis)", serviceid, cid, rtcode, payloadlen, atcommand_str);
/*
    while (TRUE) {
        ret = fibo_prase_get_ap_version(serviceid, cid, rtcode, payloadlen, atcommand_str, original_str, fibocom_test_at_ready);
        // fibo_prase_get_md_version(serviceid, cid, rtcode, payloadlen, atcommand_str, original_str, fibocom_test_at_ready);
        // usleep(500);
    }
*/
    return;
}
void
test_at_command1(void)
{
    gint     serviceid       = FWSWITCHSRV;
    gint     cid             = GET_AP_VERSION;
    gint     rtcode          = RET_ERROR;
    gint     payloadlen      = 1;
    gchar    *atcommand_str  = "e";
    GVariant *original_str   = NULL;
    gint     ret             = RET_ERROR;

    original_str = g_variant_new("((ii)iis)", serviceid, cid, rtcode, payloadlen, atcommand_str);

    void *skeleton = NULL;
    void *invocation = NULL;
    skeleton = &cid;
    invocation = &cid;

    while (TRUE) {
	// fibo_prase_get_ap_version((FibocomGdbusHelper *)skeleton, (GDBusMethodInvocation *)invocation, original_str, fibocom_test_at_ready);
       // ret = fibo_prase_get_ap_version(serviceid, cid, rtcode, payloadlen, atcommand_str, fibocom_test_at_ready);
        // fibo_prase_get_md_version(serviceid, cid, rtcode, payloadlen, atcommand_str, original_str, fibocom_test_at_ready);
        // fibo_prase_get_fw_info(serviceid, cid, rtcode, payloadlen, atcommand_str, original_str, fibocom_test_at_ready);
        usleep(1000 * 500);
    }
    return;
}

