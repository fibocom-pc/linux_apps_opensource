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
 * @file config_helper.c
 * @author ziqi.zhao@fibocom.com (zhaoziqi)
 * @brief 
 * @version 1.0
 * @date 2023-09-23
 * 
 * 
 **/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include<semaphore.h>
#include<sys/sem.h>
#include <gio/gio.h>
#include <execinfo.h>
#include "fibocom-helper-gdbus-generated.h"
#include "fibo_log.h"
#include "fibo_static_config.h"
#include "fibo_config_helper.h"
#include "fibo_dynamic_config.h"
#include "fibo_helper_cid.h"
#include "assert.h"

#define HELPER_BUS_SERVICE "com.fibocom.helper"
#define HELPER_BUS_PATH "/com/fibocom/helper"

static FibocomGdbusHelper *proxy = NULL;
static char roam_mcc_new[8+1] = {0};
static char roam_mcc_old[8+1] = {0};
static bool mcc_changed = false;
static bool static_config_end = false;
static bool dbus_is_ready = false;

void stack_trace()
{
    void *trace[16];
    char **messages = (char **)NULL;
    int i, trace_size = 0;

    trace_size = backtrace(trace, 16);
    messages = backtrace_symbols(trace, trace_size);
    if (messages == NULL)
    {
        FIBO_LOG_ERROR("%s: no backtrace captured.", __func__);
        return;
    }

    for (i = 0; i < trace_size; i++)
    {
        if (messages[i])
            FIBO_LOG_DEBUG("%s.", messages[i]);
    }

    if (messages)
    {
        free(messages);
    }
}

static void sig_handler(int sig)
{
    FIBO_LOG_DEBUG("%s - Signal Received=%d", __func__, sig);

    if (SIGHUP == sig)
    {
        return;
    }
    else if (SIGSEGV == sig)
    {
        stack_trace();
    }
    exit(-1);
}

void send_event_by_mcc_change(void)
{
    int result = 0;
    char *mccmnc_new = NULL;
    msg_st_t msg = {0};

    int msg_len = sizeof(msg_st_t) - sizeof(long int);

    // fibo_set_sim_change(false);
    mccmnc_new = fibo_get_mcc_value();
    if (0 == strlen(mccmnc_new))
    {
        // goto dev_monitor;
        FIBO_LOG_ERROR("get mcc error");
        return;
    }
    FIBO_LOG_DEBUG("get mcc success,mccmnc_new:%s", mccmnc_new);
    fibo_set_disableesim_for_mcc();
    if (0 != strcmp(roam_mcc_old, mccmnc_new))
    {
        msg.msg_type = MCCMNC_CHANGE;
        strncpy(msg.mccmnc, mccmnc_new, sizeof(msg.mccmnc));
        result = msgsnd(get_msg_id(), (void *)&msg, msg_len, 0);
        if (result)
        {
            FIBO_LOG_ERROR("send mccmnc change event error,result:%d", result);
        }
        else
        {
            FIBO_LOG_INFO("send msg success,mcc change mccmnc_new:%s", mccmnc_new);
            strncpy(roam_mcc_old, mccmnc_new, strlen(mccmnc_new));
        }
    }
}

gboolean cfg_get_mcc(void)
{

    mesg_info *response = NULL;
    //check port
    if (!send_message_get_response(GET_NETWORK_MCCMNC,"",0,&response))
    {
        FIBO_LOG_ERROR("GET_NETWORK_MCCMNC error");
        dbus_is_ready = false;
        return false;
    }
    FIBO_LOG_DEBUG("get mccmnc:%s",response->payload);
    strncpy(roam_mcc_new,response->payload,response->payload_lenth>8 ?8 : response->payload_lenth);
    return true;
}


static gboolean modem_sim_change_handler(FibocomGdbusHelper *object, const char *value, gpointer userdata)
{
    FIBO_LOG_INFO("<<<<<<<<<------network mccmnc chanage mcc %s ------>>>>>>>>>>>>", value);
    sem_t *sem =NULL;

    if (value == NULL)
    {
        return TRUE;
    }
    else
    {
        if(!cfg_get_mcc())
        {
            FIBO_LOG_ERROR("[get mcc] error");
            return TRUE;
        }

        send_event_by_mcc_change();
    }
}

gboolean cfg_get_port_state(void)
{
    mesg_info *response = NULL;
    //check port
    if (!send_message_get_response(GET_PORT_STATE,"",0,&response))
    {
        // FIBO_LOG_ERROR("GET_PORT_STATE error");
        dbus_is_ready = false;
        return false;
    }
    FIBO_LOG_DEBUG("get port state:%s",response->payload);
    if(0 == strncmp(response->payload, "normal",strlen("normal")))
    {
        FIBO_LOG_INFO("current port is ready!");
        dbus_is_ready = true;
    }
    else
    {
        dbus_is_ready = false;
        // FIBO_LOG_INFO("modem is not ready!");
        return false;
    }
    return true;
}


static gboolean cfg_modem_status_callback(FibocomGdbusHelper *object, const char *value, gpointer userdata)
{
    int          ret = 0;

    FIBO_LOG_INFO("<<<<<<<<<------modem_status_callback %s ------>>>>>>>>>>>>", value);

    if(value == NULL)
    {
        return TRUE;
    }
    else
    {
        dbus_is_ready = true;
        if(!cfg_get_port_state())
        {
            FIBO_LOG_ERROR("[get_port_state] error");
            return TRUE;
        }

        if(static_config_set())
        {
            return true;
        }
    }

    return TRUE;
}


/* pseudocode Implement the wccd driver and then improve*/
/* static gboolean device_mode_change_handler(int value)
{
    FIBO_LOG_DEBUG("device mode change! %s \n", value);

    if(NULL != get_device_sem_id())
    {
        sem_post(get_device_sem_id());
    }
    FIBO_LOG_DEBUG("receive userdate :%s\n", (char *)userdata);
} */

void set_static_config_flg(bool value)
{
    static_config_end = value;
}

bool get_static_config_flg(void)
{
    return static_config_end;
}


static void owner_name_change_notify(GObject *object, GParamSpec *pspec, gpointer userdata)
{
    gchar *pname_owner = NULL;
    pname_owner = g_dbus_proxy_get_name_owner((GDBusProxy *)object);

    if (NULL != pname_owner)
    {
        FIBO_LOG_INFO("helper service is ready!\n");
        dbus_is_ready = true;
        if(static_config_set())
        {
            return ;
        }
        g_free(pname_owner);
    }
    else
    {
        dbus_is_ready = false;
        FIBO_LOG_DEBUG("DBus service is NOT ready!\n");
        g_free(pname_owner);
    }
}


void fibo_set_sim_change(bool value)
{
    mcc_changed = value;
}

bool fibo_get_sim_change(void)
{
    return mcc_changed;
}

bool fibo_get_sim_reign(void)
{
    return true;
}
char *fibo_get_mcc_value(void)
{
    return roam_mcc_new;
}

static void *fibo_dbus_run(void* arg)
{
    GMainLoop *loop;

    loop = g_main_loop_new(NULL, FALSE);

    g_main_loop_run(loop);

    g_object_unref(proxy);
}

int thread_create(void)
{
    int err;
    pthread_t thr;

    err = pthread_create(&thr, NULL, fibo_dbus_run, NULL);

    if (0 != err)
    {
        FIBO_LOG_DEBUG("Can't create thread: %s", strerror(err));
    }
    else
    {
        FIBO_LOG_DEBUG("New thread created: %s", strerror(err));
    }

    return err;
}

static bool dbus_init_ok = false;

bool fibo_dbus_init_status(void)
{
    return dbus_init_ok;
}
void fibo_dus_init(void)
{
    GError *connerror = NULL;
    GError *proxyerror = NULL;
    GDBusConnection *conn = NULL;
    GMainLoop *loop = NULL;
    GThread *gthread = NULL;

    // struct sigaction sa;
    // memset(&sa, 0, sizeof(sa));
    // sa.sa_handler = sig_handler;
    // sigaction(SIGHUP, &sa, NULL);
    // sigaction(SIGSTOP, &sa, NULL);
    // sigaction(SIGTERM, &sa, NULL);
    // sigaction(SIGINT, &sa, NULL);
#if !GLIB_CHECK_VERSION(2, 35, 0)
    g_type_init();
#endif

    while (1)
    {
        conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &connerror);
        if (connerror == NULL)
        {
            proxy = fibocom_gdbus_helper_proxy_new_sync(conn, G_DBUS_PROXY_FLAGS_NONE, HELPER_BUS_SERVICE, HELPER_BUS_PATH, NULL, &proxyerror);
            if (proxy == 0)
            {
                FIBO_LOG_ERROR("fibocom_gdbus_helper_proxy_new_sync error! %s", proxyerror->message);
                g_error_free(proxyerror);
                sleep(1);
                continue;
            }
            else
            {
                FIBO_LOG_INFO("fibocom_gdbus_helper_proxy_new_sync success!");
                dbus_init_ok = true;
                break;
            }
        }
        else
        {
            FIBO_LOG_ERROR("fibocom_gdbus_helper_proxy_new_sync error! %s", connerror->message);
            g_error_free(connerror);
            sleep(1);
            continue;
        }
    }
    thread_create();
}

bool register_dbus_event_handler(void)
{
    // 注册signal处理函数
    FIBO_LOG_DEBUG("register_dbus_event_handler satrt");
    g_signal_connect(proxy, "notify::g-name-owner", G_CALLBACK(owner_name_change_notify), NULL);
    g_signal_connect(proxy, "cellular-state",G_CALLBACK(cfg_modem_status_callback),NULL);
    g_signal_connect(proxy, "roam-region", G_CALLBACK(modem_sim_change_handler), NULL);
    
    FIBO_LOG_DEBUG("register_dbus_event_handler end");
}

static bool send_message_to_helper(e_command_cid cid, char *payload, int len, mesg_info **response)
{
    GError *callError = NULL;
    GVariant *indata = NULL;
    GVariant *outdata = NULL;
    gint serviceid = 0;
    gint rtcid = 0;
    gint rtcode = 0;
    gint payloadlen = 0;
    gchar *atresp = NULL;

    indata = g_variant_new("((ii)iis)", CONFIGSRV, cid, GET_DATA_SUCCESS, len, payload);
    fibocom_gdbus_helper_call_send_mesg_sync(proxy, (GVariant *)indata, (GVariant **)&outdata, NULL, &callError);
    if (callError == NULL)
    {
        g_variant_get(outdata, "((ii)iis)", &serviceid, &rtcid, &rtcode, &payloadlen, &atresp);
        /* FIBO_LOG_DEBUG("call_atcommand_sync success:serviceid:%d, cid:%d, code:%d,payloadlen:%d, atresp:%s",
                      serviceid, cid, rtcode, payloadlen, atresp); */
        *response = malloc(sizeof(mesg_info) + payloadlen + 1);
        if (NULL != *response)
        {
            memset(*response, 0, sizeof(mesg_info) + payloadlen + 1);
            (*response)->header.service_id = serviceid;
            (*response)->header.command_cid = rtcid;
            (*response)->rtcode = rtcode;
            (*response)->payload_lenth = payloadlen;
            memcpy((*response)->payload, atresp, payloadlen);
        }
        if (outdata != NULL)
        {
            g_variant_unref(outdata);
            FIBO_LOG_DEBUG("unref ok");
        }
        if (NULL != atresp)
        {
            g_free(atresp);
        }
        else
        {
            FIBO_LOG_DEBUG("atresp data is NULL");
        }
    }
    else
    {
        FIBO_LOG_DEBUG("all_atcommand_sync error, %s", callError->message);
    }
}


bool send_message_get_response(e_command_cid cid, char *payload, int len, mesg_info **response)
{
    int i = 0;
    if (!dbus_is_ready)
    {
        FIBO_LOG_DEBUG("gdbus is not ready disconnect");
        return false;
    }
    for (i = 0; i < 3; i++)
    {
        if(NULL != *response)
        {
            free(*response);
        }
        send_message_to_helper(cid, payload, len, response);
        if (NULL == (*response))
        {
            FIBO_LOG_DEBUG("call_atcommand_sync error");
            sleep(3);
            continue;
        }
        if (cid != (*response)->header.command_cid)
        {
            FIBO_LOG_DEBUG("helper response command_cid error, %d", (*response)->header.command_cid);
        }
        if (GET_DATA_SUCCESS == (*response)->rtcode)
        {
            FIBO_LOG_DEBUG("response data serviceid:%d, cid:%d, code:%d,payloadlen:%d, atresp:%s",\
                          (*response)->header.service_id, (*response)->header.command_cid, (*response)->rtcode, (*response)->payload_lenth, (*response)->payload);
            return true;
        }
        else if (SERVICE_BUSY == (*response)->rtcode || GET_DATA_FAIL == (*response)->rtcode || (i +1 >= 3))
        {
            FIBO_LOG_DEBUG("get message error,continue");
            sleep(3);
            continue;
        }
    }
    if(NULL != *response)
    {
        return true;
    }
    return false;
}

void send_message_test()
{
    mesg_info *response = NULL;
    char *msg = "hello!";
    FIBO_LOG_DEBUG("len:%d", (int)strlen(msg));
    send_message_get_response(GET_BODYSAR_STATUS, msg, strlen(msg), &response);
    free(response);
}

bool dbus_service_is_ready(void)
{
    gchar *owner_name = NULL;
    owner_name = g_dbus_proxy_get_name_owner((GDBusProxy *)proxy);
    if (NULL != owner_name)
    {
        FIBO_LOG_INFO("Owner Name: %s", owner_name);
        g_free(owner_name);
        dbus_is_ready = true;
        return true;
    }
    else
    {
        return false;
    }
}
