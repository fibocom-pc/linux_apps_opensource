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
#include "cfg_log.h"
#include "static_config.h"
#include "config_helper.h"
#include "dynamic_config.h"

#define HELPER_BUS_SERVICE "com.fibocom.helper"
#define HELPER_BUS_PATH "/com/fibocom/helper"

static FibocomGdbusHelper *proxy = NULL;
static char mcc[8] = "440";
static bool mcc_changed = false;
static bool static_config_end = false;

void stack_trace()
{
    void *trace[16];
    char **messages = (char **)NULL;
    int i, trace_size = 0;

    trace_size = backtrace(trace, 16);
    messages = backtrace_symbols(trace, trace_size);
    if (messages == NULL)
    {
        CFG_LOG_ERROR("%s: no backtrace captured.", __func__);
        return;
    }

    for (i = 0; i < trace_size; i++)
    {
        if (messages[i])
            CFG_LOG_DEBUG("%s.", messages[i]);
    }

    if (messages)
    {
        free(messages);
    }
}

static void sig_handler(int sig)
{
    CFG_LOG_DEBUG("%s - Signal Received=%d", __func__, sig);

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

static gboolean modem_status_handler(FibocomGdbusHelper *object, const char *value, gpointer userdata)
{
    CFG_LOG_DEBUG("modem_status_handler invoked! %s \n", value);
    if (userdata == NULL)
    {
        return TRUE;
    }
    else
    {
        CFG_LOG_DEBUG("[%s]:recive userdate :%s\n", (char *)userdata, (char *)userdata);
    }
}

static gboolean modem_sim_change_handler(FibocomGdbusHelper *object, const char *value, gpointer userdata)
{
    CFG_LOG_DEBUG("network mccmnc chanage mcc %s ", value);
    sem_t *sem =NULL;

    if (userdata == NULL)
    {
        return TRUE;
    }
    else
    {
        fibo_set_sim_change(true);
        sem = get_mcc_sem_id();
        if(NULL != sem)
        {
            sem_post(sem);
        }
        CFG_LOG_DEBUG("recive userdate :%s\n", (char *)userdata);
        strncpy(mcc, userdata, strlen(userdata));
        CFG_LOG_DEBUG("network MCCMNC:%s\n", (char *)mcc);
    }
}


/* pseudocode Implement the wccd driver and then improve*/
/* static gboolean device_mode_change_handler(int value)
{
    CFG_LOG_DEBUG("device mode change! %s \n", value);

    if(NULL != get_device_sem_id())
    {
        sem_post(get_device_sem_id());
    }
    CFG_LOG_DEBUG("recive userdate :%s\n", (char *)userdata);
} */

void set_static_config_flg(bool value)
{
    static_config_end = value;
}

bool get_static_config_flg(void)
{
    return static_config_end;
}

static gboolean service_status_handler(FibocomGdbusHelper *object, const char *value, gpointer userdata)
{
    CFG_LOG_DEBUG("Revice signal : %s", value);
    /* sem_t *sem =NULL; */

    // if(strcmp(value, "413c:8213") != 0)
    if (strcmp(value, "4d75") != 0)
    {
        CFG_LOG_DEBUG("[-------------------------------]Modem not exit!\n");
    }
    /* test thread */
    /* sem = get_mcc_sem_id();
    if(NULL != sem)
    {
        sem_post(sem);
    } */
}

static bool dbus_is_ready = false;

static void owner_name_change_notify(GObject *object, GParamSpec *pspec, gpointer userdata)
{
    gchar *pname_owner = NULL;
    pname_owner = g_dbus_proxy_get_name_owner((GDBusProxy *)object);

    if (NULL != pname_owner)
    {
        CFG_LOG_DEBUG("DBus service is ready!\n");
        if (!get_static_config_flg())
        {
            if (fibo_get_config_and_set())
            {
                set_static_config_flg(true);
                CFG_LOG_DEBUG("service_status config successfully!");
            }
            else
            {
                CFG_LOG_DEBUG("service_status config fail!");
            }
        }
        dbus_is_ready = true;
        g_free(pname_owner);
    }
    else
    {
        dbus_is_ready = false;
        CFG_LOG_DEBUG("DBus service is NOT ready!\n");
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
    return mcc;
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
        CFG_LOG_DEBUG("Can't create thread: %s", strerror(err));
    }
    else
    {
        CFG_LOG_DEBUG("New thread created: %s", strerror(err));
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
                CFG_LOG_ERROR("fibocom_gdbus_helper_proxy_new_sync error! %s", proxyerror->message);
                g_error_free(proxyerror);
                sleep(1);
                continue;
            }
            else
            {
                CFG_LOG_INFO("fibocom_gdbus_helper_proxy_new_sync success!");
                dbus_init_ok = true;
                break;
            }
        }
        else
        {
            CFG_LOG_ERROR("fibocom_gdbus_helper_proxy_new_sync error! %s", connerror->message);
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
    CFG_LOG_DEBUG("register_dbus_event_handler satrt");
    g_signal_connect(proxy, "notify::g-name-owner", G_CALLBACK(owner_name_change_notify), NULL);
    /* g_signal_connect(proxy, "modem-status", G_CALLBACK(modem_status_handler), NULL);
    g_signal_connect(proxy, "service-status", G_CALLBACK(service_status_handler), NULL); */
    g_signal_connect(proxy, "roam-region", G_CALLBACK(modem_sim_change_handler), NULL);
    CFG_LOG_DEBUG("register_dbus_event_handler end");
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

    indata = g_variant_new("((ii)iis)", CONFIGSERVICE, cid, GET_DATA_SUCCESS, len, payload);

    fibocom_gdbus_helper_call_send_mesg_sync(proxy, (GVariant *)indata, (GVariant **)&outdata, NULL, &callError);
    if (callError == NULL)
    {
        g_variant_get(outdata, "((ii)iis)", &serviceid, &rtcid, &rtcode, &payloadlen, &atresp);
        CFG_LOG_DEBUG("call_atcommand_sync success:serviceid:%d, cid:%d, code:%d,payloadlen:%d, atresp:%s",
                      serviceid, cid, rtcode, payloadlen, atresp);

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
            CFG_LOG_DEBUG("unref ok");
        }
        if (NULL != atresp)
        {
            g_free(atresp);
        }
        else
        {
            CFG_LOG_DEBUG("atresp data is NULL");
        }
    }
    else
    {
        CFG_LOG_DEBUG("all_atcommand_sync error, %s", callError->message);
    }
}

bool get_dbus_connect_flg(void)
{
    if (NULL == proxy)
    {
        return false;
    }
    else
    {
        return true;
    }
}

bool send_message_get_response(e_command_cid cid, char *payload, int len, mesg_info **response)
{
    int i = 0;
    if (!dbus_is_ready)
    {
        CFG_LOG_DEBUG("gdbus is not ready disconnect");
        return false;
    }

    for (i = 0; i < 3; i++)
    {
        send_message_to_helper(cid, payload, len, response);
        if (NULL == (*response))
        {
            CFG_LOG_DEBUG("call_atcommand_sync error");
            continue;
        }
        if (cid != (*response)->header.command_cid)
        {
            CFG_LOG_DEBUG("helper response command_cid error, %d", (*response)->header.command_cid);
        }
        if (GET_DATA_SUCCESS == (*response)->rtcode)
        {
            // CFG_LOG_DEBUG("response data serviceid:%d, cid:%d, code:%d,payloadlen:%d, atresp:%s",\
                          (*response)->header.service_id, (*response)->header.command_cid, (*response)->rtcode, (*response)->payload_lenth, (*response)->payload);
            break;
        }
        else if (SERVICE_BUSY == (*response)->rtcode || GET_DATA_FAIL == (*response)->rtcode)
        {
            CFG_LOG_DEBUG("get message error,continue");
            free(*response);
            continue;
        }
    }

    if (i >= 3 || NULL == *response)
    {
        CFG_LOG_DEBUG("get message error");
        return false;
    }

    return true;
}

void send_message_test()
{
    mesg_info *response = NULL;
    char *msg = "hello!";
    CFG_LOG_DEBUG("len:%d\n", (int)strlen(msg));
    send_message_get_response(GET_BODYSAR_STATUS, msg, strlen(msg), &response);
    free(response);
}

bool dbus_service_is_ready(void)
{
    gchar *owner_name = NULL;
    owner_name = g_dbus_proxy_get_name_owner((GDBusProxy *)proxy);
    if (NULL != owner_name)
    {
        CFG_LOG_DEBUG("Owner Name: %s", owner_name);
        g_free(owner_name);
        dbus_is_ready = true;
        return true;
    }
    else
    {
        return false;
    }
}
