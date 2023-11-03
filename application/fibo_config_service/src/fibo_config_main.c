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
 * @file fibo_config_main.c
 * @author ziqi.zhao@fibocom.com (zhaoziqi)
 * @brief 
 * @version 1.0
 * @date 2023-09-23
 * 
 * 
 **/

#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>
#include "version.h"
#include "fibo_cfg_log.h"
#include "fibo_static_config.h"
#include "fibo_dynamic_config.h"
#include "fibo_config_helper.h"

int main(int argc, char **argv)
{
    bool result = 0;
    int get_device_mode_method = 0;
    pthread_t dbus_tid;
    pthread_t event_tid;
    pthread_t dynamic_tid;
    void *dbus_result = NULL;
    void *event_result = NULL;
    void *dynamic_result = NULL;
    int cnt = 0;
    
    CFG_LOG_OPEN();
    CFG_LOG_INFO("fibo_config_service version:%s", CONFIG_VERSION_STRING);

    if (!fibo_static_ini_cfg())
    {
        CFG_LOG_ERROR("ini file parse error");
        return 1;
    }
    if(0 == fibo_get_start_state())
    {
        CFG_LOG_INFO("fibo_config_service config not run");
        CFG_LOG_CLOSE();
        return 0;
    }

    fibo_dus_init();

    if (!fibo_static_config_paese())
    {
        CFG_LOG_ERROR("static config error");
        return 1;
    }
    CFG_LOG_INFO("wait dbus connect service...");
    while ((!dbus_service_is_ready()) || (!cfg_get_port_state()))
    {
        if(cnt >= 60)
        {
            CFG_LOG_ERROR("set error,exit");
            return 0;
        }
        sleep(2);
        cnt++;
    }
    CFG_LOG_INFO("connect dbus is ready!");
    cnt = 0;
    while(1)
    {
        if(cnt >= 5)
        {
            CFG_LOG_ERROR("set error,exit");
            return 0;
        }
        if(static_config_set())
        {
            /* No other configuration items are available. Exit after the configuration is complete */
            return 0;
        }
        sleep(5);
        cnt++;
    }

    for(int i = 0; i < 3; i++)
    {
        if(static_config_set())
        {
            break;
        }
        sleep(5);
    }
    if(!msg_init())
    {
        CFG_LOG_ERROR("msg_init failed");
        return 1;
    }

    result = pthread_create(&dynamic_tid, NULL, dynamic_thread, NULL);
    if (result)
    {
        CFG_LOG_ERROR("create event_from_file_thread error");
        return 1;
    }
    //first check cueernt mcc
    if(!cfg_get_mcc())
    {
        CFG_LOG_ERROR("[first check cueernt mcc] error");
    }
    send_event_by_mcc_change();
    get_device_mode_method = fibo_device_mode_get();
    if (1 == get_device_mode_method)
    {
        CFG_LOG_DEBUG("create event_from_file_thread start");
        result = pthread_create(&event_tid, NULL, event_from_file_thread, NULL);
        if (result)
        {
            CFG_LOG_ERROR("create event_from_file_thread error");
            return 1;
        }
    }
    else
    {
        CFG_LOG_DEBUG("create event_from_signal_thread start");
        result = pthread_create(&event_tid, NULL, event_from_signal_thread, NULL);
        if (result)
        {
            CFG_LOG_ERROR("create event_from_signal_thread error");
            return 1;
        }
    }

    
    // fibo_dbus_run();
    register_dbus_event_handler();
    pthread_join(event_tid, &event_result);
    pthread_join(dynamic_tid, &dynamic_result);
    fibo_deinit();
    dynamic_deinit();
    CFG_LOG_CLOSE();
    return 0;
}