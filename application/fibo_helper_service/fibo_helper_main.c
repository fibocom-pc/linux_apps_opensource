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
 * @file fibo_helper_main.c
 * @author rick.chen@fibocom.com (chenhaotian)
 * @brief
 * @version 1.0
 * @date 2023-09-23
 *
 *
 **/

#include <glib.h>
#include "unistd.h"
#include "fibo_helper_common.h"
#include "fibo_helper_basic_func.h"


GMainLoop   *gMainLoop            = NULL;

static gint
fibo_helperd_control_receiver_init()
{
    int      ret                   = RET_ERROR;
    GThread  *mbim_ctl_rcv_thread  = NULL;

    ret = fibo_helper_queue_init();
    if (ret != RET_OK) {
        FIBO_LOG_ERROR("message_queue_init failed! can't init message seq!");
        return RET_OK;
    }

    mbim_ctl_rcv_thread = g_thread_new ("mbim-ctl-rcv", (GThreadFunc)fibo_helper_control_message_receiver, NULL);
    if (!mbim_ctl_rcv_thread) {
        FIBO_LOG_ERROR("thread init failed!\n");
        return RET_ERROR;
    }

    return RET_OK;
}

static gint
fibo_helper_device_check_thread_init()
{
    int      ret              = RET_ERROR;
    GThread  *dev_check_thread  = NULL;

    dev_check_thread = g_thread_new ("dev-check", (GThreadFunc)fibo_helper_device_check, NULL);
    if (!dev_check_thread) {
        FIBO_LOG_ERROR("thread init failed!\n");
        return RET_ERROR;
    }

    return RET_OK;
}

/* main func can't be blocked at any time! */
gint main(gint argc, char const *argv[])
{
    gint    ret        = RET_ERROR;

    FIBO_LOG_OPEN ("helper");
    FIBO_LOG_INFO("fibo_helper_service version:%s", HELPER_VERSION_STRING);

    // cause other service will call helper to execute command, here must register it to dbus firstly.
    ret = fibo_register_helper_service();
    if (ret != RET_OK) {
        FIBO_LOG_CRITICAL("fibo_register_helper_service failed! exit mainloop!\n");
        return ret;
    }

    ret = fibo_mutex_init();
    if (ret != RET_OK) {
        FIBO_LOG_CRITICAL("fibo_mutex_init failed! exit mainloop!\n");
        return ret;
    }

    // Setup signals
    ret = fibo_set_linux_app_signals();
    if (ret != RET_OK) {
        FIBO_LOG_CRITICAL("fibo_set_linux_app_signals failed! exit mainloop!\n");
        return ret;
    }

    // g_type_system will be initialized automatically from glib 2.36. we need to initialized it manually if glib version is before 2.36.
    // this system will be used to support object-faced language's class, object feature.
    #if !GLIB_CHECK_VERSION (2,35,0)
    g_type_init ();
    #endif

    ret = fibo_helperd_control_receiver_init();
    if (ret != RET_OK) {
        FIBO_LOG_CRITICAL("fibo_helper_control_receiver_init failed! exit mainloop!\n");
        return ret;
    }

    ret = fibo_helper_device_check_thread_init();
    if (ret != RET_OK) {
        FIBO_LOG_CRITICAL("fibo_helper_device_check_thread_init failed! exit mainloop!\n");
        return ret;
    }

    ret = fibocom_hwreset_gpio_init();
    if (ret != RET_OK) {
        FIBO_LOG_CRITICAL("fibocom_hwreset_gpio_init failed!\n");
    }
/*
    ret = fibo_helper_mmevent_register();
    if (ret != RET_OK) {
        FIBO_LOG_CRITICAL("fibo_helper_mmevent_register failed! exit mainloop!\n");
        return ret;
    }
*/

    // main loop go cycle.
    gMainLoop = g_main_loop_new (NULL, FALSE);
    g_main_loop_run (gMainLoop);

    /* Below funcs are used to unregister all dependent variables and exit main func */

    fibo_mutex_force_sync_unlock();

    fibo_udev_deinit();

    g_main_loop_unref (gMainLoop);
    gMainLoop = NULL;

    FIBO_LOG_CRITICAL("exiting 'fibo-helper-dbus'...\n");
    FIBO_LOG_CLOSE;

    return RET_OK;
}
