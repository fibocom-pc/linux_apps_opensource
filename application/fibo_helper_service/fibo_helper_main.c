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

#include <glib.h>
#include "unistd.h"
#include "fibo_helper_common.h"
#include "fibo_helper_basic_func.h"


GMainLoop   *gMainLoop            = NULL;
GThread     *main_analyzer_thread = NULL;
gboolean    g_table_check_flag    = FALSE;

static void
check_global_tables(void)
{
    gboolean check_flag     =  FALSE;

    check_flag = fibo_check_supported_request_table();
    if (!check_flag) {
        FIBO_LOG_CRITICAL ("fibo_check_supported_request_table failed!\n");
        return;
    }

    check_flag = fibo_check_module_info_table();
    if (!check_flag) {
        FIBO_LOG_CRITICAL ("fibo_check_module_info_table failed!\n");
        return;
    }

    FIBO_LOG_DEBUG ("check_global_tables finished!\n");
    g_table_check_flag = TRUE;
    return;
}

static void
fibo_helper_mbim_app_init()
{
    int      ret                   = RET_ERROR;
    GThread  *mbim_ctl_rcv_thread  = NULL;

    ret = fibo_helper_sequence_init();
    if (ret != RET_OK) {
        FIBO_LOG_CRITICAL("message_sequence_init failed! can't init message seq!");
        return;
    }
    // fibo-helper-mbim should be a independent app.
    // so here wont call system func to execute fibo-helper-mbim app.
    // system("`find . -name fibo_helper_mbim`& ");

    mbim_ctl_rcv_thread = g_thread_new ("mbim-ctl-rcv", (GThreadFunc)fibo_helper_control_message_receiver, NULL);
    return;
}

static void
fibo_helper_device_check_thread_init()
{
    int      ret              = RET_ERROR;
    GThread  *dev_check_thread  = NULL;

    dev_check_thread = g_thread_new ("dev-check", (GThreadFunc)fibo_helper_device_check, NULL);
    return;
}

/* main func cant be blocked at any time! */
gint main(gint argc, char const *argv[])
{
    guint   owner_id              = 0;
    pid_t   forkid;

    FIBO_LOG_OPEN ("helper");

    fibo_mutex_init();

    // Setup signals
    fibo_set_necessary_signals();

    #if !GLIB_CHECK_VERSION (2,35,0)
    g_type_init ();
    #endif

    fibo_helper_mbim_app_init();

    fibo_helper_device_check_thread_init();

    owner_id = fibo_register_helper_service();

    check_global_tables();

    fibo_helper_mmevent_register();

    // main loop go cycle.
    gMainLoop = g_main_loop_new (NULL, FALSE);
    g_main_loop_run (gMainLoop);

    /* Below funcs are used to unregister all dependent variables and exit main func */

    // g_bus_unown_name (owner_id);

    fibo_mutex_force_sync_unlock();

    fibo_udev_deinit();

    g_main_loop_unref (gMainLoop);
    gMainLoop = NULL;

    FIBO_LOG_CRITICAL("exiting 'fibo-helper-dbus'...\n");
    FIBO_LOG_CLOSE;

    return RET_OK;
}
