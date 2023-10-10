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
 * @file fibo_helper_mbim_main.c
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
gboolean    g_table_check_flag    = FALSE;

static gint
fibo_helper_control_receiver_init()
{
    int      ret              = RET_ERROR;
    GThread  *ctl_rcv_thread  = NULL;

    // step1: init message queue.
    ret = fibo_helper_queue_init();
    if (ret != RET_OK) {
        FIBO_LOG_ERROR("message_queue_init failed! can't init message seq!\n");
        return RET_ERROR;
    }

    ctl_rcv_thread = g_thread_new ("control_recv", (GThreadFunc)fibo_helper_control_receiver, NULL);
    if (!ctl_rcv_thread) {
        FIBO_LOG_ERROR("thread init failed!\n");
        return RET_ERROR;
    }
    return RET_OK;
}

static gint
fibo_main_receiver_init()
{
    GThread  *main_rcv_thread = NULL;

    main_rcv_thread = g_thread_new ("req_recv", (GThreadFunc)fibo_helper_main_receiver, NULL);
    if (!main_rcv_thread) {
        FIBO_LOG_ERROR("thread init failed!\n");
        return RET_ERROR;
    }
    return RET_OK;
}

/* main func cant be blocked at any time! */
gint main(gint argc, char const *argv[])
{
    guint   owner_id        = 0;
    gint    ret             = RET_ERROR;

    FIBO_LOG_OPEN ("helper_mbim_analyzer");

    #if !GLIB_CHECK_VERSION (2,35,0)
    g_type_init ();
    #endif

    // step1: init a thread to get control message, aka, mbim init and close.
    ret = fibo_helper_control_receiver_init();
    if (ret != RET_OK) {
        FIBO_LOG_CRITICAL("fibo_helper_control_receiver_init failed! exit mainloop!\n");
        return ret;
    }

    // step2: init main receiver to get normal request, but if mbim not ready, should send resp to message seq with error.
    ret = fibo_main_receiver_init();
    if (ret != RET_OK) {
        FIBO_LOG_CRITICAL("fibo_main_receiver_init failed! exit mainloop!\n");
        return ret;
    }

    // main loop go cycle.
    gMainLoop = g_main_loop_new (NULL, FALSE);
    g_main_loop_run (gMainLoop);

    g_main_loop_unref (gMainLoop);
    gMainLoop = NULL;

    fibo_mbim_port_deinit();

    FIBO_LOG_CRITICAL("exiting 'fibo-helper-mbim'...\n");
    FIBO_LOG_CLOSE;

    return RET_OK;
}
