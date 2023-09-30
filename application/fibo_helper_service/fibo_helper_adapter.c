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

#include <stdio.h>
#include "fibo_helper_adapter.h"
#include "glib-unix.h"
#include "pthread.h"
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include "poll.h"

/* 全局变量 */
struct udev            *udev                         = NULL;
struct udev_monitor    *monitor                      = NULL;

gboolean               g_mbim_device_init_flag       = FALSE;
static GCancellable    *cancellable                  = NULL;
static MbimDevice      *mbimdevice                   = NULL;
static MbimProxy       *proxy                        = NULL;

static gboolean        device_open_proxy_flag        = TRUE;
static gboolean        device_open_ms_mbimex_v2_flag = FALSE;
static gboolean        device_open_ms_mbimex_v3_flag = FALSE;
static gboolean        g_udev_init_flag              = FALSE;

static gint            g_error_flag                  = 0;
static pthread_mutex_t mutex_force_sync;
static pthread_mutex_t mutex_cellular_info_operate;
static pthread_mutex_t mutex_keep_pointer_exist;
static pthread_mutex_t mutex_mbim_flag_operate;
static pthread_mutex_t mutex_sim_insert_flag_operate;

extern GMainLoop      *gMainLoop;
extern GThread        *main_analyzer_thread;
fibocom_cellular_type g_cellular_info                = {CELLULAR_STATE_UNKNOWN, CELLULAR_TYPE_UNKNOWN, "ERROR", -1, "ERROR"};
async_user_data_type  user_data                      = {0, 0, NULL, NULL};

extern FibocomGdbusHelper *g_skeleton;

#define REQUEST_MAX_RETRY                2
#define DEFAULT_CELLULAR_TYPE            "usb"
#define PCIE_GREP_MODULE_CMD_LEN         0
#define USB_GREP_MODULE_CMD_LEN          23  // max size like "lsusb | grep 2cb7:01a2"
#define GREP_MBIM_PORT_CMD_LEN           30
#define MODULE_ID_CHECK_CMD_LEN          (USB_GREP_MODULE_CMD_LEN >= PCIE_GREP_MODULE_CMD_LEN ? USB_GREP_MODULE_CMD_LEN : PCIE_GREP_MODULE_CMD_LEN)
#define MM_PORT_MBIM_SIGNAL_NOTIFICATION "notification"
#define RDONLY                           "r"
#define WRONLY                           "w"

Fibocom_module_info_type module_info_table[] = {
/*   Module name     module_type          usbsubsysid   pciessvid  pciessdid   mbimport name    dlport name   atport name */
    {"FM101-GL-00",  CELLULAR_TYPE_USB,   "2cb7:01a2",  {0},       {0},         "cdc-wdm",      "05c6:9008",  "ttyUSB1"},
    {"FM101-GL-00",  CELLULAR_TYPE_USB,   "2cb7:01a3",  {0},       {0},         "cdc-wdm",      "05c6:9008",  "ttyUSB"},
    {"FM101-GL-00",  CELLULAR_TYPE_USB,   "2cb7:01a4",  {0},       {0},         "cdc-wdm",      "05c6:9008",  "ttyUSB1"},
    {"FM101-GL-00",  CELLULAR_TYPE_USB,   "413c:8209",  {0},       {0},         "cdc-wdm",      "05c6:9008",  "ttyUSB"},
    {"FM101-GL-00",  CELLULAR_TYPE_USB,   "413c:8211",  {0},       {0},         "cdc-wdm",      "05c6:9008",  "ttyUSB"},
    {"FM101-GL-00",  CELLULAR_TYPE_USB,   "413c:8213",  {0},       {0},         "cdc-wdm",      "05c6:9008",  "ttyUSB"},
    {"FM101-GL-00",  CELLULAR_TYPE_USB,   "413c:8215",  {0},       {0},         "cdc-wdm",      "05c6:9008",  "ttyUSB"},
    {"QC-EDL",       CELLULAR_TYPE_USB,   "05c6:9008",  {0},       {0},         {0},            "05c6:9008",  {0}},
    {"QC-FASTBOOT",  CELLULAR_TYPE_USB,   "2cb7:d00d",  {0},       {0},         {0},            "2cb7:d00d",  {0}},
    {"FM350-GL-00",  CELLULAR_TYPE_PCIE,  {0},          "0d40",    "4d75",      {0},            {0},          "wwan0at0"},
    {"L860-GL-16",   CELLULAR_TYPE_PCIE,  {0},          "xxxx",    "xxxx",      {0},            {0},          "wwan0at0"},
};

/*--------------------------------------Below are Internal Funcs-------------------------------------------------------*/
static gboolean
quit_cb (gpointer user_data)
{
    gint output_seq_id = RET_ERROR;
    gint input_seq_id  = RET_ERROR;
    gchar cmd_buf[11]  = {0};

    input_seq_id  = fibo_adapter_get_helper_seq_id(SEQ_INPUT);
    output_seq_id = fibo_adapter_get_helper_seq_id(SEQ_OUTPUT);

    fibo_adapter_send_control_message_to_mbim(CTL_MBIM_END, 0, NULL);

    sprintf(cmd_buf, "ipcrm -q %d", input_seq_id);
    system(cmd_buf);

    sprintf(cmd_buf, "ipcrm -q %d", output_seq_id);
    system(cmd_buf);

    if (gMainLoop) {
        FIBO_LOG_CRITICAL ("Caught signal, stopping main loop...\n");
        g_idle_add ((GSourceFunc) g_main_loop_quit, gMainLoop);
    }

    return FALSE;
}

static gint
port_notification_cb (MbimDevice   *Device,
                      MbimMessage  *notification,
                      gpointer     userdata)
{
    FIBO_LOG_DEBUG("port_notification_cb hello world!\n");

    guint        cid         = RET_OK;
    const gchar  *raw_buffer = NULL;
    MbimService  service     = RET_OK;

    service = mbim_message_indicate_status_get_service (notification);
    cid     = mbim_message_indicate_status_get_cid (notification);

    FIBO_LOG_DEBUG("indication service is %d, cid is %d\n", service, cid);

    raw_buffer = mbim_cid_get_printable (service, cid);
    if (!raw_buffer) {
        FIBO_LOG_CRITICAL("raw buffer is NULL!\n");
        return RET_ERROR;
    }

    FIBO_LOG_DEBUG("Message:%s\n", raw_buffer);
/*
    // further: change to customized signal emit func.
    g_signal_emit_by_name (mbimdevice,
                           MM_PORT_MBIM_SIGNAL_NOTIFICATION,
                           userdata);
*/
    return RET_ERROR;
}

static void
device_open_ready (MbimDevice   *dev,
                   GAsyncResult *res)
{
    GError *error = NULL;

    FIBO_LOG_DEBUG("device_open_ready hello world!\n");

    if (!mbim_device_open_finish (dev, res, &error)) {
        g_printerr ("error: couldn't open the MbimDevice: %s\n",
                    error->message);
        exit (EXIT_FAILURE);
    }

    FIBO_LOG_DEBUG ("MBIM Device at '%s' ready\n",
             mbim_device_get_path_display (dev));

    fibo_adapter_mutex_mbim_flag_operate_lock();
    g_mbim_device_init_flag = TRUE;
    fibo_adapter_mutex_mbim_flag_operate_unlock();

    FIBO_LOG_DEBUG("mbim port init finished! flag:%d\n", g_mbim_device_init_flag);
/*
    // further: add func to receive and deal with specific mbim indication message.
    g_signal_connect (mbimdevice,
                      MBIM_DEVICE_SIGNAL_INDICATE_STATUS,
                      G_CALLBACK (port_notification_cb),
                      NULL);
*/
    return;
}

static void
device_new_ready (GObject      *unused,
                  GAsyncResult *res)
{
    GError *error = NULL;
    MbimDeviceOpenFlags open_flags = MBIM_DEVICE_OPEN_FLAGS_NONE;

    FIBO_LOG_DEBUG("device_new_ready hello world!\n");

    mbimdevice = mbim_device_new_finish (res, &error);
    if (!mbimdevice) {
        g_printerr ("error: couldn't create MbimDevice: %s\n",
                    error->message);
        return;
    }

    if (device_open_proxy_flag)
        open_flags |= MBIM_DEVICE_OPEN_FLAGS_PROXY;
    if (device_open_ms_mbimex_v2_flag)
        open_flags |= MBIM_DEVICE_OPEN_FLAGS_MS_MBIMEX_V2;
    if (device_open_ms_mbimex_v3_flag)
        open_flags |= MBIM_DEVICE_OPEN_FLAGS_MS_MBIMEX_V3;

    /* Open the device */
    mbim_device_open_full (mbimdevice,
                           open_flags,
                           30,
                           cancellable,
                           (GAsyncReadyCallback) device_open_ready,
                           NULL);
    return;
}


static gint
fibo_udev_deinit(struct udev         **udev_addr,
                 struct udev_monitor **monitor_addr)
{
    if (!*udev_addr && !*monitor_addr)
    {
        FIBO_LOG_CRITICAL("NULL pointer, seems already deinit!\n");
        return RET_OK;
    }

    udev_monitor_unref(*monitor_addr);
    *monitor_addr = NULL;

    udev_unref(*udev_addr);
    *udev_addr = NULL;

    return RET_OK;
}

static void
restore_main_signal_work(int signum)
{
    helper_message_struct  *msgs          = NULL;
    gint                   ret            = RET_ERROR;
    fibo_async_struct_type *user_data     = NULL;
    gint                   cid            = RET_ERROR;
    gint                   service_id     = RET_ERROR;

    FIBO_LOG_CRITICAL("fibo-helper-mbim no resp!\n");

    msgs = (helper_message_struct *)malloc(2048 * sizeof(char));
    if (msgs == NULL)
    {
        FIBO_LOG_CRITICAL("malloc failed!");
        // g_thread_stop(fibo_adapter_device_Check);
        return;
    }
    FIBO_LOG_DEBUG("malloc finished!\n");
    // if alarm timeout, means there must be a message on input pipe, so this func always return RET_OK.
    ret = fibo_adapter_get_any_req_from_dbus(msgs);
    if (ret != RET_OK) {
        FIBO_LOG_CRITICAL("cant get message!\n");
        free(msgs);
        msgs = NULL;
        return;
    }

    user_data = (fibo_async_struct_type *)msgs->mtext;
    cid = user_data->cid;
    service_id = user_data->serviceid;

    fibo_adapter_alloc_and_send_resp_structure(service_id, cid, RET_ERR_PROCESS, 0, NULL);

    user_data = NULL;
    free(msgs);
    msgs = NULL;

    FIBO_LOG_DEBUG("finished!\n");
    // noted below code cause we dont expect mbim's crash influence dbus.
    /*
    if (g_error_flag < 5) {
        fibo_adapter_alloc_and_send_resp_structure(HELPER, CTL_MBIM_NO_RESP, 1, 0, NULL);
        g_error_flag++;
    }
    else
        fibo_adapter_send_control_message_to_dbus(CTL_MBIM_NO_RESP, 0, NULL);
    FIBO_LOG_DEBUG("flag times:%d", g_error_flag);
    */

    return;
}

static int
helper_main_analyzer_timer_handle(void)
{
    int ret = RET_ERROR;

    signal(SIGALRM, restore_main_signal_work);
    // set a 6s alarm cause max timeout time on AT should be common 0.5 + specially 5s.
    ret = alarm(6);
    if (ret != 0)
    {
        FIBO_LOG_DEBUG("alarm is used!\n");
        return RET_ERROR;
    }
    FIBO_LOG_DEBUG("alarm created!\n");
    return RET_OK;
}

static int
helper_main_analyzer_timer_close(void)
{
    alarm(0);
    FIBO_LOG_DEBUG("alarm closed!\n");
    g_error_flag = 0;
    return RET_OK;
}

/*--------------------------------------Above are Internal Funcs-------------------------------------------------------*/

/*--------------------------------------Below are External Funcs-------------------------------------------------------*/

void
fibo_adapter_trigger_app_exit(void) {
    quit_cb(NULL);
}

gint
fibo_adapter_alloc_and_send_resp_structure(gint serviceid, gint cid, gint rtcode, gint payloadlen, gchar *payload_str)
{
    helper_message_struct               *msgs          = NULL;
    fibo_async_struct_type              *user_data     = NULL;
    gint                                ret            = RET_ERROR;

    FIBO_LOG_DEBUG("enter, len:%d\n", payloadlen);

    user_data = (fibo_async_struct_type *)malloc(sizeof(fibo_async_struct_type) + payloadlen + 1);
    if (user_data == NULL)
    {
        FIBO_LOG_CRITICAL("malloc failed!\n");
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

    msgs = (helper_message_struct *)malloc(2048 * sizeof(char));
    if (msgs == NULL)
    {
        FIBO_LOG_CRITICAL("malloc failed!\n");
        free(user_data);
        user_data = NULL;
        return RET_ERROR;
    }
    memset(msgs, 0, 2048);

    memcpy(msgs->mtext, user_data, sizeof(fibo_async_struct_type) + payloadlen);
    msgs->mtype = MSG_NORMAL;

    ret = fibo_adapter_send_resp_to_dbus(msgs, 2048);
    if (ret != RET_OK) {

        FIBO_LOG_CRITICAL("Send message failed!\n");
        free(user_data);
        user_data = NULL;
        free(msgs);
        msgs = NULL;

        return RET_ERROR;
    }

    free(user_data);
    user_data = NULL;
    free(msgs);
    msgs = NULL;

    return RET_OK;
}

// sim_insert_flag_operate mutex will be used to keep sim inserted flag can be operated otomically.
void
fibo_adapter_mutex_sim_insert_flag_operate_unlock()
{
    pthread_mutex_unlock(&mutex_sim_insert_flag_operate);
    return;
}

void
fibo_adapter_mutex_sim_insert_flag_operate_lock()
{
    pthread_mutex_lock(&mutex_sim_insert_flag_operate);
    return;
}

// keep_pointer_exist mutex will be used to keep all params on function's callback can be used normally.
void
fibo_adapter_mutex_mbim_flag_operate_unlock()
{
    pthread_mutex_unlock(&mutex_mbim_flag_operate);
    return;
}

void
fibo_adapter_mutex_mbim_flag_operate_lock()
{
    pthread_mutex_lock(&mutex_mbim_flag_operate);
    return;
}

// keep_pointer_exist mutex will be used to keep all params on function's callback can be used normally.
void
fibo_adapter_mutex_keep_pointer_exist_unlock()
{
    pthread_mutex_unlock(&mutex_keep_pointer_exist);
    return;
}

void
fibo_adapter_mutex_keep_pointer_exist_lock()
{
    pthread_mutex_lock(&mutex_keep_pointer_exist);
    return;
}

// cellular_info_operate mutex will be used to keep nobody will change work cellular info.
void
fibo_adapter_mutex_cellular_info_operate_unlock()
{
    pthread_mutex_unlock(&mutex_cellular_info_operate);
    return;
}

void
fibo_adapter_mutex_cellular_info_operate_lock()
{
    pthread_mutex_lock(&mutex_cellular_info_operate);
    return;
}

// force_sync mutex will be used to keep main analyzer can get req data only after the previous one is done.
void
fibo_adapter_mutex_force_sync_unlock()
{
    pthread_mutex_unlock(&mutex_force_sync);
    return;
}

void
fibo_adapter_mutex_force_sync_lock()
{
    pthread_mutex_lock(&mutex_force_sync);
    return;
}

void
fibo_adapter_all_mutex_init()
{
    int ret = RET_ERROR;

    ret =  pthread_mutex_init(&mutex_force_sync, NULL);
    ret |= pthread_mutex_init(&mutex_cellular_info_operate, NULL);
    ret |= pthread_mutex_init(&mutex_keep_pointer_exist, NULL);
    ret |= pthread_mutex_init(&mutex_mbim_flag_operate, NULL);
    ret |= pthread_mutex_init(&mutex_sim_insert_flag_operate, NULL);
    // ret |= pthread_mutex_init(&mutex_mbim_fail_flag_operate, NULL);

    if (ret != RET_OK)
        FIBO_LOG_CRITICAL("init mutex failed!\n");

    return;
}

int
fibo_adapter_send_control_message_to_dbus(int cid, int payloadlen, char *payload_str)
{
    helper_message_struct               *msgs          = NULL;
    fibo_async_struct_type              *user_data     = NULL;
    gint                                ret            = RET_ERROR;

    FIBO_LOG_DEBUG("enter, len:%d\n", payloadlen);

    user_data = (fibo_async_struct_type *)malloc(sizeof(fibo_async_struct_type) + payloadlen + 1);
    if (user_data == NULL) {
        FIBO_LOG_CRITICAL("malloc failed!\n");
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

    user_data->serviceid   = HELPER;
    user_data->cid         = cid;
    user_data->rtcode      = 0;

    msgs = (helper_message_struct *)malloc(2048 * sizeof(char));
    if (msgs == NULL) {
        FIBO_LOG_CRITICAL("malloc failed!\n");
        free(user_data);
        user_data = NULL;
        return RET_ERROR;
    }
    memset(msgs, 0, 2048);

    memcpy(msgs->mtext, user_data, sizeof(fibo_async_struct_type) + payloadlen);
    msgs->mtype = MSG_CONTROL;

    ret = fibo_adapter_send_resp_to_dbus(msgs, 2048);
    free(user_data);
    user_data = NULL;
    free(msgs);
    msgs = NULL;

    if (ret != RET_OK) {
        FIBO_LOG_CRITICAL("Send message failed!\n");
        return RET_ERROR;
    }

    return RET_OK;
}

int
fibo_adapter_send_control_message_to_mbim(int cid, int payloadlen, char *payload_str)
{
    helper_message_struct               *msgs          = NULL;
    fibo_async_struct_type              *user_data     = NULL;
    gint                                ret            = RET_ERROR;

    FIBO_LOG_DEBUG("enter, len:%d\n", payloadlen);

    user_data = (fibo_async_struct_type *)malloc(sizeof(fibo_async_struct_type) + payloadlen + 1);
    if (user_data == NULL) {
        FIBO_LOG_CRITICAL("malloc failed!\n");
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

    user_data->serviceid   = HELPER;
    user_data->cid         = cid;
    user_data->rtcode      = 0;

    msgs = (helper_message_struct *)malloc(2048 * sizeof(char));
    if (msgs == NULL) {
        FIBO_LOG_CRITICAL("malloc failed!\n");
        free(user_data);
        user_data = NULL;
        return RET_ERROR;
    }
    memset(msgs, 0, 2048);

    memcpy(msgs->mtext, user_data, sizeof(fibo_async_struct_type) + payloadlen);
    msgs->mtype = MSG_CONTROL;

    ret = fibo_adapter_send_control_req_to_mbim(msgs, 2048);
    free(user_data);
    user_data = NULL;
    free(msgs);
    msgs = NULL;

    if (ret != RET_OK) {
        FIBO_LOG_CRITICAL("Send message failed!\n");
        return RET_ERROR;
    }

    return RET_OK;
}

void
fibo_adapter_send_async_resp_to_dbus(FibocomGdbusHelper     *skeleton,
                                              GDBusMethodInvocation     *invocation,
                                              gint              serviceid,
                                              gint     cid,
                                              gint     rtcode,
                                              gint     payloadlen,
                                              gchar    *payload_str)
{
    GVariant               *resp_str      = NULL;

    FIBO_LOG_DEBUG("Send resp to caller!\n");

    resp_str = g_variant_new("((ii)iis)", serviceid, cid, rtcode, payloadlen, payload_str);
    fibocom_gdbus_helper_complete_send_mesg (skeleton, invocation, resp_str);

    return;
}

int
fibo_adapter_get_supported_module_number(void)
{
    return sizeof(module_info_table) / sizeof(Fibocom_module_info_type);
}

int
fibo_adapter_get_supported_module_info(Fibocom_module_info_type *module_info, gint index)
{
    memcpy(module_info, &module_info_table[index], sizeof(Fibocom_module_info_type));
    return RET_OK;
}

int
fibo_adapter_get_work_cellular_info(fibocom_cellular_type *work_cellular_info)
{
    fibo_adapter_mutex_cellular_info_operate_lock();

    memcpy(work_cellular_info, &g_cellular_info, sizeof(fibocom_cellular_type));

    fibo_adapter_mutex_cellular_info_operate_unlock();

    return RET_OK;
}

int
fibo_adapter_set_work_cellular_info(fibocom_cellular_type *work_cellular_info)
{
    fibo_adapter_mutex_cellular_info_operate_lock();

    memcpy(&g_cellular_info, work_cellular_info, sizeof(fibocom_cellular_type));

    fibo_adapter_mutex_cellular_info_operate_unlock();

    return RET_OK;
}

void
fibo_adapter_set_unix_signals()
{
    g_unix_signal_add (SIGINT,  (GSourceFunc)quit_cb, NULL);
    g_unix_signal_add (SIGHUP,  (GSourceFunc)quit_cb, NULL);
    g_unix_signal_add (SIGTERM, (GSourceFunc)quit_cb, NULL);
    /* Signal SIGSTOP and SIGKILL cant be catched! Below code will cause exception! */
    /* g_unix_signal_add (SIGSTOP, quit_cb, NULL); */
    return;
}

gint
fibo_adapter_send_message_async(void                   *message,
                                guint32                len,
                                guint32                timeout,
                                GAsyncReadyCallback    callback,
                                gpointer               userdata)
{
    g_autoptr(MbimMessage)   request                              =  NULL;
    guint8                   *req_str                             =  NULL;
    guint32                  req_size                             =  RET_ERROR;
    guint32                  malloc_size                          =  RET_ERROR;
    gint                     ret                                  =  RET_ERROR;
    gint                     retry                                =  REQUEST_MAX_RETRY;
    gchar                    *rcv_data                            =  NULL;
    fibo_async_struct_type   *user_data                           =  NULL;
    gint                     service_id                           =  0;
    gint                     cid                                  =  0x1001;
    gint                     rtcode                               =  RET_OK;
    gint                     payloadlen                           =  RET_OK;
    fibocom_cellular_type    work_cellular_info;
    Fibocom_module_info_type module_info;
    int                      res                                  =  RET_ERROR;

    char                     command[GREP_MBIM_PORT_CMD_LEN + 9]  =  {0};  // add extra "find /dev"
    FILE                     *fp                                  =  NULL;
    char                     commandrsp[GREP_MBIM_PORT_CMD_LEN]   =  {0};
    char                     atport[GREP_MBIM_PORT_CMD_LEN]       =  {0};

    if (!message || !len || !timeout || !callback || !userdata) {
        FIBO_LOG_CRITICAL("NULL pointer!\n");
        return RET_ERROR;
    }

    if (!userdata) {
        FIBO_LOG_DEBUG("Warning: user_data NULL pointer!\n");
        return RET_ERROR;
    }

    memset(&work_cellular_info, 0, sizeof(fibocom_cellular_type));
    memset(&module_info,        0, sizeof(Fibocom_module_info_type));

#ifdef MBIM_FUNCTION_SUPPORTED
    FIBO_LOG_DEBUG("MBIM FLAG:%d\n", g_mbim_device_init_flag);

    while (!g_mbim_device_init_flag && retry >= 0) {
        FIBO_LOG_DEBUG("mbim device not ready! wait for 1s!\n");
        g_usleep(1000 * 1000 * 1);
        retry--;
    }

    if (retry < 0) {
        FIBO_LOG_CRITICAL("Reach max retry, mbim device not ready!\n");
        return RET_ERR_RESOURCE;
    }
#endif
    req_size = strlen(message);

    malloc_size = (req_size > len ? req_size : len);
    malloc_size = malloc_size + 2;

    req_str = malloc(malloc_size);
    if (!req_str) {
        FIBO_LOG_CRITICAL("malloc space failed!\n");
        return RET_ERR_RESOURCE;
    }
    memset(req_str, 0, malloc_size);

    strcpy((char *)req_str, message);
    strcat((char *)req_str, "\r\n");

#ifdef MBIM_FUNCTION_SUPPORTED
    request = mbim_message_fibocom_at_command_set_new (malloc_size, (const guint8 *)req_str, NULL);
    // main thread deal with callback, sub thread will exit without any deal!
    mbim_device_command (mbimdevice,
                         request,
                         timeout,
                         cancellable,
                         (GAsyncReadyCallback)callback,
                         userdata);
#else

    // below commands are used to dynamically get current cellular's atportname.
    ret = fibo_adapter_check_cellular(&res);
    if (ret != RET_OK || res != RET_OK)
    {
        FIBO_LOG_CRITICAL("Helper cant recognize cellular!\n");
        return RET_ERR_RESOURCE;
    }

    fibo_adapter_get_work_cellular_info(&work_cellular_info);

    FIBO_LOG_CRITICAL("Found %s exist!\n", work_cellular_info.work_module_name);

    fibo_adapter_get_supported_module_info(&module_info, work_cellular_info.module_info_index);

    FIBO_LOG_DEBUG("device AT port:%s\n", module_info.atportname);

    if (module_info.atportname == NULL || strlen(module_info.atportname) < 1) {
        FIBO_LOG_CRITICAL("Invalid atport name, dont init!\n");
        return RET_ERR_RESOURCE;
    }

    sprintf(command, "find /dev -name %s*", module_info.atportname);

    // execute command.
    fp = popen(command, RDONLY);
    if (fp == NULL) {
        FIBO_LOG_CRITICAL("execute command failed!\n");
        return RET_ERROR;
    }

    // get command's resp.
    while(fgets(commandrsp, GREP_MBIM_PORT_CMD_LEN, fp) != NULL);

    // check command's execute result.
    ret = pclose(fp);
    if (ret != RET_OK || strlen(commandrsp) == 0) {
        FIBO_LOG_CRITICAL("cant find atport!\n");
        return RET_ERROR;
    }
/*
    for (int i = 0; i <strlen(commandrsp); i++) {
        FIBO_LOG_DEBUG("at cmd return:%d\n", commandrsp[i]);
    }
*/
    memset(atport, 0, sizeof(atport));

    // commandrsp will end with 0x0A, cause string contains invalid symbol, so here will cut 1.
    strncpy(atport, commandrsp + 5, (int)strlen(commandrsp) - 6);

    rcv_data = malloc(2048);
    if (!rcv_data) {
        FIBO_LOG_CRITICAL("malloc space failed!\n");
        if (userdata) {
            free(userdata);
            userdata = NULL;
        }
        return RET_ERR_RESOURCE;
    }
    memset(rcv_data, 0, 2048);

    FIBO_LOG_DEBUG("portname:%s\n", atport);

    // send AT command to module.
    ret = fibo_adapter_send_at_command(req_str, rcv_data, atport);
    if (ret != RET_OK) {
        FIBO_LOG_CRITICAL("Send command failed, error:%d\n", ret);
        if (rcv_data) {
            free(rcv_data);
            rcv_data = NULL;
        }
        if (req_str) {
            free(req_str);
            req_str = NULL;
        }
        rtcode = RET_ERROR;
        payloadlen = 0;
    }
    else {
        FIBO_LOG_DEBUG("get received data:%s\n", rcv_data);
        payloadlen = strlen(rcv_data);
    }

    user_data  = (fibo_async_struct_type *)userdata;
    service_id = user_data->serviceid;
    cid        = user_data->cid;

    if (cid != FLASH_FW_FASTBOOT && cid != FLASH_FW_EDL) {
        // only flash-related 2 funcs will keep original payload, otherwise here will drop previous user_data and full it with new AT's resp.
        if (user_data) {
            free(user_data);
            user_data = NULL;
        }

        user_data = (fibo_async_struct_type *) malloc(sizeof(fibo_async_struct_type) + payloadlen + 1);
        if (user_data == NULL) {
            FIBO_LOG_CRITICAL("malloc failed!\n");
            return RET_ERROR;
        }

        memset(user_data, 0, sizeof(fibo_async_struct_type) + payloadlen + 1);

        if (payloadlen == 0) {
            user_data->payloadlen = 0;
            user_data->payload_str[0] = 0;
        } else {
            user_data->payloadlen = payloadlen;
            memcpy(user_data->payload_str, rcv_data, payloadlen);
        }

        user_data->serviceid   = service_id;
        user_data->cid         = cid;
        user_data->rtcode      = rtcode;
    }

    if (rcv_data) {
        free(rcv_data);
        rcv_data = NULL;
    }

    callback(NULL, NULL, user_data);

#endif

    if (req_str) {
        free(req_str);
        req_str = NULL;
    }

    return RET_OK;
}

void
fibo_adapter_udev_deinit(void)
{
    fibo_udev_deinit(&udev, &monitor);

    g_udev_init_flag = FALSE;
    return;
}

gint
fibo_adapter_udev_init(gint cellular_type, gint *output_fd)
{
    char device_type[5] = {0};
    gint fd             = RET_ERROR;

    if (g_udev_init_flag) {
        FIBO_LOG_DEBUG("udev already initialized!\n");
        return RET_ERROR;
    }

    if (cellular_type > CELLULAR_TYPE_MAX || cellular_type < CELLULAR_TYPE_MIN) {
        FIBO_LOG_CRITICAL("Invalid param, refuse to init!\n");
        return RET_ERROR;
    }

    udev = udev_new();
    if(!udev) {
        FIBO_LOG_CRITICAL("Failed to initialize libudev.\n");
        return RET_ERROR;
    }

    monitor = udev_monitor_new_from_netlink(udev, "udev");
    if (!monitor) {
        FIBO_LOG_CRITICAL("Failed to create udev monitor.\n");
        udev_unref(udev);
        return RET_ERROR;
    }

    switch (cellular_type)
    {
        case CELLULAR_TYPE_PCIE:
            sprintf(device_type, "pcie");
            break;
        case CELLULAR_TYPE_USB:
            sprintf(device_type, "usb");
            break;
        default:
            sprintf(device_type, DEFAULT_CELLULAR_TYPE);
            break;
    }

    /* Monitor all device's change, should be inserted and removed */
    udev_monitor_filter_add_match_subsystem_devtype(monitor, device_type, NULL);
    udev_monitor_enable_receiving(monitor);

    g_udev_init_flag = TRUE;
    *output_fd = udev_monitor_get_fd (monitor);
    FIBO_LOG_DEBUG("fd:%d\n", *output_fd);
    FIBO_LOG_DEBUG("finished!\n");
    return RET_OK;
}

gint
fibo_adapter_check_cellular(gint *check_result)
{
    gint                      i                                = RET_ERROR;
    gint                      max_len                          = RET_ERROR;
    FILE                      *fp                              = NULL;
    char                      command[MODULE_ID_CHECK_CMD_LEN] = {0};
    gint                      ret                              = RET_ERROR;
    char                      *command_rsp                     = NULL;
    gboolean                  checkflag                        = TRUE;
    gint                      matched_devices                  = 0;
    Fibocom_module_info_type  *module_info                     = NULL;
    fibocom_cellular_type     cellular_info;

    if (check_result == NULL)
    {
        FIBO_LOG_CRITICAL("NULL pointer!\n");
        return RET_ERROR;
    }
    *check_result = RET_ERROR;

    fibo_adapter_get_work_cellular_info(&cellular_info);

    command_rsp = malloc(AT_COMMAND_LEN * sizeof(char));
    if (!command_rsp) {
        FIBO_LOG_CRITICAL("malloc command_rsp failed!\n");
        return RET_ERROR;
    }
    memset(command_rsp, 0, AT_COMMAND_LEN * sizeof(char));

    max_len = fibo_adapter_get_supported_module_number();

    for (i = 0; i < max_len; i++) {

        if (!module_info) {
            module_info = malloc(sizeof(Fibocom_module_info_type));
            if (!module_info) {
                FIBO_LOG_CRITICAL("malloc module_info failed!\n");
                free(command_rsp);
                return RET_ERROR;
            }
        }

        // clear all mid-variables to default value for next use.
        fp = NULL;
        memset(module_info, 0, sizeof(Fibocom_module_info_type));
        memset(command_rsp, 0, AT_COMMAND_LEN * sizeof(char));

        ret = fibo_adapter_get_supported_module_info(module_info, i);
        if (ret != RET_OK) {
            FIBO_LOG_CRITICAL("fibo_get_supported_module_info failed!\n");
            free(module_info);
            free(command_rsp);
            return RET_ERROR;
        }

        // generate whole command according to device type.
        if (module_info->module_type == CELLULAR_TYPE_USB)
            sprintf(command, "%s%s", "lsusb | grep ", module_info->usbsubsysid);
        else if (module_info->module_type == CELLULAR_TYPE_PCIE && checkflag)
            sprintf(command, "%s%s", "lspci | grep ", module_info->pciessvid);
        else if (module_info->module_type == CELLULAR_TYPE_PCIE && !checkflag)
            sprintf(command, "%s%s", "lspci | grep ", module_info->pciessdid);

        // execute command.
        fp = popen(command, RDONLY);
        if (fp == NULL) {
            FIBO_LOG_CRITICAL("execute command failed!\n");
            continue;
        }

        // get command's resp.
        while(fgets(command_rsp, AT_COMMAND_LEN, fp) != NULL);

        // check command's execute result.
        ret = pclose(fp);
        if (ret != RET_OK || strlen(command_rsp) == 0) {
            // FIBO_LOG_DEBUG("command return error!\n");
            continue;
        }

        // if pcie device and check ssvid pass, will check ssdid again by changing flag and i
        if (module_info->module_type == CELLULAR_TYPE_PCIE && checkflag) {
            i--;
            checkflag = FALSE;
            continue;
        }
        else if (module_info->module_type == CELLULAR_TYPE_USB || (module_info->module_type == CELLULAR_TYPE_PCIE && !checkflag)) {
            FIBO_LOG_DEBUG("get cellular name: %s\n", module_info->module_name);
            matched_devices++;

            cellular_info.cellular_state    = CELLULAR_STATE_EXISTED;
            // only here to change cellular type cause we expect same type module inserted.
            cellular_info.cellular_type     = (cellular_type_enum_type)module_info->module_type;
            sprintf(cellular_info.work_module_name, "%s", module_info->module_name);
            cellular_info.module_info_index = i;
            sprintf(cellular_info.path, "default");
        }

        break;
    }

    free(command_rsp);

    *check_result = RET_OK;

    // if func found valid cellular more than 1, will return error.
    if (matched_devices > 1 || matched_devices == 0) {
        cellular_info.cellular_state  = CELLULAR_STATE_UNKNOWN;
        *check_result = RET_ERROR;
        sprintf(cellular_info.path, "%s", "ERROR");
    }

    if (matched_devices == 0) {
        cellular_info.cellular_state = CELLULAR_STATE_MISSING;
        FIBO_LOG_DEBUG("Dont find any supported cellular!\n");
    }

    fibo_adapter_set_work_cellular_info(&cellular_info);

    if (matched_devices > 1) {
        FIBO_LOG_CRITICAL("Found more than 1 cellulars!\n");
        return RET_ERROR;
    }

    FIBO_LOG_DEBUG("finished!\n");

    return RET_OK;
}

void
fibo_adapter_mbim_port_deinit(void)
{
    FIBO_LOG_DEBUG("enter!\n");

    fibo_adapter_mutex_mbim_flag_operate_lock();
    g_mbim_device_init_flag = FALSE;
    fibo_adapter_mutex_mbim_flag_operate_unlock();

    if (cancellable)
        g_object_unref (cancellable);
    if (mbimdevice)
        g_object_unref (mbimdevice);
    if (proxy)
        g_object_unref (proxy);

    cancellable = NULL;
    mbimdevice  = NULL;
    proxy       = NULL;

    return;
}

void
fibo_adapter_mbim_port_init(char *mbimportname)
{
    g_autoptr(GError)         error                                = NULL;
    g_autoptr(GFile)          file                                 = NULL;
    fibocom_cellular_type     work_cellular_info;
    char                      command[GREP_MBIM_PORT_CMD_LEN + 9]  = {0};
    FILE                      *fp                                  = NULL;
    char                      commandrsp[GREP_MBIM_PORT_CMD_LEN]   = {0};
    char                      mbimport[GREP_MBIM_PORT_CMD_LEN]     = {0};
    gint                      ret                                  = RET_ERROR;

    FIBO_LOG_DEBUG("begin to init!\n");

    if (g_mbim_device_init_flag) {
        FIBO_LOG_DEBUG("mbim device has been inited!\n");
        return;
    }

    if (mbimportname == NULL) {
        FIBO_LOG_CRITICAL("NULL pointer! refuse to init!\n");
        return;
    }
/*
    // libmbim only support 1 proxy, aka a socket which called "mbim proxy".
    // so there is no need to create a proxy.
    proxy = mbim_proxy_new(&error);
    if (!proxy)
    {
        g_printerr("proxy new failed! error:%s\n", error->message);
        // if not root user to run, here will report privillages error.
        return;
    }
*/

    if (mbimportname == NULL || strlen(mbimportname) < 1) {
        FIBO_LOG_CRITICAL("Invalid mbimport name, dont init!\n");
        return;
    }

    sprintf(command, "find /dev -name %s*", mbimportname);

    // execute command.
    fp = popen(command, RDONLY);
    if (fp == NULL) {
        FIBO_LOG_CRITICAL("execute command failed!\n");
        return;
    }

    // get command's resp.
    while(fgets(commandrsp, GREP_MBIM_PORT_CMD_LEN, fp) != NULL);

    // check command's execute result.
    ret = pclose(fp);
    if (ret != RET_OK || strlen(commandrsp) == 0) {
        FIBO_LOG_CRITICAL("cant find mbimport!\n");
        return;
    }
/*
    for (int i = 0; i <strlen(commandrsp); i++) {
        FIBO_LOG_DEBUG("mbim cmd return:%d\n", commandrsp[i]);
    }
*/
    memset(mbimport, 0, sizeof(mbimport));
    // commandrsp will end with 0x0A, cause string contains invalid symbol, so here will cut 1.
    strncpy(mbimport, commandrsp, (int)strlen(commandrsp) - 1);
    file = g_file_new_for_path(mbimport);
    if (!file)
    {
        FIBO_LOG_CRITICAL("GFile new failed!\n");
        // if not root user to run, here will report privillages error.
        return;
    }
    cancellable = g_cancellable_new();

    // any error about device new will cause cb wont work.
    mbim_device_new (file, cancellable, (GAsyncReadyCallback)device_new_ready, NULL);
    return;
}

void
fibo_adapter_control_mbim_init(void)
{
    fibocom_cellular_type    work_cellular_info;
    Fibocom_module_info_type module_info;

    memset(&work_cellular_info, 0, sizeof(fibocom_cellular_type));
    memset(&module_info,        0, sizeof(Fibocom_module_info_type));

    fibo_adapter_get_work_cellular_info(&work_cellular_info);

    FIBO_LOG_CRITICAL("Found cellular %s added!\n", work_cellular_info.work_module_name);
    if (g_skeleton != NULL)
        fibocom_gdbus_helper_emit_cellular_state(g_skeleton, "[ModemState]cellular existed!");
    else
        FIBO_LOG_CRITICAL("variable is NULL, dont send cellular info signal!\n");

    fibo_adapter_get_supported_module_info(&module_info, work_cellular_info.module_info_index);

    fibo_adapter_send_control_message_to_mbim(CTL_MBIM_INIT, strlen(module_info.mbimportname), module_info.mbimportname);
    return;
}

void
fibo_adapter_device_Check(void)
{
    const char               *action                          = NULL;
    const char               *devnode                         = NULL;
    struct udev_device       *device                          = NULL;
    gint                     res                              = RET_ERROR;
    gint                     ret                              = RET_ERROR;
    gint                     i                                = RET_ERROR;
    gint                     max_len                          = RET_ERROR;
    FILE                     *fp                              = NULL;
    char                     *command_rsp                     = NULL;
    char                     command[MODULE_ID_CHECK_CMD_LEN] = {0};
    fibocom_cellular_type    work_cellular_info;
    Fibocom_module_info_type module_info;
    int                      fd                               = RET_ERROR;
    struct pollfd            ufd;

    FIBO_LOG_DEBUG ("enter func.\n");

    memset(&work_cellular_info, 0, sizeof(fibocom_cellular_type));
    memset(&ufd, 0, sizeof(ufd));

    ret = fibo_adapter_udev_init(work_cellular_info.cellular_type, &fd);
    if (ret == RET_ERROR) {
        FIBO_LOG_CRITICAL("Fatal error! exit main thread!\n");
        return;
    }

    ufd.fd = fd;
    ufd.events = POLLIN;

    while (TRUE)
    {
        device  = NULL;
        action  = NULL;
        devnode = NULL;

        memset(&work_cellular_info, 0, sizeof(fibocom_cellular_type));
        memset(&module_info,        0, sizeof(Fibocom_module_info_type));

        while (poll (&ufd, 1, -1) == -1)
            if (errno != EINTR)
                break;
                
        device = udev_monitor_receive_device (monitor);
        if (!device)
            continue;

        action  = udev_device_get_action (device);
        devnode = udev_device_get_devnode (device);
        if (!action || !devnode) {
            // FIBO_LOG_DEBUG("get udev, but action or devnode failed!\n");
            udev_device_unref(device);
            continue;
        }

        if (0 == strcmp(action, "add"))
        {
            ret = fibo_adapter_check_cellular(&res);
            if (ret != RET_OK || res != RET_OK)
            {
                FIBO_LOG_CRITICAL("Helper cant recognize cellular!\n");
                udev_device_unref(device);
                continue;
            }

            fibo_adapter_control_mbim_init();
        }
        else if (0 == strcmp(action, "remove"))
        {
            // if core func still can found modem, remove will be failed.
            ret = fibo_adapter_check_cellular(&res);
            if (ret != RET_OK || res != RET_ERROR)
            {
                FIBO_LOG_DEBUG("cellular seems not removed!\n");
                udev_device_unref(device);
                continue;
            }
            fibo_adapter_get_work_cellular_info(&work_cellular_info);

            FIBO_LOG_CRITICAL("Found cellular %s removed!\n", work_cellular_info.work_module_name);
            if (g_skeleton != NULL)
                fibocom_gdbus_helper_emit_cellular_state(g_skeleton, "[ModemState]cellular missing!");
            else
                FIBO_LOG_CRITICAL("variable is NULL, dont send cellular info signal!\n");

            fibo_adapter_send_control_message_to_mbim(CTL_MBIM_DEINIT, 0, NULL);
            udev_device_unref(device);
        }
        else
        {
            FIBO_LOG_DEBUG("dont know what accured on module: action: %s\n", action);
        }
    }

   fibo_udev_deinit (&udev, &monitor);
}

gboolean
fibo_adapter_check_module_info_table(void)
{
    gint     table_len      =  RET_ERROR;
    gint     i              =  RET_ERROR;
    gboolean check_flag     =  TRUE;

    table_len = sizeof(module_info_table) / sizeof(Fibocom_module_info_type);
    for (i = 0; i < table_len; i++) {
        if (module_info_table[i].module_name == NULL)
            check_flag = FALSE;
        break;
        if (module_info_table[i].module_type >= CELLULAR_TYPE_MAX)
            check_flag = FALSE;
        break;
        if (module_info_table[i].usbsubsysid == NULL)
            check_flag = FALSE;
        break;
        if (module_info_table[i].module_type == CELLULAR_TYPE_PCIE && (module_info_table[i].pciessvid == NULL || module_info_table[i].pciessdid == NULL))
            check_flag = FALSE;
        break;
        if (module_info_table[i].module_type == CELLULAR_TYPE_USB && (module_info_table[i].pciessvid != NULL || module_info_table[i].pciessdid != NULL))
            check_flag = FALSE;
        break;
        if (module_info_table[i].mbimportname == NULL)
            check_flag = FALSE;
        break;

        /* dont check download and AT port cause several module dont exist dlport or support AT over GNSS feature. */
        /*
        if (module_info_table[i].dlportname == NULL)
            check_flag = FALSE;
        break;

        if (module_info_table[i].atportname == NULL)
            check_flag = FALSE;
        break;
        */
    }

    return check_flag;
}

gint
fibo_adapter_get_normal_req_from_dbus(void *msgs)
{
    int     input_seq_id = RET_ERROR;
    int     ret           = RET_OK;

    input_seq_id  = fibo_adapter_get_helper_seq_id(SEQ_INPUT);

    ret = msgrcv(input_seq_id, (void *)msgs, 2048, MSG_NORMAL, 0);  // try get first normal message on message seq(input pipe).
    if (ret == RET_ERROR) {
        // FIBO_LOG_DEBUG("ret: %d\n", ret);
        return RET_ERROR;
    }
    return RET_OK;

}

gint
fibo_adapter_get_any_req_from_dbus(void *msgs)
{
    int     input_seq_id = RET_ERROR;
    int     ret           = RET_OK;

    input_seq_id  = fibo_adapter_get_helper_seq_id(SEQ_INPUT);

    ret = msgrcv(input_seq_id, (void *)msgs, 2048, MSG_ALL, 0);  // try get first any kinds of message on message seq(input pipe).
    if (ret == RET_ERROR)
        return RET_ERROR;
    return RET_OK;
}

gint
fibo_adapter_get_control_req_from_dbus(void *msgs)
{
    int     input_seq_id = RET_ERROR;
    int     ret           = RET_OK;

    input_seq_id  = fibo_adapter_get_helper_seq_id(SEQ_INPUT);

    ret = msgrcv(input_seq_id, (void *)msgs, 2048, MSG_CONTROL, 0);  // try get first control message on message seq(input pipe).
    if (ret == RET_ERROR)
        return RET_ERROR;
    return RET_OK;
}

gint
fibo_adapter_send_resp_to_dbus(void *msgs, int msgsize)
{
    int     output_seq_id;
    int     ret = RET_OK;

    if (!msgs || msgsize < 0) {
        FIBO_LOG_CRITICAL("NULL pointer!");
        return RET_ERROR;
    }

    output_seq_id  = fibo_adapter_get_helper_seq_id(SEQ_OUTPUT);

    ret = msgsnd(output_seq_id, (void *)msgs, msgsize, 0);
    if (ret != RET_OK) {
        FIBO_LOG_CRITICAL("ret = %d\n", ret);
        return RET_ERROR;
    }
    return RET_OK;

}

gint
fibo_adapter_get_control_req_from_mbim(void *msgs)
{
    int     output_seq_id = RET_ERROR;
    int     ret           = RET_OK;

    output_seq_id  = fibo_adapter_get_helper_seq_id(SEQ_OUTPUT);

    ret = msgrcv(output_seq_id, (void *)msgs, 2048, MSG_CONTROL, 0);  // try get first control message on message seq(output pipe).

    if (ret == RET_ERROR)
        return RET_ERROR;

    return RET_OK;
}

gint
fibo_adapter_get_normal_resp_from_mbim(void *msgs)
{
    int     output_seq_id = RET_ERROR;
    int     ret           = RET_OK;

    output_seq_id  = fibo_adapter_get_helper_seq_id(SEQ_OUTPUT);

    ret = msgrcv(output_seq_id, (void *)msgs, 2048, MSG_NORMAL, 0);  // try get first normal message on message seq(output pipe).
    FIBO_LOG_DEBUG("ret:%d, errno:%s\n", ret, strerror(errno));

    while(ret == RET_ERROR && errno == 4) {  // 4: INTERRUPTED SYSTEM CALL, signal's callback influence msgrcv func!
        FIBO_LOG_DEBUG("system call error, give another chance to get!\n");
        ret = msgrcv(output_seq_id, (void *)msgs, 2048, MSG_NORMAL, 0);  // try get first normal message on message seq(output pipe).
    }

    if (ret == RET_ERROR)
        return RET_ERROR;

    // helper_main_analyzer_timer_close();

    return RET_OK;
}

gint
fibo_adapter_send_control_req_to_mbim(void *msgs, int msgsize)
{
    int     input_seq_id     = RET_ERROR;
    int     ret              = RET_OK;
    GThread *recovery_thread = NULL;

    if (!msgs || msgsize < 0) {
        FIBO_LOG_CRITICAL("NULL pointer!\n");
        return RET_ERROR;
    }

    input_seq_id  = fibo_adapter_get_helper_seq_id(SEQ_INPUT);

    ret = msgsnd(input_seq_id, (void *)msgs, msgsize, 0);
    if (ret != RET_OK)
        return RET_ERROR;

    return RET_OK;
}

gint
fibo_adapter_send_req_to_mbim(void *msgs, int msgsize)
{
    int ret = RET_ERROR;

    ret = fibo_adapter_send_control_req_to_mbim(msgs, msgsize);
    if (ret != RET_OK)
        return RET_ERROR;

    // helper_main_analyzer_timer_handle();

    return RET_OK;
}

gint
fibo_adapter_get_helper_seq_id(int seq)
{
    int ipc_key = ftok("/etc/dbus-1/system.d/com.fibocom.helper.conf", seq);  // calculate individual message id.
    int seqid   = RET_ERROR;

    if (ipc_key == RET_ERROR)
    {
        FIBO_LOG_CRITICAL("can't alloc key!\n");
        return RET_ERROR;
    }
    else
    {
        seqid = msgget(ipc_key, 0);
        if (seqid == RET_ERROR)
        {
            // FIBO_LOG_DEBUG("seq not existed!\n");
            return RET_ERROR;
        }
    }
    return seqid;
}

int
fibo_adapter_helper_sequence_init(void)
{
    key_t ipc_key;
    int   ret = RET_ERROR;

    for (int i = 0; i < 2; i++)
    {
        ipc_key = ftok("/etc/dbus-1/system.d/com.fibocom.helper.conf", i);  // calculate individual message id.
        if (ipc_key == RET_ERROR)
        {
            FIBO_LOG_CRITICAL("can't alloc sequence id!\n");
            return RET_ERROR;
        }

        ret = msgget(ipc_key, 0666|IPC_EXCL|IPC_CREAT);  // Create new seq, if existed, will return error.
        if (RET_ERROR == ret)
        {
            FIBO_LOG_DEBUG("seq already existed!\n");
            return RET_OK;
        }
    }

    FIBO_LOG_DEBUG("finished!\n");
    return RET_OK;
}

/*--------------------------------------Above are External Funcs-------------------------------------------------------*/

