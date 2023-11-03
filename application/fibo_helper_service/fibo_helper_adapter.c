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
 * @file fibo_helper_adapter.c
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
fibocom_cellular_type g_cellular_info                = {CELLULAR_STATE_UNKNOWN, CELLULAR_TYPE_UNKNOWN, "ERROR", -1};
async_user_data_type  user_data                      = {0, 0, NULL, NULL};

extern FibocomGdbusHelper *g_skeleton;
extern gint               g_current_svcid;
extern gint               g_current_cid;

#define REQUEST_MAX_RETRY                2
#define DEFAULT_CELLULAR_TYPE            "usb"
#define PCIE_GREP_MODULE_CMD_LEN         0
#define USB_GREP_MODULE_CMD_LEN          23  // max size like "lsusb | grep 2cb7:01a2"
#define GREP_MBIM_PORT_CMD_LEN           30  // max size like "find /dev -name wwan0mbim0*" // should be 28.
#define MODULE_ID_CHECK_CMD_LEN          (USB_GREP_MODULE_CMD_LEN >= PCIE_GREP_MODULE_CMD_LEN ? USB_GREP_MODULE_CMD_LEN : PCIE_GREP_MODULE_CMD_LEN)
#define MM_PORT_MBIM_SIGNAL_NOTIFICATION "notification"
#define RDONLY                           "r"
#define WRONLY                           "w"
#define TIMEOUT_INFINITE                 -1
#define FIBOCOM_MBIM_SERVICE             24  // on libmbim code, fibocom uuid enum value must be 24!

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
static void
quit_cb (gint user_data)
{
    gint output_seq_id = RET_ERROR;
    gint input_seq_id  = RET_ERROR;
    gchar cmd_buf[11]  = {0};

    input_seq_id  = fibo_adapter_get_helper_seq_id(SEQ_INPUT);
    output_seq_id = fibo_adapter_get_helper_seq_id(SEQ_OUTPUT);

    // fibo_adapter_helperd_send_control_message_to_helperm(CTL_MBIM_END, 0, NULL);

    sprintf(cmd_buf, "ipcrm -q %d", input_seq_id);
    system(cmd_buf);

    sprintf(cmd_buf, "ipcrm -q %d", output_seq_id);
    system(cmd_buf);

    if (gMainLoop) {
        FIBO_LOG_ERROR ("Caught signal, stopping main loop...\n");
        g_main_loop_quit(gMainLoop);
    }

    return;
}

gboolean g_sim_inserted_flag = FALSE;

static void
fibo_basic_connect_notification_subscriber_ready_status (MbimDevice           *device,
                                                    MbimMessage          *notification)
{
    MbimSubscriberReadyState ready_state       = MBIM_SUBSCRIBER_READY_STATE_FAILURE;
    g_autoptr(GError)        error             = NULL;

    if (mbim_device_check_ms_mbimex_version (device, 3, 0)) {
        if (!mbim_message_ms_basic_connect_v3_subscriber_ready_status_notification_parse (
                notification,
                &ready_state,
                NULL, /* flags */
                NULL, /* subscriber id */
                NULL, /* sim_iccid */
                NULL, /* ready_info */
                NULL, /* telephone_numbers_count */
                NULL, /* telephone number */
                &error)) {
            FIBO_LOG_ERROR ("Failed processing MBIMEx v3.0 subscriber ready status notification: %s", error->message);
            return;
        }
        FIBO_LOG_DEBUG("processed MBIMEx v3.0 subscriber ready status notification\n");
    } else {
        if (!mbim_message_subscriber_ready_status_notification_parse (
                notification,
                &ready_state,
                NULL, /* subscriber_id */
                NULL, /* sim_iccid */
                NULL, /* ready_info */
                NULL, /* telephone_numbers_count */
                NULL, /* telephone number */
                &error)) {
            FIBO_LOG_ERROR ("Failed processing subscriber ready status notification: %s", error->message);
            return;
        }
        FIBO_LOG_DEBUG ("processed subscriber ready status notification");
    }

    FIBO_LOG_DEBUG("ready state:%d\n", ready_state);

    switch (ready_state) {
        case MBIM_SUBSCRIBER_READY_STATE_NO_ESIM_PROFILE:
            FIBO_LOG_ERROR("Not support ESIM yet!\n");
            break;
        case MBIM_SUBSCRIBER_READY_STATE_DEVICE_LOCKED:
            FIBO_LOG_DEBUG("Duplicated ind, SIM card is locked!\n");
            break;
        case MBIM_SUBSCRIBER_READY_STATE_INITIALIZED:
            if (g_sim_inserted_flag) {
                FIBO_LOG_DEBUG("SIM card was inserted before, abort to send signal!\n");
                break;
            }
            g_sim_inserted_flag = TRUE;
            fibo_adapter_helperm_send_control_message_to_helperd(CTL_MBIM_SUBSCRIBER_READY_IND, strlen("SIM inserted"), "SIM inserted");

            // HOME PROVIDER not support indication, so here have to manually query.
            fibo_adapter_helperd_send_control_message_to_helperm(CTL_MBIM_HOME_PROVIDER_QUERY, 0, NULL);
            break;
        case MBIM_SUBSCRIBER_READY_STATE_NOT_INITIALIZED:
            FIBO_LOG_ERROR("SIM card is initializing!\n");
            if (g_sim_inserted_flag) {
                FIBO_LOG_DEBUG("SIM card was inserted before, abort to send signal!\n");
                break;
            }
            g_sim_inserted_flag = TRUE;
            fibo_adapter_helperm_send_control_message_to_helperd(CTL_MBIM_SUBSCRIBER_READY_IND, strlen("SIM inserted"), "SIM inserted");
            break;
        case MBIM_SUBSCRIBER_READY_STATE_FAILURE:
            FIBO_LOG_DEBUG("Failure on SIM card state! treat it as SIM card removed!\n");
        case MBIM_SUBSCRIBER_READY_STATE_SIM_NOT_INSERTED:
            if (!g_sim_inserted_flag) {
                FIBO_LOG_DEBUG("SIM card not inserted at all, abort to send signal!\n");
                break;
            }
            g_sim_inserted_flag = FALSE;
            fibo_adapter_helperm_send_control_message_to_helperd(CTL_MBIM_SUBSCRIBER_READY_IND, strlen("SIM removed"), "SIM removed");
            break;
        default:
            FIBO_LOG_ERROR("Unsupported SIM card ready state: %d!\n", ready_state);
    }
    return;
}

static void
basic_connect_notification_register_state (MbimDevice           *device,
                                                    MbimMessage          *notification)
{
    MbimRegisterState  register_state = MBIM_REGISTER_STATE_UNKNOWN;
    g_autofree gchar   *provider_id   = NULL;
    g_autoptr(GError)  error          = NULL;

    if (mbim_device_check_ms_mbimex_version (device, 2, 0)) {
            if (!mbim_message_ms_basic_connect_v2_register_state_notification_parse (
                    notification,
                    NULL, /* nw error */
                    &register_state,
                    NULL, /* register_mode */
                    NULL, /* available_data_classses */
                    NULL, /* current_cellular_class */
                    &provider_id,
                    NULL, /* provider_name */
                    NULL, /* roaming_text */
                    NULL, /* registration_flag */
                    NULL, /* preferred_data_classes */
                    &error)) {
                FIBO_LOG_ERROR("Failed processing MBIMEx v2.0 register state indication\n");
                return;
            }
    } else {
            if (!mbim_message_register_state_notification_parse (
                    notification,
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
                FIBO_LOG_ERROR("Failed processing register state indication\n");
                return;
            }
    }

    if (provider_id) {
        FIBO_LOG_DEBUG("provider id: %s\n", provider_id);
        fibo_adapter_helperm_send_control_message_to_helperd(CTL_MBIM_REGISTER_STATE_IND, strlen(provider_id), provider_id);
    } else {
        FIBO_LOG_DEBUG("register state: %s\n", mbim_register_state_get_string (register_state));
        FIBO_LOG_DEBUG("don't get valid roam mccmnc!\n");
    }

    return;
}

static void
fibo_adapter_mbim_bc_ind_parse(MbimDevice   *Device, MbimMessage   *notification)
{
    guint        cid         = RET_OK;

    cid = mbim_message_indicate_status_get_cid (notification);
    switch (cid) {
    case MBIM_CID_BASIC_CONNECT_REGISTER_STATE:
            basic_connect_notification_register_state (Device, notification);
        break;
    case MBIM_CID_BASIC_CONNECT_SUBSCRIBER_READY_STATUS:
            fibo_basic_connect_notification_subscriber_ready_status (Device, notification);
        break;
    default:
        // FIBO_LOG_DEBUG("Unsupported cid: %d\n", cid);
    }
    return;
}

static void
fibo_adapter_mbim_bcext_ind_parse(MbimDevice   *Device, MbimMessage   *notification)
{
    guint        cid         = RET_OK;

    cid = mbim_message_indicate_status_get_cid (notification);
    switch (cid) {
        case MBIM_CID_MS_BASIC_CONNECT_EXTENSIONS_SLOT_INFO_STATUS:
            FIBO_LOG_DEBUG("Noted SLOT_INFO_STATUS cid for debug!\n");
            // ms_basic_connect_extensions_notification_slot_info_status (Device, notification);
            break;
        default:
            // FIBO_LOG_DEBUG("Unsupported cid: %d\n", cid);
    }

    return;
}

static gint
fibo_port_notification_cb (MbimDevice   *Device,
                      MbimMessage  *notification,
                      gpointer     userdata)
{
    guint        cid         = RET_OK;
    MbimService  service     = RET_OK;

    FIBO_LOG_DEBUG("enter!\n");

    service = mbim_message_indicate_status_get_service (notification);
    cid     = mbim_message_indicate_status_get_cid (notification);

    switch (service) {
        case MBIM_SERVICE_BASIC_CONNECT:
            fibo_adapter_mbim_bc_ind_parse(Device, notification);
        break;
        case MBIM_SERVICE_MS_BASIC_CONNECT_EXTENSIONS:
            fibo_adapter_mbim_bcext_ind_parse(Device, notification);
        break;
        default:
            FIBO_LOG_DEBUG("get unsupported mbim indication! service is %d, cid is %d\n", service, cid);
    }

    // here can't return 0 cause it will block ModemManager or other APP's indication func!
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
        return;
    }

    FIBO_LOG_DEBUG ("MBIM Device at '%s' ready\n",
             mbim_device_get_path_display (dev));

    fibo_adapter_mutex_mbim_flag_operate_lock();
    g_mbim_device_init_flag = TRUE;
    fibo_adapter_mutex_mbim_flag_operate_unlock();

    FIBO_LOG_DEBUG("mbim port init finished! flag:%d\n", g_mbim_device_init_flag);

    // further: add func to receive and deal with specific mbim indication message.
    g_signal_connect (mbimdevice,
                      MBIM_DEVICE_SIGNAL_INDICATE_STATUS,
                      G_CALLBACK (fibo_port_notification_cb),
                      NULL);

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
        FIBO_LOG_ERROR("NULL pointer, seems already deinit!\n");
        return RET_OK;
    }

    udev_monitor_unref(*monitor_addr);
    *monitor_addr = NULL;

    udev_unref(*udev_addr);
    *udev_addr = NULL;

    return RET_OK;
}


// this func should only be called by timeout callback!
static gint
fibo_adapter_timer_get_any_req_from_helperd(void *msgs)
{
    gint     input_seq_id = RET_ERROR;
    gint     ret           = RET_OK;

    input_seq_id  = fibo_adapter_get_helper_seq_id(HELPERM_INPUT);

    ret = msgrcv(input_seq_id, (void *)msgs, 2048, MSG_ALL, IPC_NOWAIT);  // try get first any kinds of message on message seq(input pipe).
    if (ret == RET_ERROR || ret == ENOMSG)
        return RET_ERROR;
    return RET_OK;
}

static void
restore_main_signal_work(gint signum)
{
    helper_message_struct  *msgs          = NULL;
    gint                   ret            = RET_ERROR;
    fibo_async_struct_type *user_data     = NULL;
    gint                   cid            = RET_ERROR;
    gint                   service_id     = RET_ERROR;

    FIBO_LOG_ERROR("fibo-helperm no resp!\n");

    msgs = (helper_message_struct *)malloc(2048 * sizeof(char));
    if (msgs == NULL)
    {
        FIBO_LOG_ERROR("malloc failed!");
        return;
    }
    memset(msgs, 0, 2048 * sizeof(char));

    // if alarm timeout, means there likely be a message on input pipe.
    ret = fibo_adapter_timer_get_any_req_from_helperd(msgs);
    if (ret == RET_OK) {
        user_data = (fibo_async_struct_type *)msgs->mtext;
        cid = user_data->cid;
        service_id = user_data->serviceid;
    } else {
        cid = g_current_cid;
        service_id = g_current_svcid;
    }

    fibo_adapter_alloc_and_send_resp_structure(service_id, cid, RET_ERR_PROCESS, 0, NULL);

    user_data = NULL;
    free(msgs);
    msgs = NULL;

    FIBO_LOG_DEBUG("finished!\n");

    // noted below code cause we don't expect mbim's crash influence dbus.
    /*
    if (g_error_flag < 5) {
        fibo_adapter_alloc_and_send_resp_structure(HELPER, CTL_MBIM_NO_RESP, 1, 0, NULL);
        g_error_flag++;
    }
    else
        fibo_adapter_helperm_send_control_message_to_helperd(CTL_MBIM_NO_RESP, 0, NULL);
    FIBO_LOG_DEBUG("flag times:%d", g_error_flag);
    */

    return;
}

static gint
fibo_adapter_helperm_get_work_module_name(gchar *atport)
{
    gint                     ret                                  =  RET_ERROR;
    gint                     res                                  =  RET_ERROR;
    fibocom_cellular_type    work_cellular_info;
    Fibocom_module_info_type module_info;
    gchar                    command[GREP_MBIM_PORT_CMD_LEN + 9]  =  {0};  // add extra "find /dev"
    FILE                     *fp                                  =  NULL;
    gchar                    commandrsp[GREP_MBIM_PORT_CMD_LEN]   =  {0};

    memset(&work_cellular_info, 0, sizeof(fibocom_cellular_type));
    memset(&module_info,        0, sizeof(Fibocom_module_info_type));

    if (!atport || strlen(atport) != 0) {
        FIBO_LOG_ERROR("NULL pointer!\n");
        return RET_ERROR;
    }

    // below commands are used to dynamically get current cellular's atportname.
    ret = fibo_adapter_check_cellular(&res);
    if (ret != RET_OK || res != RET_OK)
    {
        FIBO_LOG_ERROR("Helper can't recognize cellular!\n");
        return RET_ERR_RESOURCE;
    }

    fibo_adapter_get_work_cellular_info(&work_cellular_info);

    FIBO_LOG_ERROR("Found %s exist!\n", work_cellular_info.work_module_name);

    fibo_adapter_get_supported_module_info(&module_info, work_cellular_info.module_info_index);

    FIBO_LOG_DEBUG("device AT port:%s\n", module_info.atportname);

    if (module_info.atportname == NULL || strlen(module_info.atportname) < 1) {
        FIBO_LOG_ERROR("Invalid atport name, don't init!\n");
        return RET_ERR_RESOURCE;
    }

    sprintf(command, "find /dev -name %s*", module_info.atportname);

    // execute command.
    fp = popen(command, RDONLY);
    if (fp == NULL) {
        FIBO_LOG_ERROR("execute command failed!\n");
        return RET_ERROR;
    }

    // get command's resp.
    while(fgets(commandrsp, GREP_MBIM_PORT_CMD_LEN, fp) != NULL);

    // check command's execute result.
    ret = pclose(fp);
    if (ret != RET_OK || strlen(commandrsp) == 0) {
        FIBO_LOG_ERROR("can't find atport!\n");
        return RET_ERROR;
    }

//    for (gint i = 0; i <strlen(commandrsp); i++) {
//        FIBO_LOG_DEBUG("at cmd return:%d\n", commandrsp[i]);
//    }

    // portname will begin with /dev/ttyUSB*, skip "/dev/", 5 offset.
    // commandrsp will end with 0x0A, cause string contains invalid symbol, so here will more cut 1.
    strncpy(atport, commandrsp + 5, (gint)strlen(commandrsp) - 6);
    return RET_OK;
}

static gint
fibo_adapter_send_at_over_mbim_message(void           *message,
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

    if (!message || !len || !timeout || !callback || !userdata) {
        FIBO_LOG_ERROR("NULL pointer!\n");
        return RET_ERROR;
    }

    FIBO_LOG_DEBUG("MBIM FLAG:%d\n", g_mbim_device_init_flag);

    while (!g_mbim_device_init_flag && retry >= 0) {
        FIBO_LOG_DEBUG("mbim device not ready! wait for 1s!\n");
        g_usleep(1000 * 1000 * 1);
        retry--;
    }

    if (retry < 0) {
        FIBO_LOG_ERROR("Reach max retry, mbim device not ready!\n");
        return RET_ERR_RESOURCE;
    }

    req_size = strlen(message);

    malloc_size = (req_size > len ? req_size : len);
    malloc_size = malloc_size + 2;

    req_str = malloc(malloc_size);
    if (!req_str) {
        FIBO_LOG_ERROR("malloc space failed!\n");
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

    if (req_str) {
        free(req_str);
        req_str = NULL;
    }

    return RET_OK;

#else

    FIBO_LOG_ERROR("Not support MBIM yet!\n");

    if (req_str) {
        free(req_str);
        req_str = NULL;
    }

    return RET_ERROR;
#endif
}

static gint
fibo_adapter_send_at_over_gnss_message(void                   *message,
                                guint32                len,
                                GAsyncReadyCallback    callback,
                                gpointer               userdata)
{
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
    gint                     res                                  =  RET_ERROR;

    gchar                    command[GREP_MBIM_PORT_CMD_LEN + 9]  =  {0};  // add extra "find /dev"
    FILE                     *fp                                  =  NULL;
    gchar                    commandrsp[GREP_MBIM_PORT_CMD_LEN]   =  {0};
    gchar                    atport[GREP_MBIM_PORT_CMD_LEN]       =  {0};

    if (!message || !len || !callback || !userdata) {
        FIBO_LOG_ERROR("NULL pointer!\n");
        return RET_ERROR;
    }

    memset(&work_cellular_info, 0, sizeof(fibocom_cellular_type));
    memset(&module_info,        0, sizeof(Fibocom_module_info_type));

    user_data = (fibo_async_struct_type *)userdata;
    cid = user_data->cid;
    service_id = user_data->serviceid;

    ret = fibo_adapter_helperm_get_work_module_name(atport);
    if (ret != RET_OK) {
        FIBO_LOG_ERROR("can't get atport name!\n");
        return RET_ERROR;
    }

    FIBO_LOG_DEBUG("portname:%s\n", atport);

    req_size    = strlen(message);
    malloc_size = (req_size > len ? req_size : len);
    // add more 2 bytes to paste with "\r\n".
    malloc_size = malloc_size + 2;

    req_str = malloc(malloc_size);
    if (!req_str) {
        FIBO_LOG_ERROR("malloc space failed!\n");
        return RET_ERR_RESOURCE;
    }
    memset(req_str, 0, malloc_size);

    strcpy((char *)req_str, message);
    strcat((char *)req_str, "\r\n");

    rcv_data = malloc(2048);
    if (!rcv_data) {
        FIBO_LOG_ERROR("malloc space failed!\n");
        if (userdata) {
            free(userdata);
            userdata = NULL;
        }
        return RET_ERR_RESOURCE;
    }
    memset(rcv_data, 0, 2048);

    // send AT command to module.
    ret = fibo_adapter_send_at_command(req_str, rcv_data, atport);
    if (ret != RET_OK) {
        FIBO_LOG_ERROR("Send command failed, error:%d\n", ret);
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

    if (req_str) {
        free(req_str);
        req_str = NULL;
    }

    if (cid != FLASH_FW_FASTBOOT && cid != FLASH_FW_EDL) {
        // only flash-related 2 funcs will keep original payload, otherwise here will drop previous user_data and full it with new AT's resp.
        if (user_data) {
            free(user_data);
            user_data = NULL;
        }

        user_data = (fibo_async_struct_type *) malloc(sizeof(fibo_async_struct_type) + payloadlen + 1);
        if (user_data == NULL) {
            FIBO_LOG_ERROR("malloc failed!\n");
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

    return RET_OK;
}
/*--------------------------------------Above are Internal Funcs-------------------------------------------------------*/

/*--------------------------------------Below are External Funcs-------------------------------------------------------*/

void
fibo_adapter_trigger_app_exit(void) {
    quit_cb(0);
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

    msgs = (helper_message_struct *)malloc(2048 * sizeof(char));
    if (msgs == NULL)
    {
        FIBO_LOG_ERROR("malloc failed!\n");
        free(user_data);
        user_data = NULL;
        return RET_ERROR;
    }
    memset(msgs, 0, 2048);

    memcpy(msgs->mtext, user_data, sizeof(fibo_async_struct_type) + payloadlen);
    msgs->mtype = MSG_NORMAL;

    ret = fibo_adapter_helperm_send_msg_to_helperd(msgs, 2048);
    if (ret != RET_OK) {

        FIBO_LOG_ERROR("Send message failed!\n");
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

// mbim_flag_operate mutex will be used to keep all params on function's callback can be used normally.
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

gint
fibo_adapter_all_mutex_init()
{
    gint ret = RET_ERROR;

    ret =  pthread_mutex_init(&mutex_force_sync, NULL);
    ret |= pthread_mutex_init(&mutex_cellular_info_operate, NULL);
    ret |= pthread_mutex_init(&mutex_keep_pointer_exist, NULL);
    ret |= pthread_mutex_init(&mutex_mbim_flag_operate, NULL);
    ret |= pthread_mutex_init(&mutex_sim_insert_flag_operate, NULL);
    // ret |= pthread_mutex_init(&mutex_mbim_fail_flag_operate, NULL);

    if (ret != RET_OK) {
        FIBO_LOG_ERROR("init mutex failed!\n");
        return ret;
    }
    return RET_OK;
}

gint
fibo_adapter_helperm_send_control_message_to_helperd(gint cid, gint payloadlen, char *payload_str)
{
    helper_message_struct               *msgs          = NULL;
    fibo_async_struct_type              *user_data     = NULL;
    gint                                ret            = RET_ERROR;

    FIBO_LOG_DEBUG("enter, len:%d\n", payloadlen);

    user_data = (fibo_async_struct_type *)malloc(sizeof(fibo_async_struct_type) + payloadlen + 1);
    if (user_data == NULL) {
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

    user_data->serviceid   = HELPER;
    user_data->cid         = cid;
    user_data->rtcode      = 0;

    msgs = (helper_message_struct *)malloc(2048 * sizeof(char));
    if (msgs == NULL) {
        FIBO_LOG_ERROR("malloc failed!\n");
        free(user_data);
        user_data = NULL;
        return RET_ERROR;
    }
    memset(msgs, 0, 2048);

    memcpy(msgs->mtext, user_data, sizeof(fibo_async_struct_type) + payloadlen);
    msgs->mtype = MSG_CONTROL;

    ret = fibo_adapter_helperm_send_msg_to_helperd(msgs, 2048);
    free(user_data);
    user_data = NULL;
    free(msgs);
    msgs = NULL;

    if (ret != RET_OK) {
        FIBO_LOG_ERROR("Send message failed!\n");
        return RET_ERROR;
    }

    return RET_OK;
}

gint
fibo_adapter_helperd_send_control_message_to_helperm(gint cid, gint payloadlen, char *payload_str)
{
    helper_message_struct               *msgs          = NULL;
    fibo_async_struct_type              *user_data     = NULL;
    gint                                ret            = RET_ERROR;

    FIBO_LOG_DEBUG("enter, len:%d\n", payloadlen);

    if (payloadlen > 2048) {
        FIBO_LOG_ERROR("Reach max size!\n");
        return RET_ERROR;
    }

    user_data = (fibo_async_struct_type *)malloc(sizeof(fibo_async_struct_type) + payloadlen + 1);
    if (user_data == NULL) {
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

    user_data->serviceid   = HELPER;
    user_data->cid         = cid;
    user_data->rtcode      = 0;

    msgs = (helper_message_struct *)malloc(2048 * sizeof(char));
    if (msgs == NULL) {
        FIBO_LOG_ERROR("malloc failed!\n");
        free(user_data);
        user_data = NULL;
        return RET_ERROR;
    }
    memset(msgs, 0, 2048);

    memcpy(msgs->mtext, user_data, sizeof(fibo_async_struct_type) + payloadlen + 1);
    msgs->mtype = MSG_CONTROL;

    ret = fibo_adapter_helperd_send_req_to_helperm(msgs, 2048);
    if (ret != RET_OK) {
        FIBO_LOG_ERROR("Send message failed!\n");
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

void
fibo_adapter_helperd_send_resp_to_dbus(FibocomGdbusHelper     *skeleton,
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

gint
fibo_adapter_get_supported_module_number(void)
{
    return sizeof(module_info_table) / sizeof(Fibocom_module_info_type);
}

gint
fibo_adapter_get_supported_module_info(Fibocom_module_info_type *module_info, gint index)
{
    memcpy(module_info, &module_info_table[index], sizeof(Fibocom_module_info_type));
    return RET_OK;
}

gint
fibo_adapter_get_work_cellular_info(fibocom_cellular_type *work_cellular_info)
{
    fibo_adapter_mutex_cellular_info_operate_lock();

    memcpy(work_cellular_info, &g_cellular_info, sizeof(fibocom_cellular_type));

    fibo_adapter_mutex_cellular_info_operate_unlock();

    return RET_OK;
}

gint
fibo_adapter_set_work_cellular_info(fibocom_cellular_type *work_cellular_info)
{
    fibo_adapter_mutex_cellular_info_operate_lock();

    memcpy(&g_cellular_info, work_cellular_info, sizeof(fibocom_cellular_type));

    fibo_adapter_mutex_cellular_info_operate_unlock();

    return RET_OK;
}

gint
fibo_adapter_set_linux_app_signals()
{
    signal(SIGINT,  quit_cb);
    signal(SIGHUP,  quit_cb);
    signal(SIGTERM, quit_cb);

    return RET_OK;
}

gint
fibo_adapter_send_message_async(void                   *message,
                                guint32                len,
                                guint32                timeout,
                                GAsyncReadyCallback    callback,
                                gpointer               userdata)
{
    gint     ret           = RET_ERROR;
    MbimUuid *uuid_pointer = NULL;

#ifdef MBIM_FUNCTION_SUPPORTED
    uuid_pointer = (MbimUuid *)mbim_uuid_from_service(FIBOCOM_MBIM_SERVICE);
    if (uuid_pointer && uuid_pointer->a[0] != 0x0) {
        ret = fibo_adapter_send_at_over_mbim_message(message, len, timeout, callback, userdata);
    }
    else {
        FIBO_LOG_DEBUG("Seems libmbim not support FBC uuid yet!\n");
        ret = fibo_adapter_send_at_over_gnss_message(message, len, callback, userdata);
    }
#else
    FIBO_LOG_DEBUG("Force to use AT over GNSS!\n");
    ret = fibo_adapter_send_at_over_gnss_message(message, len, callback, userdata);

#endif

    if (ret != RET_OK) {
        FIBO_LOG_ERROR("send message failed!\n");
        return RET_ERROR;
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
    gint ret            = RET_ERROR;

    if (g_udev_init_flag) {
        FIBO_LOG_DEBUG("udev already initialized!\n");
        return RET_ERROR;
    }

    if (cellular_type > CELLULAR_TYPE_MAX || cellular_type < CELLULAR_TYPE_MIN) {
        FIBO_LOG_ERROR("Invalid param, refuse to init!\n");
        return RET_ERROR;
    }

    udev = udev_new();
    if(!udev) {
        FIBO_LOG_ERROR("Failed to initialize libudev.\n");
        return RET_ERROR;
    }

    monitor = udev_monitor_new_from_netlink(udev, "udev");
    if (!monitor) {
        FIBO_LOG_ERROR("Failed to create udev monitor.\n");
        udev_unref(udev);
        return RET_ERROR;
    }
/*
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
    }
*/

    /* Monitor all device's change, should be inserted and removed */
    ret = udev_monitor_filter_add_match_subsystem_devtype(monitor, "pcie", NULL);
    if (ret < RET_OK) {
        FIBO_LOG_ERROR("Monitor filter pcie failed!\n");
        return RET_ERROR;
    }
    ret = udev_monitor_filter_add_match_subsystem_devtype(monitor, "usb", NULL);
    if (ret < RET_OK) {
        FIBO_LOG_ERROR("Monitor filter usb failed!\n");
        return RET_ERROR;
    }

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
        FIBO_LOG_ERROR("NULL pointer!\n");
        return RET_ERROR;
    }

    *check_result = RET_ERROR;
    memset(&cellular_info, 0, sizeof(fibocom_cellular_type));

    command_rsp = malloc(AT_COMMAND_LEN * sizeof(char));
    if (!command_rsp) {
        FIBO_LOG_ERROR("malloc command_rsp failed!\n");
        return RET_ERROR;
    }
    memset(command_rsp, 0, AT_COMMAND_LEN * sizeof(char));

    module_info = malloc(sizeof(Fibocom_module_info_type));
    if (!module_info) {
        FIBO_LOG_ERROR("malloc module_info failed!\n");
        free(command_rsp);
        return RET_ERROR;
    }


    fibo_adapter_get_work_cellular_info(&cellular_info);
    max_len = fibo_adapter_get_supported_module_number();

    for (i = 0; i < max_len; i++) {
        // clear all mid-variables to default value for next use.
        fp = NULL;
        memset(module_info, 0, sizeof(Fibocom_module_info_type));
        memset(command_rsp, 0, AT_COMMAND_LEN * sizeof(char));

        ret = fibo_adapter_get_supported_module_info(module_info, i);
        if (ret != RET_OK) {
            FIBO_LOG_ERROR("fibo_get_supported_module_info failed!\n");
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
            FIBO_LOG_ERROR("execute command failed!\n");
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

            *check_result = RET_OK;
            break;
        }
    }

    free(command_rsp);
    free(module_info);

    // if func found valid cellular more than 1, will return error.
    if (matched_devices == 0) {
        *check_result = RET_ERROR;
        cellular_info.cellular_state = CELLULAR_STATE_MISSING;
        FIBO_LOG_DEBUG("don't find any supported cellular!\n");
    }

    fibo_adapter_set_work_cellular_info(&cellular_info);

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
        FIBO_LOG_ERROR("NULL pointer! refuse to init!\n");
        return;
    }
/*
    // libmbim only support 1 proxy, aka a socket which called "mbim proxy".
    // so there is no way to create a new proxy.
    proxy = mbim_proxy_new(&error);
    if (!proxy)
    {
        g_printerr("proxy new failed! error:%s\n", error->message);
        // if not root user to run, here will report privillages error.
        return;
    }
*/

    if (mbimportname == NULL || strlen(mbimportname) < 1) {
        FIBO_LOG_ERROR("Invalid mbimport name, don't init!\n");
        return;
    }

    sprintf(command, "find /dev -name %s*", mbimportname);

    // execute command.
    fp = popen(command, RDONLY);
    if (fp == NULL) {
        FIBO_LOG_ERROR("execute command failed!\n");
        return;
    }

    // get command's resp.
    while(fgets(commandrsp, GREP_MBIM_PORT_CMD_LEN, fp) != NULL);

    // check command's execute result.
    ret = pclose(fp);
    if (ret != RET_OK || strlen(commandrsp) == 0) {
        FIBO_LOG_ERROR("can't find mbimport!\n");
        return;
    }
/*
    for (gint i = 0; i <strlen(commandrsp); i++) {
        FIBO_LOG_DEBUG("mbim cmd return:%d\n", commandrsp[i]);
    }
*/
    memset(mbimport, 0, sizeof(mbimport));
    // commandrsp will end with 0x0A, cause string contains invalid symbol, so here will cut 1.
    strncpy(mbimport, commandrsp, (gint)strlen(commandrsp) - 1);
    file = g_file_new_for_path(mbimport);
    if (!file)
    {
        FIBO_LOG_ERROR("GFile new failed!\n");
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

    FIBO_LOG_ERROR("Found cellular %s added!\n", work_cellular_info.work_module_name);

    fibo_adapter_get_supported_module_info(&module_info, work_cellular_info.module_info_index);

    fibo_adapter_helperd_send_control_message_to_helperm(CTL_MBIM_INIT, strlen(module_info.mbimportname), module_info.mbimportname);
    return;
}

void
fibo_adapter_device_Check(gpointer user_data)
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
    gint                      fd                              = RET_ERROR;
    struct pollfd            ufd;
    gboolean                 *device_exist_flag               = NULL;

    if (!user_data) {
        FIBO_LOG_ERROR("NULL pointer!\n");
        return;
    }

    device_exist_flag = user_data;

    FIBO_LOG_DEBUG ("enter func.\n");

    memset(&work_cellular_info, 0, sizeof(fibocom_cellular_type));
    memset(&ufd, 0, sizeof(ufd));

    fibo_adapter_get_work_cellular_info(&work_cellular_info);

    ret = fibo_adapter_udev_init(work_cellular_info.cellular_type, &fd);
    if (ret == RET_ERROR) {
        FIBO_LOG_ERROR("Fatal error! exit main thread!\n");
        return;
    }

    ufd.fd = fd;
    ufd.events = POLLIN;

    while (TRUE)
    {
        device  = NULL;
        action  = NULL;

        memset(&work_cellular_info, 0, sizeof(fibocom_cellular_type));
        memset(&module_info,        0, sizeof(Fibocom_module_info_type));

        ret = poll(&ufd, 1, TIMEOUT_INFINITE);
        if (ret == RET_ERROR && errno != EINTR) {
            FIBO_LOG_ERROR("get udev event failed!\n");
            continue;
        }

        device = udev_monitor_receive_device (monitor);
        if (!device)
            continue;

        action  = udev_device_get_action (device);
        if (!action) {
            // FIBO_LOG_DEBUG("get udev, but action or devnode failed!\n");
            udev_device_unref(device);
            continue;
        }

        if (0 == strcmp(action, "add"))
        {
            ret = fibo_adapter_check_cellular(&res);
            if (ret != RET_OK || res != RET_OK)
            {
                FIBO_LOG_ERROR("Helper can't recognize cellular!\n");
                udev_device_unref(device);
                continue;
            }

            if (*device_exist_flag) {
                FIBO_LOG_DEBUG("device already existed!\n");
                udev_device_unref(device);
                continue;
            }

            *device_exist_flag = TRUE;

            fibo_adapter_control_mbim_init();

            if (g_skeleton != NULL) {
                sleep(2);
                fibocom_gdbus_helper_emit_cellular_state(g_skeleton, "[ModemState]cellular existed!");
            } else
                FIBO_LOG_ERROR("variable is NULL, don't send cellular info signal!\n");
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
            FIBO_LOG_ERROR("Found cellular %s removed!\n", work_cellular_info.work_module_name);

            if (!*device_exist_flag) {
                FIBO_LOG_DEBUG("device already removed or not inserted at all!\n");
                udev_device_unref(device);
                continue;
            }

            *device_exist_flag = FALSE;

            if (g_skeleton != NULL)
                fibocom_gdbus_helper_emit_cellular_state(g_skeleton, "[ModemState]cellular missing!");
            else
                FIBO_LOG_ERROR("variable is NULL, don't send cellular info signal!\n");

            fibo_adapter_helperd_send_control_message_to_helperm(CTL_MBIM_DEINIT, 0, NULL);
        }
        else
        {
            FIBO_LOG_DEBUG("don't know what accured on module: action: %s\n", action);
        }
        udev_device_unref(device);
    }
}

gint
fibo_adapter_helperm_get_normal_msg_from_helperd(void *msgs)
{
    gint     input_seq_id = RET_ERROR;
    gint     ret           = RET_OK;

    input_seq_id  = fibo_adapter_get_helper_seq_id(HELPERM_INPUT);
    if (input_seq_id == RET_ERROR) {
        FIBO_LOG_ERROR("message queue not existed!\n");
        return RET_ERROR;
    }

    ret = msgrcv(input_seq_id, (void *)msgs, 2048, MSG_NORMAL, 0);  // try get first normal message on message seq(input pipe).
    if (ret == RET_ERROR) {
        // FIBO_LOG_DEBUG("ret: %d\n", ret);
        return RET_ERROR;
    }
    return RET_OK;
}

gint
fibo_adapter_helperm_get_control_msg_from_helperd(void *msgs)
{
    gint     input_seq_id = RET_ERROR;
    gint     ret           = RET_OK;

    input_seq_id  = fibo_adapter_get_helper_seq_id(HELPERM_INPUT);
    if (input_seq_id == RET_ERROR) {
        // FIBO_LOG_ERROR("message queue not existed!\n");
        return RET_ERROR;
    }

    ret = msgrcv(input_seq_id, (void *)msgs, 2048, MSG_CONTROL, 0);  // try get first control message on message seq(input pipe).
    if (ret == RET_ERROR)
        return RET_ERROR;
    return RET_OK;
}

gint
fibo_adapter_helperm_send_msg_to_helperd(void *msgs, gint msgsize)
{
    gint     output_seq_id = RET_ERROR;
    gint     ret           = RET_OK;

    if (!msgs || msgsize < 0) {
        FIBO_LOG_ERROR("NULL pointer!");
        return RET_ERROR;
    }

    output_seq_id  = fibo_adapter_get_helper_seq_id(HELPERM_OUTPUT);
    if (output_seq_id == RET_ERROR) {
        FIBO_LOG_ERROR("message queue not existed!\n");
        return RET_ERROR;
    }

    ret = msgsnd(output_seq_id, (void *)msgs, msgsize, 0);
    if (ret != RET_OK) {
        FIBO_LOG_ERROR("ret = %d\n", ret);
        return RET_ERROR;
    }
    return RET_OK;

}

gint
fibo_adapter_helperd_get_control_msg_from_helperm(void *msgs)
{
    gint     output_seq_id = RET_ERROR;
    gint     ret           = RET_OK;

    output_seq_id  = fibo_adapter_get_helper_seq_id(HELPERD_INPUT);
    if (output_seq_id == RET_ERROR) {
        FIBO_LOG_ERROR("message queue not existed!\n");
        return RET_ERROR;
    }

    ret = msgrcv(output_seq_id, (void *)msgs, 2048, MSG_CONTROL, 0);  // try get first control message on message seq(output pipe).

    if (ret == RET_ERROR)
        return RET_ERROR;

    return RET_OK;
}

gint
fibo_adapter_helperd_get_normal_msg_from_helperm(void *msgs)
{
    gint     output_seq_id = RET_ERROR;
    gint     ret           = RET_OK;

    output_seq_id  = fibo_adapter_get_helper_seq_id(HELPERD_INPUT);
    if (output_seq_id == RET_ERROR) {
        FIBO_LOG_ERROR("message queue not existed!\n");
        return RET_ERROR;
    }

    ret = msgrcv(output_seq_id, (void *)msgs, 2048, MSG_NORMAL, 0);  // try get first normal message on message seq(output pipe).
    FIBO_LOG_DEBUG("ret:%d\n", ret);
    if (ret == RET_ERROR)
        FIBO_LOG_DEBUG("errno:%s\n", strerror(errno));

    while(ret == RET_ERROR && errno == 4) {  // 4: INTERRUPTED SYSTEM CALL, signal's callback influence msgrcv func!
        FIBO_LOG_DEBUG("system call error, give another chance to get!\n");
        ret = msgrcv(output_seq_id, (void *)msgs, 2048, MSG_NORMAL, 0);  // try get first normal message on message seq(output pipe).
    }

    if (ret == RET_ERROR)
        return RET_ERROR;

    return RET_OK;
}

gint
fibo_adapter_helperd_send_req_to_helperm(void *msgs, gint msgsize)
{
    gint     input_seq_id     = RET_ERROR;
    gint     ret              = RET_OK;

    if (!msgs || msgsize < 0) {
        FIBO_LOG_ERROR("NULL pointer!\n");
        return RET_ERROR;
    }

    input_seq_id  = fibo_adapter_get_helper_seq_id(HELPERD_OUTPUT);
    if (input_seq_id == RET_ERROR) {
        FIBO_LOG_ERROR("message queue not existed!\n");
        return RET_ERROR;
    }

    ret = msgsnd(input_seq_id, (void *)msgs, msgsize, 0);
    if (ret != RET_OK)
        return RET_ERROR;

    // helper_main_analyzer_timer_handle();

    return RET_OK;
}

gint
fibo_adapter_get_helper_seq_id(gint seq)
{
    gint ipc_key = ftok(".", seq);  // calculate individual message id.
    gint seqid   = RET_ERROR;

    if (ipc_key == RET_ERROR)
    {
        FIBO_LOG_ERROR("can't alloc key!\n");
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

gint
fibo_adapter_helper_queue_init(void)
{
    key_t ipc_key;
    gint  ret = RET_ERROR;
    gint  i   = 0;

    for (i = 0; i < 2; i++)
    {
        ipc_key = ftok(".", i);  // calculate individual message id.
        if (ipc_key == RET_ERROR)
        {
            FIBO_LOG_ERROR("can't alloc queue id!\n");
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

gint
fibo_adapter_helperd_timer_handle(void)
{
    gint ret = RET_ERROR;

    signal(SIGALRM, restore_main_signal_work);
    // set a 6s alarm cause max timeout time on AT should be common 0.6s + specially 5s.
    // if user request to download, there might be a 5s timeout to wait for fastboot port ready, so here will use default AT command timeout.
    ret = alarm(6);
    if (ret != RET_OK)
    {
        FIBO_LOG_DEBUG("alarm is used!\n");
        return RET_ERROR;
    }
    FIBO_LOG_DEBUG("alarm created!\n");
    return RET_OK;
}

gint
fibo_adapter_helperd_timer_close(void)
{
    alarm(0);
    FIBO_LOG_DEBUG("alarm closed!\n");
    // g_error_flag = 0;
    return RET_OK;
}

int g_local_mcc_retry_flag = 0;

// this callback will be executed on helperm's mainloop, so it will block mainloop less than 11s on worst scenario.
void
fibo_adapter_helperm_control_get_local_mccmnc_ready (MbimDevice   *device,
                                 GAsyncResult *res,
                                 gpointer userdata)
{
    g_autoptr(GError)                   error          =  NULL;
    g_autoptr(MbimMessage)              response       =  NULL;
    gint                                ret            =  RET_ERROR;
    MbimProvider                        *out_provider  =  NULL;

    FIBO_LOG_DEBUG("enter!\n");

    response = mbim_device_command_finish (device, res, &error);

    if (!response || !mbim_message_response_get_result (response, MBIM_MESSAGE_TYPE_COMMAND_DONE, &error)) {
        FIBO_LOG_ERROR ("error: operation failed: %s\n", error->message);

        if (g_local_mcc_retry_flag < 40) {
            g_usleep(1000 * 500);
            g_local_mcc_retry_flag++;
            FIBO_LOG_DEBUG("retry to check home provider! current times:%d\n", g_local_mcc_retry_flag);
            if (out_provider)
                mbim_provider_free(out_provider);

            fibo_adapter_helperm_get_local_mccmnc((GAsyncReadyCallback)fibo_adapter_helperm_control_get_local_mccmnc_ready, NULL);
        }
        else {
            FIBO_LOG_ERROR("reach max retry, SIM card init error!\n");
            g_local_mcc_retry_flag = 0;

            if (out_provider)
                mbim_provider_free(out_provider);
        }

        return;
    }

    if (!mbim_message_home_provider_response_parse (
            response,
            &out_provider,
            &error)) {
        FIBO_LOG_ERROR ("error: couldn't parse response message: %s\n", error->message);

        if (g_local_mcc_retry_flag < 40) {
            g_usleep(1000 * 500);
            g_local_mcc_retry_flag++;
            FIBO_LOG_DEBUG("retry to check home provider! current times:%d\n", g_local_mcc_retry_flag);
            if (out_provider)
                mbim_provider_free(out_provider);

            fibo_adapter_helperm_get_local_mccmnc((GAsyncReadyCallback)fibo_adapter_helperm_control_get_local_mccmnc_ready, NULL);
        }
        else {
            FIBO_LOG_ERROR("reach max retry, SIM card init error!\n");
            g_local_mcc_retry_flag = 0;

            if (out_provider)
                mbim_provider_free(out_provider);
        }
        return;
    }
    else {
        FIBO_LOG_DEBUG("get local mccmnc:%s\n", out_provider->provider_id);
        fibo_adapter_helperm_send_control_message_to_helperd(CTL_MBIM_HOME_PROVIDER_IND, strlen(out_provider->provider_id), out_provider->provider_id);
    }

    if (out_provider)
        mbim_provider_free(out_provider);

    g_local_mcc_retry_flag = 0;

    return;
}

// this func should query home provider status and send mccmnc back to helperd.
gint
fibo_adapter_helperm_get_local_mccmnc(GAsyncReadyCallback func_pointer, gpointer userdata)
{
    g_autoptr(MbimMessage)   request                              =  NULL;
    gint                     retry                                =  REQUEST_MAX_RETRY;

    FIBO_LOG_DEBUG("MBIM FLAG:%d\n", g_mbim_device_init_flag);

    if (func_pointer == NULL) {
        FIBO_LOG_DEBUG("NULL pointer!\n");
        return RET_ERROR;
    }

    while (!g_mbim_device_init_flag && retry >= 0) {
        FIBO_LOG_DEBUG("mbim device not ready! wait for 1s!\n");
        g_usleep(1000 * 1000 * 1);
        retry--;
    }

    if (retry < 0) {
        FIBO_LOG_ERROR("Reach max retry, mbim device not ready!\n");
        return RET_ERR_RESOURCE;
    }

    request = mbim_message_home_provider_query_new (NULL);
    // main thread deal with callback, sub thread will exit without any deal!
    mbim_device_command (mbimdevice,
                         request,
                         5,
                         cancellable,
                         func_pointer,
                         userdata);

    return RET_OK;
}

// this callback will be executed on helperm's mainloop.
void
fibo_adapter_helperm_control_get_network_mccmnc_ready (MbimDevice   *device,
                                 GAsyncResult *res,
                                 gpointer userdata)
{
    g_autoptr(GError)                   error          =  NULL;
    g_autoptr(MbimMessage)              response       =  NULL;
    gint                                ret            =  RET_ERROR;
    MbimRegisterState                   register_state =  MBIM_REGISTER_STATE_UNKNOWN;
    g_autofree gchar                    *provider_id   =  NULL;

    FIBO_LOG_DEBUG("enter!\n");

    response = mbim_device_command_finish (device, res, &error);

    if (!response || !mbim_message_response_get_result (response, MBIM_MESSAGE_TYPE_COMMAND_DONE, &error)) {
        FIBO_LOG_ERROR ("error: operation failed: %s\n", error->message);
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
        return;
    }

    if (!provider_id) {
        FIBO_LOG_DEBUG("register state: %s\n", mbim_register_state_get_string (register_state));
        FIBO_LOG_DEBUG("don't get valid roam mccmnc!\n");
        return;
    }

    FIBO_LOG_DEBUG("provider id: %s\n", provider_id);
    fibo_adapter_helperm_send_control_message_to_helperd(CTL_MBIM_REGISTER_STATE_IND, strlen(provider_id), provider_id);

    return;
}

// this func should query register state status and send roam mccmnc back to helperd.
gint
fibo_adapter_helperm_get_network_mccmnc(GAsyncReadyCallback func_pointer, gpointer userdata)
{

    g_autoptr(MbimMessage)   request                              =  NULL;
    gint                     retry                                =  REQUEST_MAX_RETRY;

    FIBO_LOG_DEBUG("MBIM FLAG:%d\n", g_mbim_device_init_flag);

    if (func_pointer == NULL) {
        FIBO_LOG_DEBUG("NULL pointer!\n");
        return RET_ERROR;
    }

    while (!g_mbim_device_init_flag && retry >= 0) {
        FIBO_LOG_DEBUG("mbim device not ready! wait for 1s!\n");
        g_usleep(1000 * 1000 * 1);
        retry--;
    }

    if (retry < 0) {
        FIBO_LOG_ERROR("Reach max retry, mbim device not ready!\n");
        return RET_ERR_RESOURCE;
    }

    request = mbim_message_register_state_query_new (NULL);
    // main thread deal with callback, sub thread will exit without any deal!
    mbim_device_command (mbimdevice,
                         request,
                         5,
                         cancellable,
                         func_pointer,
                         userdata);

    return RET_OK;
}

// this callback will be executed on helperm's mainloop.
void
fibo_adapter_helperm_deinit_get_subscriber_ready_status_ready (MbimDevice   *device,
                                 GAsyncResult *res,
                                 gpointer userdata)
{
    FIBO_LOG_DEBUG("enter!\n");

    // this func don't care about SIM card status, just to clear insert flag and call deinit function on mainloop.
    g_sim_inserted_flag = FALSE;

    fibo_adapter_mbim_port_deinit();
    return;
}

// this callback will be executed on helperm's mainloop.
void
fibo_adapter_helperm_control_get_subscriber_ready_status_ready (MbimDevice   *device,
                                 GAsyncResult *res,
                                 gpointer userdata)
{
    g_autoptr(GError)                   error          =  NULL;
    g_autoptr(MbimMessage)              response       =  NULL;
    gint                                ret            =  RET_ERROR;
    MbimSubscriberReadyState            ready_state    =  MBIM_SUBSCRIBER_READY_STATE_FAILURE;

    FIBO_LOG_DEBUG("enter!\n");

    response = mbim_device_command_finish (device, res, &error);

    if (!response || !mbim_message_response_get_result (response, MBIM_MESSAGE_TYPE_COMMAND_DONE, &error)) {
        FIBO_LOG_ERROR ("error: operation failed: %s\n", error->message);
        return;
    }

    if (!mbim_message_subscriber_ready_status_response_parse (
            response,
            &ready_state,
            NULL, /* subscriber_id */
            NULL, /* sim_iccid */
            NULL, /* ready_info */
            NULL, /* telephone_numbers_count */
            NULL, /* telephone number */
            &error)) {
        FIBO_LOG_ERROR ("error: couldn't parse response message: %s\n", error->message);
        return;
    }

    switch (ready_state) {
        case MBIM_SUBSCRIBER_READY_STATE_NO_ESIM_PROFILE:
            FIBO_LOG_ERROR("Not support ESIM yet!\n");
            break;
        case MBIM_SUBSCRIBER_READY_STATE_DEVICE_LOCKED:
            FIBO_LOG_DEBUG("Duplicated ind, SIM card is locked!\n");
            break;
        case MBIM_SUBSCRIBER_READY_STATE_INITIALIZED:
            if (g_sim_inserted_flag) {
                FIBO_LOG_DEBUG("SIM card was inserted before, abort to send signal!\n");
                break;
            }
            g_sim_inserted_flag = TRUE;
            fibo_adapter_helperm_send_control_message_to_helperd(CTL_MBIM_SUBSCRIBER_READY_IND, strlen("SIM inserted"), "SIM inserted");

            // HOME PROVIDER not support indication, so here have to manually query.
            fibo_adapter_helperd_send_control_message_to_helperm(CTL_MBIM_HOME_PROVIDER_QUERY, 0, NULL);
            // if this func is called, means service reboot while module existed, give a chance to check network mccmnc to avoid missing indication.
            fibo_adapter_helperd_send_control_message_to_helperm(CTL_MBIM_REGISTER_STATE_QUERY, 0, NULL);
            break;
        case MBIM_SUBSCRIBER_READY_STATE_NOT_INITIALIZED:
            FIBO_LOG_ERROR("SIM card is initializing!\n");
            if (g_sim_inserted_flag) {
                FIBO_LOG_DEBUG("SIM card was inserted before, abort to send signal!\n");
                break;
            }
            g_sim_inserted_flag = TRUE;
            fibo_adapter_helperm_send_control_message_to_helperd(CTL_MBIM_SUBSCRIBER_READY_IND, strlen("SIM inserted"), "SIM inserted");
            break;
        case MBIM_SUBSCRIBER_READY_STATE_FAILURE:
            FIBO_LOG_DEBUG("Failure on SIM card state! treat it as SIM card removed!\n");
        case MBIM_SUBSCRIBER_READY_STATE_SIM_NOT_INSERTED:
            if (!g_sim_inserted_flag) {
                FIBO_LOG_DEBUG("SIM card not inserted at all, abort to send signal!\n");
                break;
            }

            g_sim_inserted_flag = FALSE;
            fibo_adapter_helperm_send_control_message_to_helperd(CTL_MBIM_SUBSCRIBER_READY_IND, strlen("SIM removed"), "SIM removed");
            break;
        default:
            FIBO_LOG_ERROR("Unsupported SIM card ready state: %d!\n", ready_state);
    }

    return;
}

// this func should query subscriber ready status and send mccmnc back to helperd.
gint
fibo_adapter_helperm_get_subscriber_ready_status(GAsyncReadyCallback func_pointer, gpointer userdata)
{
    g_autoptr(MbimMessage)   request                              =  NULL;
    gint                     retry                                =  REQUEST_MAX_RETRY;

    FIBO_LOG_DEBUG("MBIM FLAG:%d\n", g_mbim_device_init_flag);

    while (!g_mbim_device_init_flag && retry >= 0) {
        FIBO_LOG_DEBUG("mbim device not ready! wait for 1s!\n");
        g_usleep(1000 * 1000 * 1);
        retry--;
    }

    if (retry < 0) {
        FIBO_LOG_ERROR("Reach max retry, mbim device not ready!\n");
        return RET_ERR_RESOURCE;
    }

    request = mbim_message_subscriber_ready_status_query_new (NULL);
    // main thread deal with callback, sub thread will exit without any deal!
    mbim_device_command (mbimdevice,
                         request,
                         5,
                         cancellable,
                         func_pointer,
                         userdata);

    return RET_OK;
}

gint
fibo_adapter_helperm_get_work_slot_info(GAsyncReadyCallback func_pointer, gpointer userdata)
{
    g_autoptr(MbimMessage)   request                              =  NULL;
    gint                     retry                                =  REQUEST_MAX_RETRY;

    FIBO_LOG_DEBUG("MBIM FLAG:%d\n", g_mbim_device_init_flag);

    while (!g_mbim_device_init_flag && retry >= 0) {
        FIBO_LOG_DEBUG("mbim device not ready! wait for 1s!\n");
        g_usleep(1000 * 1000 * 1);
        retry--;
    }

    if (retry < 0) {
        FIBO_LOG_ERROR("Reach max retry, mbim device not ready!\n");
        return RET_ERR_RESOURCE;
    }

    request = mbim_message_ms_basic_connect_extensions_device_slot_mappings_query_new(NULL);
    // main thread deal with callback, sub thread will exit without any deal!
    mbim_device_command (mbimdevice,
                         request,
                         5,
                         cancellable,
                         func_pointer,
                         userdata);

    return RET_OK;
}

gint
fibo_adapter_helperm_switch_work_slot(GAsyncReadyCallback func_pointer, gpointer userdata)
{
    g_autoptr(MbimMessage)   request        =  NULL;
    gint                     retry          =  REQUEST_MAX_RETRY;
    gint64                   input_slot     =  RET_ERROR;
    fibo_async_struct_type   *user_data     =  NULL;
    g_autoptr(GPtrArray)     slot_array     =  NULL;
    MbimSlot                *slot_index     =  NULL;

    FIBO_LOG_DEBUG("MBIM FLAG:%d\n", g_mbim_device_init_flag);

    user_data = (fibo_async_struct_type *)userdata;
    if (!user_data) {
        FIBO_LOG_ERROR ("NULL pointer!\n");
        return RET_ERROR;
    }

    slot_array = g_ptr_array_new_with_free_func (g_free);

    input_slot = g_ascii_strtoll (user_data->payload_str, NULL, 10);
    if (input_slot < 0 || input_slot > 1) {
        FIBO_LOG_ERROR ("Invalid slot:%ld!\n", input_slot);
        return RET_ERROR;
    }
    slot_index = g_new (MbimSlot, 1);
    slot_index->slot = (guint32) input_slot;
    g_ptr_array_add (slot_array, slot_index);

    while (!g_mbim_device_init_flag && retry >= 0) {
        FIBO_LOG_DEBUG("mbim device not ready! wait for 1s!\n");
        g_usleep(1000 * 1000 * 1);
        retry--;
    }

    if (retry < 0) {
        FIBO_LOG_ERROR("Reach max retry, mbim device not ready!\n");
        return RET_ERR_RESOURCE;
    }

    request = mbim_message_ms_basic_connect_extensions_device_slot_mappings_set_new(slot_array->len, (const MbimSlot **)slot_array->pdata, NULL);
    // main thread deal with callback, sub thread will exit without any deal!
    mbim_device_command (mbimdevice,
                         request,
                         5,
                         cancellable,
                         func_pointer,
                         userdata);

    return RET_OK;

}

/*--------------------------------------Above are External Funcs-------------------------------------------------------*/

