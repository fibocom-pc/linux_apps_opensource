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
 * @file fibo_flash_main.h
 * @author bolan.wang@fibocom.com (wangbolan)
 * @brief
 * @version 1.0
 * @date 2023-09-23
 *
 *
 **/

#ifndef __FIBO_FLASH_MAIN_H__
#define __FIBO_FLASH_MAIN_H__

#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <linux/netlink.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <termios.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <unwind.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <syslog.h>
#include "fibocom-helper-gdbus-generated.h"

#define AT_COMMAND_LEN    (256)
#define CMD_OUTPUT_LEN    (64)
#define UPGRADE_MAX_TIMES (1)
#define CONFIG_FILE_PATH "/opt/fibocom/fibo_flash_service/FwFlashSrv"
#define INI_PATH         "/opt/fibocom/fibo_flash_service/FwUpdate.ini"
#define NEW_PACKAGE_PATH "/opt/fibocom/fibo_fw_pkg/FwPackage.zip"
#define FWPACKAGE_PATH   "/opt/fibocom/fibo_fw_pkg/FwPackage/"
#define DEV_PKG_PATH     "/opt/fibocom/fibo_fw_pkg/FwPackage/DEV_OTA_PACKAGE/"
#define FLASH_VERSION_STRING "1.0.3"

extern int g_debug_level;

#define FIBO_LOG_OPEN(module) openlog(module, LOG_CONS | LOG_PID, LOG_USER);

#define FIBO_LOG_CRITICAL(log, ...) \
{\
    if (LOG_CRIT <= g_debug_level)\
    {\
        syslog(LOG_CRIT, "[Critical]: %s:%u: "log, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
     }\
}

#define FIBO_LOG_ERROR(log, ...) \
{\
    if (LOG_ERR <= g_debug_level)\
    {\
        syslog(LOG_ERR, "[Error]: %s:%u: "log, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
     }\
}

#define FIBO_LOG_NOTICE(log, ...) \
{\
    if (LOG_NOTICE <= g_debug_level)\
    {\
        syslog(LOG_NOTICE, "[Notice]: %s:%u: "log, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
    }\
}

#define FIBO_LOG_WARNING(log, ...) \
{\
    if (LOG_WARNING <= g_debug_level)\
    {\
        syslog(LOG_WARNING, "[Warning]: %s:%u: "log, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
     }\
}

#define FIBO_LOG_INFO(log, ...) \
{\
     if (LOG_INFO <= g_debug_level)\
    {\
        syslog(LOG_INFO, "[Info]: %s:%u: "log, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
    }\
}

#define FIBO_LOG_DEBUG(log, ...) \
{ \
    if (LOG_DEBUG <= g_debug_level)\
    {\
        syslog(LOG_DEBUG, "[Debug]: %s:%u: "log, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
    }\
}

#define FIBO_LOG_CLOSE closelog();

#define DEV_SUBSYSID_LEN (32)
#define DEV_IMEI_LEN     (32)

typedef struct {
    int package_flag;
    int retry;
    char subSysId[DEV_SUBSYSID_LEN];
    char IMEI[DEV_IMEI_LEN];
} flash_info;

typedef struct {
   char *fw_ver;
   char *cust_pack;
   char *oem_pack;
   char *dev_pack;
   char *ap_ver;
} fw_details;

typedef struct {
   char fw_ver[32];
   char cust_pack[32];
   char oem_pack[32];
   char dev_pack[32];
   char ap_ver[32];
} mdmver_details;

typedef enum {
    FW_UPDATE_FLOW_UNLOCK,
    FW_UPDATE_FLOW_LOCK,
    FW_UPDATE_FLOW_STATE_INIT
} e_flow_state;

typedef enum {
    CMD_GET_WWANID,
    CMD_GET_SKUID,
    CMD_MAX_LIST
} e_allow_cmd;

typedef enum
{
    HELPER,
    FWFLASH,       /* FWflash service */
    FWRECOVERY,    /* FWRecovery service */
    MASERVICE,     /* MA service */
    CONFIGSERVICE, /* Config service */
    UNKNOW_SERVICE /* unknow service */
} e_service_id;

typedef enum
{
    OK = 0,
    ERROR,
    UNKNOWPROJECT
} e_error_code;

typedef enum
{
    NO_FLASH = 0,
    AUTO,
    FORCE,
    FACTORY_MODE
} e_update_option;

typedef enum
{
    INIT = 0,
    NEW_PACKAGE,
    DECOMPRESS_SUCCESS,
    FLASH_START,
    FLASH_FAIL,
    FLASH_SUCCESS
} e_pkg_flag;

typedef enum
{
    GET_AP_VERSION = 0x1001,
    GET_MD_VERSION,
    GET_OP_VERSION,
    GET_OEM_VERSION,
    GET_DEV_VERSION,
    GET_IMEI,
    GET_MCCMNC,
    GET_SUBSYSID,
    SET_ATTACH_APN,
    FLASH_FW,

    /* FWrecovery service command list */
    GET_PORT_STATE         = 0x2001,
    GET_OEM_ID,
    RESET_MODEM_HW,
    FLASH_FW_EDL,
    UNKNOW_COMMAND
} e_command_cid;

typedef struct Header
{
    e_service_id service_id;
    e_command_cid command_cid;

} Header;

typedef struct Mesg
{
    Header header;
    int payload_lenth;
    char payload[0];
} Mesg;


typedef enum
{
    NORMAL_PORT,
    FLASH_PORT,
    FASTBOOT_PORT,
    NO_PORT,
    UNKNOW_PORT,
}e_port_state;

typedef enum
{
    GET,
    SET,
    UNKOWN_TYPE,
}e_command_type;

typedef enum
{
    REBOOTFLAG,
    READYFLASHFLAG,
    PORTSTATEFLAG,
    UNKNOWFLAG,
}e_flags;
#endif

