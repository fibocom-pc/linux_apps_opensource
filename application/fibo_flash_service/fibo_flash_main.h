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

#include <string.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <sys/types.h>
#include <dirent.h>
#include "safe_str_lib.h"

#include "fibocom-helper-gdbus-generated.h"

#define AT_COMMAND_LEN    (256)
#define CMD_OUTPUT_LEN    (64)
#define UPGRADE_MAX_TIMES (1)
#define CONFIG_FILE_PATH "/opt/fibocom/fibo_flash_service/FwFlashSrv"
#define INI_PATH         "/opt/fibocom/fibo_flash_service/FwUpdate.ini"
#define NEW_PACKAGE_PATH "/opt/fibocom/fibo_fw_pkg/FwPackage.zip"
#define FWPACKAGE_PATH   "/opt/fibocom/fibo_fw_pkg/FwPackage/"
#define DEV_PKG_PATH     "/opt/fibocom/fibo_fw_pkg/FwPackage/DEV_OTA_PACKAGE/"
#define FILE_MONITOR_PATH "/opt/fibocom/fibo_fw_pkg/"
#define FLASH_VERSION_STRING "1.0.5"

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

typedef enum {
    GET_SECTION = 1,
    GET_KEY,
    INI_FLAG_INIT
} e_ini_flag;

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
    NO_PORT,
    NORMAL_PORT,
    FLASH_PORT,
    FASTBOOT_PORT,
    DUMP_PORT,
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

#define LIST_NUM 8
typedef struct oem_list
{
    char *oem;
}oem_list;

typedef struct vid_pid_list
{
    char *id;

}vid_pid_list;

typedef struct recovery_list
{
    oem_list oem;
    vid_pid_list id;
    vid_pid_list subsysid;
}recovery_list;

typedef struct g_flags{
    e_command_type type;
    int flag_arry[3];
}g_flags;

int get_retry_times();
void set_package_flag(e_pkg_flag flag);
void save_update_retry(int retry_times);
int get_keyString(const char *filename, const char *section, const char *key, char *result);
void save_cur_imei(char *imei);
void save_cur_subSysid(char *subSysid);
int get_fwinfo(fw_details *fwinfo);
static void search_dev_pack(xmlNode *a_node, xmlChar* oemver, xmlChar* wwandevconfid,
                            xmlChar* skuid, xmlChar *subsys_id);
void find_dev_image(char *docname,xmlChar *oemver, xmlChar* wwandevconfid, xmlChar *skuid,
                    xmlChar *subsys_id);
static void search_oempack_ver(xmlNode *a_node, xmlChar* oemver);
void find_oem_pack_ver_pkg_info(char *docname,xmlChar *oemver);
static void search_skuid(xmlNode *a_node, const xmlChar *oemver);
static void search_cid(xmlNode *a_node, const xmlChar *mccmnc);
static void search_fw_version(xmlNode *a_node, const xmlChar *carrier_id, const xmlChar *subsys_id);
void find_fw_version(char* docname, xmlChar* carrier_id, xmlChar* subsys_id);
static void search_fw_version_default(xmlNode *a_node, const xmlChar *carrier_id, const xmlChar *subsys_id);
void find_fw_version_default(char* docname, xmlChar* carrier_id, xmlChar* subsys_id );
void find_carrier_id(char* docname,xmlChar* mccmnc);
static void search_switchtbl_using_oemver(xmlNode *a_node, const xmlChar *oemver, const xmlChar *subsys_id);
void find_switch_table(char *docname,xmlChar *oemver, xmlChar *subsys_id);
int parse_version_info(char* mccmnc_id, char* sku_id, char* subsys_id,
                       char* oemver, char* wwandevconfid,fw_details *fw_ver);
void find_path_of_file(const char* file, char* directory, char *pathoffile);
gboolean comparative_oem_version();
int check_port_state(char *state);
void reset_update_retry();
#endif

