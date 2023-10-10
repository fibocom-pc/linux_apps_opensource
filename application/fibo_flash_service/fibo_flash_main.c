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
 * @author bolan.wang@fibocom.com (wangbolan)
 * @brief
 * @version 1.0
 * @date 2023-09-23
 *
 *
 **/

#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <string.h>
#include <getopt.h>
#include <sys/mman.h>
#include <glib.h>
#include <gio/gio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stddef.h>
#include <libmbim-glib/libmbim-glib.h>
#include <gio/gio.h>
#include <zlib.h>
#include <assert.h>
#include <ctype.h>
#include "fibo_flash_main.h"
#include "fibocom-helper-gdbus-generated.h"
#include "safe_str_lib.h"

static const char *allow_cmds[CMD_MAX_LIST] = {
    "dmidecode -t 2 | grep 'Product Name' | cut -d ':' -f 2",
    "dmidecode -t 1 | grep 'SKU Number' | cut -d ':' -f 2"
};

mdmver_details g_curmdm_versions;
static GMainLoop *gMainloop = NULL;
FibocomGdbusHelper *proxy;
char g_strType[256] = {0};
extern int g_debug_level = LOG_DEBUG;
e_flow_state flash_flow_state = FW_UPDATE_FLOW_UNLOCK;

/*
 * recovery:
 * */
typedef struct g_flags{
    e_command_type type;
    int flag_arry[3];
}g_flags;
/*
 g_full_flags.flag_arry[0]:   9008->reboot -> flag = 1
 g_full_flags.flag_arry[1]:   9008->reboot->reboot_flag =1 > ready_falsh_flag = 1-> flash
g_full_flags.flag_arry[2]:    modem port state:0 nopoert 1: flashport/fastbootport/normalport*/
static g_flags g_full_flags = {
        UNKOWN_TYPE,
        0,0,0
};

struct sigevent evp;
struct itimerspec ts;
struct itimerspec newts;
timer_t timer;
gboolean reboot_modem();
static int flash_flag = 0;
pthread_mutex_t mutex;
/*
 * recovery:
 * */

int call_helper_method_final(gchar *inarg, gchar *atresp, gint cids)
{
    GError *callError = NULL;
    GVariant *atcommand_out = NULL;
    GVariant *atcommand_in = NULL;
    gchar *atcommand_str = NULL;
    gint serviceid = 0;
    gint rtcode = 0;
    gint cid = 0;
    gint payloadlen = 0;

    if(inarg != NULL)
    {
        atcommand_in = g_variant_new("((ii)iis)", FWFLASH, cids, rtcode, (strlen(inarg) + 1), inarg);
    }
    else
    {
        atcommand_in = g_variant_new("((ii)iis)", FWFLASH, cids, rtcode, 0, "");
    }

    fibocom_gdbus_helper_call_send_mesg_sync(proxy,atcommand_in,&atcommand_out,NULL,&callError);
    if(callError == NULL)
    {
        FIBO_LOG_INFO("[%x] call helper success\n", cids);
        g_variant_get(atcommand_out, "((ii)iis)", &serviceid, &cid, &rtcode, &payloadlen, &atcommand_str);
        if(rtcode)
        {
            FIBO_LOG_INFO("[%s]:Error code is: %d\n", __func__, rtcode);
            return ERROR;
        }

        if(atcommand_out != NULL)
        {
            if(atresp)
            {
                memcpy(atresp, atcommand_str, payloadlen);
                g_variant_unref(atcommand_out);
                //string type need free;
                FIBO_LOG_INFO("[%s]:=======ok========: atresp:%s,atcommand_str:%s,payloadlen:%d\n", __func__, atresp, atcommand_str,payloadlen);
                g_free(atcommand_str);
            }
        }
    }
    else
    {
        FIBO_LOG_INFO("Call error!!!:[%s]\n", callError->message);
        return ERROR;
    }

    return OK;
}

int get_modem_version_info()
{
    e_error_code ret;
    bool parse_ap = FALSE;
    bool parse_md = FALSE;
    bool parse_op = FALSE;
    bool parse_oem = FALSE;
    bool parse_dev = FALSE;

    FIBO_LOG_INFO("Entry");

    memset(&g_curmdm_versions, 0, sizeof(mdmver_details));

    ret = call_helper_method_final(NULL, g_curmdm_versions.ap_ver, GET_AP_VERSION);
    if (ERROR == ret)
    {
        FIBO_LOG_ERROR("call helper to get ap version failed");
    }
    else
    {
        parse_ap = TRUE;
        FIBO_LOG_INFO("current ap version:%s", g_curmdm_versions.ap_ver);
    }

    ret = call_helper_method_final(NULL, g_curmdm_versions.fw_ver, GET_MD_VERSION);
    if (ERROR == ret)
    {
        FIBO_LOG_ERROR("call helper to get modem version failed");
    }
    else
    {
        parse_md = TRUE;
        FIBO_LOG_INFO("current modem version:%s", g_curmdm_versions.fw_ver);
    }


    ret = call_helper_method_final(NULL, g_curmdm_versions.cust_pack, GET_OP_VERSION);
    if (ERROR == ret)
    {
        FIBO_LOG_ERROR("call helper to get op version failed");
    }
    else
    {
        parse_op = TRUE;
        FIBO_LOG_INFO("current op version:%s", g_curmdm_versions.cust_pack);
    }

    ret = call_helper_method_final(NULL, g_curmdm_versions.oem_pack, GET_OEM_VERSION);
    if (ERROR == ret)
    {
        FIBO_LOG_ERROR("call helper to get oem version failed");
    }
    else
    {
        parse_oem = TRUE;
        FIBO_LOG_INFO("current oem version:%s", g_curmdm_versions.oem_pack);
    }


    ret = call_helper_method_final(NULL, g_curmdm_versions.dev_pack, GET_DEV_VERSION);
    if (ERROR == ret)
    {
        FIBO_LOG_ERROR("call helper to get dev version failed");
    }
    else
    {
        parse_dev = TRUE;
        FIBO_LOG_INFO("current dev version:%s", g_curmdm_versions.dev_pack);
    }

    if (parse_ap && parse_md && parse_op && parse_oem && parse_dev)
    {
        FIBO_LOG_INFO("get current fw versions sucess");
        ret = OK;
    }
    else
    {
        ret = ERROR;
    }

    return ret;
}

int get_subSysID(char *subSysid)
{
    e_error_code ret;
    char resp[32] = {0};

    ret = call_helper_method_final(NULL, resp, GET_SUBSYSID);
    if (ERROR == ret)
    {
        FIBO_LOG_ERROR("call helper to get imei failed");
    }
    else
    {
        memcpy(subSysid, resp, 8);
    }

    return ret;
}

int get_imei(char *imei)
{
    e_error_code ret;

    ret = call_helper_method_final(NULL, imei, GET_IMEI);
    if (ERROR == ret)
    {
        FIBO_LOG_ERROR("call helper to get imei failed");
    }

    return ret;
}

bool compare_version_dev_need_update(mdmver_details *curmdm_ver, fw_details *fw_ver)
{
    char strDev[32] = "dev:";
    char str_fw[64] = "";
    bool need_update = FALSE;

   if(NULL == strstr(curmdm_ver->dev_pack, fw_ver->dev_pack))
    {
        strcat(strDev, fw_ver->dev_pack);

        memset(g_strType, 0, sizeof(g_strType));
        strcpy(g_strType, strDev);
        need_update = TRUE;

        FIBO_LOG_INFO("send flash fw str:[%s] to helper", g_strType);
    }

    return need_update;
}

bool compare_version_need_update(mdmver_details *curmdm_ver, fw_details *fw_ver)
{
    char strAp[32] = "ap:";
    char strMd[32] = "md:";
    char strOem[32] = "oem:";
    char strOp[32] = "op:";
    char strDev[32] = "dev:";
    char str_fw[256] = {0};
    int len;
    bool need_update = FALSE;

    if ((NULL == fw_ver->ap_ver) || (NULL == fw_ver->fw_ver) || (NULL == fw_ver->oem_pack) || (NULL == fw_ver->cust_pack) ||
        (NULL == fw_ver->dev_pack))
    {
        FIBO_LOG_ERROR("param is NULL");
        return FALSE;
    }

    if(strstr(curmdm_ver->ap_ver, fw_ver->ap_ver) == NULL)
    {
        strcat(strAp, fw_ver->ap_ver);
        strcat(str_fw, strAp);
        strncat(str_fw, ";", 1);
        need_update = TRUE;
    }

    if(strstr(curmdm_ver->fw_ver, fw_ver->fw_ver) == NULL)
    {
        strcat(strMd, fw_ver->fw_ver);
        strcat(str_fw, strMd);
        strncat(str_fw, ";", 1);
        need_update = TRUE;
    }

    if(strstr(curmdm_ver->oem_pack, fw_ver->oem_pack) == NULL)
    {
        strcat(strOem, fw_ver->oem_pack);
        strcat(str_fw, strOem);
        strncat(str_fw, ";", 1);
        need_update = TRUE;
    }

    if(strstr(curmdm_ver->cust_pack, fw_ver->cust_pack) == NULL)
    {
        strcat(strOp, fw_ver->cust_pack);
        strcat(str_fw, strOp);
        strncat(str_fw, ";", 1);
        need_update = TRUE;
    }

   if(strstr(curmdm_ver->dev_pack, fw_ver->dev_pack) == NULL)
    {
        strcat(strDev, fw_ver->dev_pack);
        strcat(str_fw, strDev);
        strncat(str_fw, ";", 1);
        need_update = TRUE;
    }

    FIBO_LOG_INFO("flash fw is:%s", str_fw);
    memcpy(g_strType, str_fw, sizeof(str_fw));

    FIBO_LOG_INFO("send flash fw str:[%s] to helper", g_strType);
    return need_update;
}

void execute_cmd(int cmd_id, char* result)
{
    FILE *cmd = NULL;

    FIBO_LOG_INFO("Entry");

    if ((0 <= cmd_id) && (CMD_MAX_LIST >= cmd_id))
    {
        cmd = popen(allow_cmds[cmd_id], "r");

       if(result != NULL && cmd != NULL)
       {
           if(fgets(result, CMD_OUTPUT_LEN, cmd) == NULL)
           {
               FIBO_LOG_ERROR(" failed to get cmd: [%d] output \n", cmd_id);
           }
       }

       if(cmd != NULL)
       {
           pclose(cmd);
       }
    }
}

void do_flash_fw(char *g_strType)
{
    e_error_code ret;
    int retry = 0;

    retry = get_retry_times();
    if (retry > UPGRADE_MAX_TIMES)
    {
        FIBO_LOG_INFO("retry max times");
        set_package_flag(FLASH_FAIL);
    }
    else
    {
        retry++;
        save_update_retry(retry);

        ret = call_helper_method_final(g_strType, NULL, FLASH_FW);
        if (ERROR == ret)
        {
            FIBO_LOG_ERROR("call_helper_method_final error");

            if (retry > UPGRADE_MAX_TIMES)
            {
                FIBO_LOG_INFO("retry max times");
                set_package_flag(FLASH_FAIL);
            }
            else
            {
                set_package_flag(FLASH_START);
            }
        }
        else
        {
            FIBO_LOG_ERROR("call_helper_method_final ok");
        }
    }
}

int get_mccmnc(char *mccmnc)
{
    e_error_code ret;

    ret = call_helper_method_final(NULL, mccmnc, GET_MCCMNC);
    if (ERROR == ret)
    {
        FIBO_LOG_ERROR("call helper to get mccmnc failed");
    }

    return ret;
}

void get_skuID(char *skuid)
{
    int i, j;
    i = 0;
    char result[32] = {0};

    execute_cmd(CMD_GET_SKUID, result);
    strncpy_s(skuid, 32, result, strnlen_s(result, 32) - 1);

    j = strlen(skuid) - 1;
    while (skuid[i] == ' ')
        ++i;
    while (skuid[j] == ' ')
        --j;

    strncpy(skuid, (skuid + i), (j - i + 1));
    skuid[j - i + 1] = '\0';

    FIBO_LOG_INFO("get skuID is:%s", skuid);
}

void get_wwanconfigID(char *wwanconfigID)
{
    char result[32] = {0};

    execute_cmd(CMD_GET_WWANID, result);
    strncpy_s(wwanconfigID, 32, result, strnlen_s(result, 32) - 1);
    FIBO_LOG_INFO("get wwanconfigID is:%s", wwanconfigID);
}

void get_subSysID_from_file(char *subSysID)
{
    flash_info checkInfo = {0};
    FILE *g_file = NULL;

    g_file = fopen(CONFIG_FILE_PATH, "r+");
    if (NULL == g_file)
    {
        FIBO_LOG_INFO("FwFlashSrv file not exist");
    }
    else
    {
        fread(&checkInfo, sizeof(flash_info), 1, g_file);
        strcpy(subSysID, checkInfo.subSysId);
        fclose(g_file);
    }
}

bool check_power_status()
{
    char path[40] = "/sys/class/power_supply/BAT0/capacity";
    struct stat fstat;
    int ret = 0;
    int fd;
    char capacity[10] = {0};
    int bat_threshold;
    int power_limit;
    char result[8] = {0};

    FIBO_LOG_INFO("check current battery capacity whether satisfy update");

    ret = get_keyString(INI_PATH, "BASE_CONFIG", "POWER_LIMIT",result);
    if (ret)
    {
        FIBO_LOG_ERROR("get ini config failed");
        return FALSE;
    }
    else
    {
        power_limit = atoi(result);
        FIBO_LOG_INFO("power limit is %d", atoi(result));
        if (1 != power_limit)
        {
            FIBO_LOG_INFO("not power limit");
            return TRUE;
        }
    }

    ret = get_keyString(INI_PATH, "BASE_CONFIG", "POWER_BAT_THRESHOLD",result);
    if (ret)
    {
        FIBO_LOG_ERROR("get ini config failed");
        return FALSE;
    }
    else
    {
        bat_threshold = atoi(result);
        FIBO_LOG_INFO("battery threshold is %d", atoi(result));
    }

   ret = lstat(path, &fstat);
   if(0 == ret)
   {
      if(S_ISLNK(fstat.st_mode))
      {
          FIBO_LOG_ERROR("symlink %s detected operation not permitted", path);
          return FALSE;
      }
   }
   else
   {
       FIBO_LOG_INFO("operation is permitted");
   }


    fd = open(path, O_RDONLY);
    if (0 > fd)
    {
        FIBO_LOG_ERROR("cannot open file: %s", path);
    }
    else
    {
        read(fd, capacity, 5);
        FIBO_LOG_INFO("capacity: %d",atoi(capacity));
        close(fd);

        if(atoi(capacity) >= bat_threshold)
        {
            FIBO_LOG_INFO("current power is higher than battery threshold");
            return TRUE;
        }
    }

    return FALSE;
}

bool update_need_sim_enable()
{
    int ret;
    char result[8] = {0};

    FIBO_LOG_INFO("entry");

    ret = get_keyString(INI_PATH, "BASE_CONFIG", "ChkUpdateNeedSIMENABLE", result);
    if (ret)
    {
        FIBO_LOG_ERROR("get ini config failed");
    }
    else
    {
        FIBO_LOG_INFO("ChkUpdateNeedSIMENABLE is %s", result);
        if (!strcmp(result, "1"))
        {
            FIBO_LOG_INFO("update need sim enable");
            return TRUE;
        }
        else
        {
            FIBO_LOG_INFO("update no need sim enable");
        }
    }

    return FALSE;
}

void fw_update()
{
    char mccmncid[32] = {0};
    char skuid[32] = {0};
    char subSysid[32] = {0};
    char oemVer[32] = {0};
    char wwanconfigID[32] = {0};
    char imei[DEV_IMEI_LEN] = {0};
    fw_details fw_version = {0};
    e_error_code status = UNKNOWPROJECT;
    bool need_update = FALSE;
    char result[8] = {0};
    int ret;
    e_update_option update_option = AUTO;

    FIBO_LOG_INFO("Entry");

    if (FW_UPDATE_FLOW_UNLOCK == flash_flow_state)
    {
        flash_flow_state = FW_UPDATE_FLOW_LOCK;
    }
    else
    {
        FIBO_LOG_INFO("fw update is running, need to wait completion");
        return;
    }

    ret = get_keyString(INI_PATH, "BASE_CONFIG", "FwUpdateOption", result);
    if (ret)
    {
        FIBO_LOG_ERROR("get ini config failed");
    }
    else
    {
        update_option = atoi(result);
        FIBO_LOG_INFO("Fw update option is  %d", update_option);
    }

    if (NO_FLASH == update_option)
    {
        FIBO_LOG_INFO("Fw update option is no need flash");
        flash_flow_state = FW_UPDATE_FLOW_UNLOCK;
        return;
    }

   status = get_mccmnc(mccmncid);
    if (status == ERROR)
    {
        FIBO_LOG_ERROR("failed to get mccmnc");
    }

    if (update_need_sim_enable())
    {
        if (strcmp(mccmncid, "\0") == 0)
        {
            FIBO_LOG_INFO("can't get mccmnc,no need to flash");
            flash_flow_state = FW_UPDATE_FLOW_UNLOCK;
            return;
        }
    }

    get_skuID(skuid);
    get_wwanconfigID(wwanconfigID);

    status = get_imei(imei);
    if (ERROR == status)
    {
        FIBO_LOG_ERROR("failed to get imei");
    }
    else
    {
        FIBO_LOG_INFO("get imei is: %s", imei);
        save_cur_imei(imei);
    }


    status = get_subSysID(subSysid);
    if (ERROR == status)
    {
        FIBO_LOG_ERROR("failed to get subsysid");
        get_subSysID_from_file(subSysid);
    }
    else
    {
        FIBO_LOG_INFO("get subSysid:%s", subSysid);

        if (strcmp(subSysid, "\0") != 0)
        {
            FIBO_LOG_INFO("subSysid is not null, save it");
            save_cur_subSysid(subSysid);
        }
    }

    if(!strcmp(subSysid, "\0"))
    {
        strcpy(subSysid, "default");
        FIBO_LOG_INFO("set subSysID to default");
    }

    status = get_modem_version_info();
    if (ERROR == status)
    {
        FIBO_LOG_ERROR("failed to get modem current versions");
        flash_flow_state = FW_UPDATE_FLOW_UNLOCK;
        return;
    }

    parse_version_info(mccmncid, skuid, subSysid, oemVer, wwanconfigID, &fw_version);

    if (FACTORY_MODE == update_option)
    {
        FIBO_LOG_INFO("factory mode, only need to flash devpack");

        need_update = compare_version_dev_need_update(&g_curmdm_versions, &fw_version);
        if (TRUE == need_update)
        {
            FIBO_LOG_INFO("need to update devpack versions");

            need_update = check_power_status();
            if (TRUE == need_update)
            {
                set_package_flag(FLASH_START);
                do_flash_fw(g_strType);
            }

        }
        else
        {
            FIBO_LOG_INFO("The devpack already has correct firmware version");
        }
    }
    else if (AUTO == update_option)
    {
        need_update = compare_version_need_update(&g_curmdm_versions, &fw_version);
        if (TRUE == need_update)
        {
            FIBO_LOG_INFO("need to update firmware versions");

            need_update = check_power_status();
            if (TRUE == need_update)
            {
                set_package_flag(FLASH_START);
                do_flash_fw(g_strType);
            }

        }
        else
        {
            FIBO_LOG_INFO("The modem already has correct firmware versions");
        }
    }
    else if (FORCE == update_option)
    {
        FIBO_LOG_INFO("FW update is force flash, need to flash full packages");

        memset(&g_curmdm_versions, 0, sizeof(mdmver_details));
        need_update = compare_version_need_update(&g_curmdm_versions, &fw_version);
        if (TRUE == need_update)
        {
            FIBO_LOG_INFO("need to update firmware versions");

            need_update = check_power_status();
            if (TRUE == need_update)
            {
                set_package_flag(FLASH_START);
                do_flash_fw(g_strType);
            }
        }
    }

    flash_flow_state = FW_UPDATE_FLOW_UNLOCK;
}

void save_update_retry(int retry_times)
{
    flash_info check_info = {0};
    FILE *g_file = NULL;

    g_file = fopen(CONFIG_FILE_PATH, "r+");
    if (NULL == g_file)
    {
        FIBO_LOG_INFO("FwFlashSrv file not exist");
    }
    else
    {
        fread(&check_info, sizeof(flash_info), 1, g_file);

        check_info.retry = retry_times;
        rewind(g_file);
        fwrite(&check_info, sizeof(flash_info), 1, g_file);
        fclose(g_file);

        FIBO_LOG_INFO("save update retry times:%d success", check_info.retry);
    }
}

void reset_update_retry()
{
    int retry;

    retry = get_retry_times();
    if (0 != retry)
    {
        retry = 0;
        save_update_retry(retry);
    }
}

void set_package_flag(e_pkg_flag flag)
{
    flash_info check_info = {0};
    FILE *g_file = NULL;

    g_file = fopen(CONFIG_FILE_PATH, "r+");
    if (NULL == g_file)
    {
        FIBO_LOG_INFO("FwFlashSrv file not exist");
    }
    else
    {
        fread(&check_info, sizeof(flash_info), 1, g_file);

        check_info.package_flag = flag;
        rewind(g_file);
        fwrite(&check_info, sizeof(flash_info), 1, g_file);
        fclose(g_file);

        FIBO_LOG_INFO("write package flag success");

        if ((FLASH_FAIL == flag) || (FLASH_SUCCESS == flag))
        {
            reset_update_retry();
        }
    }
}

e_pkg_flag get_package_flag()
{
    flash_info check_info = {0};
    int pkg_flag = 0;
    FILE *g_file = NULL;

    g_file = fopen(CONFIG_FILE_PATH, "r+");
    if (NULL == g_file)
    {
        FIBO_LOG_INFO("FwFlashSrv file not exist");
    }
    else
    {
        fread(&check_info, sizeof(flash_info), 1, g_file);
        pkg_flag = check_info.package_flag;
        fclose(g_file);

        FIBO_LOG_INFO("read package flag:%d success", pkg_flag);
    }

    return pkg_flag;
}

int get_retry_times()
{
    flash_info check_info;
    int retry = 0;
    FILE *g_file = NULL;

    g_file = fopen(CONFIG_FILE_PATH, "r+");
    if (NULL == g_file)
    {
        FIBO_LOG_INFO("FwFlashSrv file not exist");
    }
    else
    {
        fread(&check_info, sizeof(flash_info), 1, g_file);
        retry = check_info.retry;
        fclose(g_file);

        FIBO_LOG_INFO("read retry times:%d", retry);
    }

    return retry;
}

bool check_flash_flag()
{
    bool need_flash = FALSE;
    e_pkg_flag pkg_flag;

    pkg_flag = get_package_flag();
    if (pkg_flag == FLASH_START)
    {
        FIBO_LOG_INFO("last flash not complete or failed, need retry.");
        need_flash = TRUE;
    }
    else
    {
        FIBO_LOG_INFO("no need flash flag");
        return need_flash;
    }

    return need_flash;
}

bool check_new_package()
{
    FILE *zip_file = NULL;
    char command[128] = {0};
    int ret;
    e_pkg_flag pkg_flag;
    bool new_pkg = FALSE;

    zip_file = fopen(NEW_PACKAGE_PATH, "r");
    if (zip_file != NULL)
    {
        set_package_flag(NEW_PACKAGE);
        sprintf(command, "unzip %s -d %s", NEW_PACKAGE_PATH, "/opt/fibocom/fibo_fw_pkg/");

        ret = system(command);
        if (!ret)
        {
            FIBO_LOG_INFO("unzip package sucess");
            set_package_flag(DECOMPRESS_SUCCESS);
            remove(NEW_PACKAGE_PATH);
        }

        new_pkg = TRUE;
    }
    else
    {
        FIBO_LOG_INFO("not new package.");
    }

    return new_pkg;
}

void save_cur_imei(char *imei)
{
    flash_info check_info = {0};
    FILE *g_file = NULL;

    g_file = fopen(CONFIG_FILE_PATH, "r+");
    if (NULL == g_file)
    {
        FIBO_LOG_INFO("FwFlashSrv file not exist");
    }
    else
    {
        fread(&check_info, sizeof(flash_info), 1, g_file);

        strcpy(check_info.IMEI, imei);
        rewind(g_file);
        fwrite(&check_info, sizeof(flash_info), 1, g_file);
        fclose(g_file);
    }
}

void save_cur_subSysid(char *subSysid)
{
    flash_info check_info = {0};
    FILE *g_file = NULL;

    g_file = fopen(CONFIG_FILE_PATH, "r+");
    if (NULL == g_file)
    {
        FIBO_LOG_INFO("FwFlashSrv file not exist");
    }
    else
    {
        fread(&check_info, sizeof(flash_info), 1, g_file);

        strcpy(check_info.subSysId, subSysid);
        rewind(g_file);
        fwrite(&check_info, sizeof(flash_info), 1, g_file);
        fclose(g_file);
    }
}

void check_imei_change()
{
    e_error_code status = UNKNOWPROJECT;
    char imei[DEV_IMEI_LEN] = {0};
    char save_imei[DEV_IMEI_LEN] = {0};
    flash_info check_info = {0};
    FILE *g_file = NULL;

    FIBO_LOG_INFO("Entry");

    status = get_imei(imei);
    if (status == ERROR)
    {
        FIBO_LOG_ERROR("failed to get imei");
        return;
    }

    g_file = fopen(CONFIG_FILE_PATH, "r+");
    if (NULL == g_file)
    {
        FIBO_LOG_INFO("FwFlashSrv file not exist");
    }
    else
    {
        fread(&check_info, sizeof(flash_info), 1, g_file);
        strcpy(save_imei, check_info.IMEI);
        fclose(g_file);

        if (0 != strcmp(imei, save_imei))
        {
            FIBO_LOG_INFO("IMEI change, need to update");

            save_cur_imei(imei);
            fw_update();
        }
        else
        {
            FIBO_LOG_INFO("no need update");
        }
    }
}

/*
 * recovery:
 * */

/*
 * watch SIGALRM siganal
 * 1.if recive this siganal, then add timer 20s,if timeout exec reboot_modem()
 */
gboolean get_port_state(e_port_state *state);
static g_flags get_set_reboot_flag(g_flags  value)
{
    int i = 0;
    switch(value.type)
    {
        case GET:
            return g_full_flags;
        case SET:
            pthread_mutex_lock(&mutex);
            for(i = 0; i < 3; i++)
            {
                if(value.flag_arry[i] == -1)
                {
                    continue;
                }
                else
                {
                    g_full_flags.flag_arry[i] = value.flag_arry[i];
                }

            }
            pthread_mutex_unlock(&mutex);
            return g_full_flags;
        default:
        FIBO_LOG_INFO("[%s]:Error of unkown command type\n", __func__);
    }
}

void sighandle(int signum)
{
    switch(signum)
    {
        case SIGALRM:
        FIBO_LOG_INFO("[%s]:Recv Alerm signal\n", __func__);
            g_timeout_add(5000,(GSourceFunc)reboot_modem, NULL);
            break;
        default:
        FIBO_LOG_INFO("[%s]:Recv %d signal\n", __func__, signum);
    }
}
/*
 * init_flash_timer(): init a timer of time(m)
 * */
gboolean init_flash_timer()
{
    int ret = 0;

    evp.sigev_value.sival_ptr = &timer;
    evp.sigev_notify          = SIGEV_SIGNAL;
    evp.sigev_signo           = SIGALRM;
    signal(evp.sigev_signo, sighandle);
    ret = timer_create(CLOCK_REALTIME, &evp, &timer);
    if(ret)
    {
        perror("timer_create error\n");
        FIBO_LOG_INFO("[%s]: >>>>-----Timer Init error:timer_create-----<<<<\n", __func__);
        return false;
    }

    FIBO_LOG_INFO("[%s]: >>>>-----Timer Init OK-----<<<<\n", __func__);
    return true;
}

gboolean start_flash_timer(int time)
{
    int ret = 0;
    ts.it_interval.tv_sec = 0;
    ts.it_interval.tv_nsec = 0;
    ts.it_value.tv_sec = time *60;
    ts.it_value.tv_nsec = 0;

    ret = timer_settime(timer, CLOCK_REALTIME, &ts, NULL);
    if(ret)
    {
        perror("start_flash_timer error\n");
        FIBO_LOG_INFO("[%s]: >>>>-----Timer Start error-----<<<<\n", __func__);
        return false;
    }

    FIBO_LOG_INFO("[%s]: >>>>-----Timer Start OK-----<<<<\n", __func__);
    return true;
}

gboolean stop_flash_timer()
{
    int ret = 0;
    ts.it_interval.tv_sec = 0;
    ts.it_interval.tv_nsec = 0;
    ts.it_value.tv_sec = 0;
    ts.it_value.tv_nsec = 0;

    if(timer_gettime(timer, &newts))
    {
        FIBO_LOG_INFO("[%s]: >>>>-----Timer stop error: timer_gettime error-----<<<<\n", __func__);
    }
    else
    {
        FIBO_LOG_INFO("[%s]: >>>>--it_value.tv_sec:%d,it_value.tv_nsec:%d,it_interval.tv_sec:%d, it_interval.tv_nsec:%d--------<<<<\n",
                      __func__, newts.it_value.tv_sec, newts.it_value.tv_nsec, newts.it_interval.tv_sec, newts.it_interval.tv_nsec);
        if(newts.it_value.tv_sec <= 0 && newts.it_value.tv_nsec <= 0)
        {
            FIBO_LOG_INFO("[%s]: >>>>-----Timer stop ok: Timer is stoped-----<<<<\n", __func__);
            return true;
        }
    }

    ret = timer_settime(timer, CLOCK_REALTIME, &ts, NULL);
    if(ret)
    {
        perror("stop_flash_timer error\n");
        FIBO_LOG_INFO("[%s]: >>>>-----Timer stop error-----<<<<\n", __func__);
        return false;
    }

    FIBO_LOG_INFO("[%s]: >>>>-----Timer stop OK-----<<<<\n", __func__);
    return true;
}

static gboolean flash_status_handler(FibocomGdbusHelper *object, const char *value, gpointer userdata)
{
    FIBO_LOG_INFO("flash_status_handler &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& invoked! %s \n", value);
    if(value == NULL)
    {
        return TRUE;
    }
    else
    {
        FIBO_LOG_INFO("[%s]:===============>%s\n", __func__, (char *)value);
        if(strstr(value,"flashing..."))
        {
            flash_flag = 1;
        }
        else if(strstr(value,"flashing ok"))
        {
            flash_flag = 0;
        }
        else if(strstr(value,"flashing error"))
        {
            flash_flag = 0;
        }
        else if(strstr(value,"charge is low"))
        {
            flash_flag = 0;
        }

    }

    return TRUE;
}

void normalport_precess();
void flashport_precess();
void noport_precess();
void fastbootport_precess();
gboolean flash_fw(char *ap, char *modem, char *oem);
void normalport_precess()
{
    g_flags      flag;
    int          ret = 0;
    flag.type = SET;

    ret = stop_flash_timer(timer);
    if(!ret)
    {
        perror("timer_settime error\n");
        FIBO_LOG_INFO("[%s]: >>>>-----stop_flash_timer error-----<<<<\n", __func__);
    }


    flag.flag_arry[REBOOTFLAG] = 0;
    flag.flag_arry[READYFLASHFLAG] = 0;
    flag.flag_arry[PORTSTATEFLAG] = 1;
    (void)get_set_reboot_flag(flag);
}
void flashport_precess()
{
    g_flags      flag;
    fw_details fwinfo;
    int ret = 0;
    flag.type = SET;
    (void)get_fwinfo( &fwinfo);

    if(g_full_flags.flag_arry[REBOOTFLAG] == 0)
    {
        //reboot modem and set reboot_flag =1
        //reboot_modem();
        ret = stop_flash_timer();
        if(!ret)
        {
            perror("timer_settime error\n");
            FIBO_LOG_INFO("[%s]: >>>>-----stop_flash_timer error-----<<<<\n", __func__);
        }

        flag.flag_arry[REBOOTFLAG] = -1;
        flag.flag_arry[READYFLASHFLAG] = 1;
        flag.flag_arry[PORTSTATEFLAG] = 1;
        (void)get_set_reboot_flag(flag);
        flash_fw(fwinfo.ap_ver, fwinfo.fw_ver, fwinfo.oem_pack);
    }
    else if(g_full_flags.flag_arry[REBOOTFLAG] == 1)
    {
        //stop timer
        ret = stop_flash_timer();
        if(!ret)
        {
            perror("timer_settime error\n");
            FIBO_LOG_INFO("[%s]: >>>>-----stop_flash_timer error-----<<<<\n", __func__);
        }

        flag.flag_arry[REBOOTFLAG] = -1;
        flag.flag_arry[READYFLASHFLAG] = 1;
        flag.flag_arry[PORTSTATEFLAG] = 1;
        (void)get_set_reboot_flag(flag);
        flash_fw(fwinfo.ap_ver, fwinfo.fw_ver, fwinfo.oem_pack);
    }
    else if(g_full_flags.flag_arry[READYFLASHFLAG] == 1)
    {
        ret = stop_flash_timer();
        if(!ret)
        {
            perror("stop_flash_timer error\n");
            FIBO_LOG_INFO("[%s]: >>>>-----stop_flash_timer error-----<<<<\n", __func__);
        }
        flag.flag_arry[REBOOTFLAG] = -1;
        flag.flag_arry[READYFLASHFLAG] = -1;
        flag.flag_arry[PORTSTATEFLAG] = 1;
        (void)get_set_reboot_flag(flag);
    }
}
void noport_precess()
{
    g_flags      flag;
    flag.type = SET;
    int ret = 0;
    /*ret = init_flash_timer();
    if(ret)
    {
        perror("init timer error\n");
        FIBO_LOG_INFO("init timer error!\n");
    }*/

    //no port, add 3min timer
    ret = start_flash_timer(3);
    if(!ret)
    {
        perror("start timer error\n");
        FIBO_LOG_INFO("start timer error!\n");
    }

    flag.flag_arry[REBOOTFLAG] = -1;
    flag.flag_arry[READYFLASHFLAG] = -1;
    flag.flag_arry[PORTSTATEFLAG] = 1;
    (void)get_set_reboot_flag(flag);
}
void fastbootport_precess()
{
    FIBO_LOG_INFO("[%s]:Now is fasbbootport\n", __func__);
}

//fw switch code
static gboolean fastboot_status_handler(FibocomGdbusHelper *object, const char *value, gpointer userdata)
{
    e_error_code ret;
    int retry = 0;

    if(NULL == value)
    {
        FIBO_LOG_INFO("value is null");
        return TRUE;
    }

    FIBO_LOG_INFO("fastboot_status_handler invoked! %s \n", value);

    retry = get_retry_times();
    FIBO_LOG_INFO("retry is :%d", retry);

    if(strstr(value,"flashing..."))
    {
        FIBO_LOG_INFO("fastboot start flashing");
        set_package_flag(FLASH_START);
    }
    else if(strstr(value,"flashing ok"))
    {
        FIBO_LOG_INFO("fastboot flash success");
        set_package_flag(FLASH_SUCCESS);
    }
    else if(strstr(value,"flashing error"))
    {
        FIBO_LOG_INFO("fastboot flash failed");
        if (retry > UPGRADE_MAX_TIMES)
        {
            FIBO_LOG_INFO("retry max times");
            set_package_flag(FLASH_FAIL);
        }
        else
        {
            set_package_flag(FLASH_START);
        }
    }
    else if(strstr(value,"charge is low"))
    {
        FIBO_LOG_INFO("fastboot return low charge");
        set_package_flag(FLASH_FAIL);
    }

    return TRUE;
}

gboolean modem_status_handler(FibocomGdbusHelper *object, const char *value, gpointer userdata)
{
    bool need_flash_flag = FALSE;
    e_error_code status;
    char port_status[32] = {0};

    FIBO_LOG_INFO("modem_status_handler invoked! %s \n", value);

    if (NULL != strstr(value, "cellular existed"))
    {
        g_usleep (1000 * 1000 * 5);
        status = check_port_state(port_status);
        if (ERROR == status)
        {
            FIBO_LOG_ERROR("get port state failed");
            return TRUE;
        }
        else
        {
            if (NULL == strstr(port_status, "normalport"))
            {
                FIBO_LOG_ERROR("port state is abnormal, no need to handle");
                return TRUE;
            }
        }

        need_flash_flag = check_flash_flag();
        if (need_flash_flag == TRUE)
        {
            fw_update();
        }
        else
        {
            check_imei_change();
        }
    }

    return TRUE;
}

static gboolean modem_status_callback(FibocomGdbusHelper *object, const char *value, gpointer userdata)
{
    int          ret = 0;
    g_flags      flag;
    e_port_state state;

    FIBO_LOG_INFO("modem_status_callback invoked! %s \n", value);

    //if(flash_flag = 0)
    if(value == NULL)
    {
        return TRUE;
    }
    else
    {
        if(!get_port_state(&state))
        {
            FIBO_LOG_INFO("[%s]:[get_port_state] error\n", __func__);
            return TRUE;
        }

        FIBO_LOG_INFO("[%s]:recive userdate :%s, port state is :%d\n", __func__, (char *)value, state);
        switch (state)
        {
            case NORMAL_PORT:
                normalport_precess();
                break;
            case FLASH_PORT:
                flashport_precess();
                break;
            case NO_PORT:
                noport_precess();
                break;
            case FASTBOOT_PORT:
                fastbootport_precess();
                break;
            default:
                FIBO_LOG_INFO("[%s]:error invail port type\n", __func__);
        }
    }


    return TRUE;
}
#if 1
gboolean regester_interesting_siganl()
{
    //注册signal处理函数
    g_signal_connect(proxy, "cellular-state",G_CALLBACK(modem_status_callback),NULL);
    g_signal_connect(proxy,"edl-status",G_CALLBACK(flash_status_handler),NULL);

    FIBO_LOG_INFO("interesting signal regester!");
    return true;
}
#endif

gboolean reboot_modem()
{
    g_flags flag;
    FIBO_LOG_INFO("[%s] :enter!!!\n", __func__);
    int ret = 0;

    if(g_full_flags.flag_arry[READYFLASHFLAG]  == 1 || flag.flag_arry[PORTSTATEFLAG] == 1)
    {
        FIBO_LOG_INFO("[%s] : ready_flash_flag 1 !!!\n", __func__);
        return false;
    }
    //ret = call_helper_method_final(NULL, NULL, RESET_MODEM);
    if(ret == ERROR)
    {
        FIBO_LOG_INFO("[%s] : modem_stae 0 !!!\n", __func__);
        return true; //contine call
    }
    else
    {
        flag.type = SET;
        flag.flag_arry[REBOOTFLAG] = 1;
        flag.flag_arry[READYFLASHFLAG] = -1;
        flag.flag_arry[PORTSTATEFLAG] = -1;
        (void)get_set_reboot_flag(flag);
        FIBO_LOG_INFO("[%s] : call_helper_method_final 1 !!!\n", __func__);
        return false;
    }
}

gboolean get_port_state(e_port_state *state)
{
    e_port_state portstate = NO_PORT;
    gboolean ret = false;
    gchar mesg_resp[128] = {0};
    g_flags flag;
    //call_helper_func check port
    ret = call_helper_method_final(NULL, mesg_resp, GET_PORT_STATE);
    if(ret == ERROR)
    {
        FIBO_LOG_INFO("[%s]:call_helper_method_final() error\n", __func__);
        return false;
    }
    FIBO_LOG_INFO("[%s]:call_helper_method_final() ok:%s\n", __func__, mesg_resp);
    if(strstr(mesg_resp, "flashport"))
    {
        portstate = FLASH_PORT;
        FIBO_LOG_INFO("[%s]:flashport\n", __func__);
    }
    else if(strstr(mesg_resp, "normal"))
    {
        portstate = NORMAL_PORT;
        FIBO_LOG_INFO("[%s]:normal\n", __func__);
    }
    else if(strstr(mesg_resp, "fastboot"))
    {
        portstate = FASTBOOT_PORT;
        FIBO_LOG_INFO("[%s]:fastboot\n", __func__);
    }
    else if(strstr(mesg_resp, "noport"))
    {
        portstate = NO_PORT;
        FIBO_LOG_INFO("[%s]:noport\n", __func__);
    }

    switch(portstate)
    {
        case NORMAL_PORT:
            *state = NORMAL_PORT;
            ret = true;
            FIBO_LOG_INFO("[%s]:NORMAL_PORT\n", __func__);
            break;
        case FLASH_PORT:
/*            if(g_full_flags.flag_arry[REBOOTFLAG] == 0)
            {
                ret = reboot_modem();
                if(!ret)
                {
                    FIBO_LOG_INFO("[%s]:reboot_modem() error\n", __func__);
                }
            }
            else
            {
                FIBO_LOG_INFO("[%s]:%d\n", __func__,__LINE__);
                ret = true;
            }*/
            *state = FLASH_PORT;
            ret = true;
            FIBO_LOG_INFO("[%s]:FLASH_PORT\n", __func__);
            break;
        case FASTBOOT_PORT:
            *state = FASTBOOT_PORT;
            ret = true;
            FIBO_LOG_INFO("[%s]:FASTBOOT_PORT\n", __func__);
            break;
        case NO_PORT:
            *state = NO_PORT;
            FIBO_LOG_INFO("[%s]:NO_PORT\n", __func__);
            ret = true;
            break;
        default:
            FIBO_LOG_INFO("[%s]:unknow port:%d\n", __func__, portstate);
    }

    FIBO_LOG_INFO("[%s]:return func: %d\n", __func__, *state);
    return ret;
}

gboolean xml_process(char **ap, char **modem, char **oem)
{
    char subSysid[32] = {0}; //413C8211
    fw_details fw_version;
    char package_info_xml[126];
    char *basepath = FWPACKAGE_PATH;
    flash_info checkInfo;
    FILE *g_file = NULL;
    gboolean  new_pkg = check_new_package();
    if (new_pkg == TRUE)
    {
        FIBO_LOG_INFO("[%s]:new packge find!\n", __func__);
    }
    else
    {
        FIBO_LOG_INFO("[%s]:not new packge find!\n", __func__);
    }

    find_path_of_file("FwPackageInfo.xml", basepath, package_info_xml);
    g_file = fopen(CONFIG_FILE_PATH, "r");
    if (NULL == g_file)
    {
        FIBO_LOG_INFO("FwFlashSrv file not exist, create one");
    }
    else
    {
        FIBO_LOG_INFO("FwFlashSrv file exist");
        memset(&checkInfo, 0, sizeof(flash_info));
        g_file = fopen(CONFIG_FILE_PATH, "wb");
        while(fread(&checkInfo, 1, sizeof(checkInfo), g_file) > 0);
        FIBO_LOG_INFO("FwFlashSrv file exist");
        fclose(g_file);
    }

    /*if(checkInfo.subSysId[0] != '\0')
    {
        FIBO_LOG_INFO("%x",checkInfo.subSysId[0]);
        find_fw_version(package_info_xml, "default", checkInfo.subSysId);
        FIBO_LOG_INFO("");
    }
    else*/
    {
        FIBO_LOG_INFO("%s",checkInfo.subSysId);
        find_fw_version_default(package_info_xml, "default", "default");
        FIBO_LOG_INFO("");
    }

    get_fwinfo(&fw_version);
    FIBO_LOG_INFO("md:%s ap:%s oem:%s",fw_version.fw_ver, fw_version.ap_ver, fw_version.oem_pack);
    *modem = (const char* )fw_version.fw_ver;
    *ap = (const char* )fw_version.ap_ver;
    *oem = NULL;
    /*FIBO_LOG_INFO("md:%s\nap:%s\noem:%s",modem, ap, oem?oem:"");
    if(g_file != NULL)
    {
        FIBO_LOG_INFO("");
        fclose(g_file);
    }*/
    return true;
}

gboolean flash_fw(char *ap, char *modem, char *oem)
{
    int ret = 0;
    char flashinfo[256] = {0};


    ret = xml_process(&ap, &modem, &oem);
    if(ret == false)
    {
        FIBO_LOG_INFO("[%s]:xml process error\n", __func__);
        memcpy(flashinfo, "",sizeof(""));
    }
    else
    {
        if(oem && oem[0] != '\0')
        {
            snprintf(flashinfo, 256, "ap:%s;modem:%s;oem%s", ap, modem, oem);
            FIBO_LOG_INFO("[%s]:ap:%s,modem:%s,oem%s\n", __func__, ap, modem, oem);
        }
        else
        {
            snprintf(flashinfo, 256, "ap:%s;modem:%s", ap, modem);
            FIBO_LOG_INFO("[%s]:ap:%s,modem:%s\n", __func__, ap, modem);
        }
    }



    //ret = call_helper_method_final(flashinfo, NULL, FLASH_FW_EDL);
    FIBO_LOG_INFO("[%s]:start recovery......\n", __func__);
    ret = call_helper_method_final(NULL, NULL, FLASH_FW_EDL);
    if(ret == ERROR)
    {
        FIBO_LOG_INFO("[%s]:flash error\n", __func__);
        return false;
    }

    return true;
}

void *fibo_recovery_monitor(void *arg)
{
    gboolean ret = false;
    e_port_state port_state = NO_PORT;
    e_port_state *state = &port_state;
    GMainLoop *loop;
    char *oem = NULL;
    char *ap = NULL;
    char *modem = NULL;

//    openlog("FWRecovery", LOG_CONS | LOG_PID, LOG_USER);
    FIBO_LOG_INFO("[%s]:enter recovery thread\nInit timer.....\n", __func__);
    if(!init_flash_timer())
    {
        FIBO_LOG_INFO("[%s]:init_flash_timer error\n", __func__);
    }

    FIBO_LOG_INFO("[%s]:regester intresting signal......", __func__);
    ret = regester_interesting_siganl();
    if (!ret)
    {
        FIBO_LOG_INFO("[%s]:regester_interesting_siganl() error\n", __func__);
    }

    FIBO_LOG_INFO("[%s]:star call get_port_state()\n", __func__);
    ret = get_port_state(state);
    if(!ret)
    {
        FIBO_LOG_INFO("[%s]:get_port_state() error\n", __func__);
    }

    if(state && *state == NORMAL_PORT)
    {
        FIBO_LOG_INFO("[%s]:port is normal, wait modemstate envent\n", __func__);
    }
    //never enter
    else if(state && *state == FLASH_PORT && g_full_flags.flag_arry[REBOOTFLAG] == 1)
    {
        //flash
        FIBO_LOG_INFO("[%s]:is flash port,will flash fw!\n", __func__);
        ret = flash_fw(ap, modem, oem);
        if(ret == false)
        {
            FIBO_LOG_INFO("[%s]:is flash port,flash fw error!\n", __func__);
        }
    }
    else if(state && *state == FLASH_PORT && g_full_flags.flag_arry[REBOOTFLAG] == 0)
    {
        FIBO_LOG_INFO("[%s]:flag is 0,reboot is process\n", __func__);
        ret = flash_fw(ap, modem, oem);
        if(ret == false)
        {
            FIBO_LOG_INFO("[%s]:is flash port,flash fw error!\n", __func__);
        }
        //reboot_modem();
    }
    else if(state && *state == NO_PORT)
    {
        //add timer 5min
        if(!start_flash_timer(5))
        {
            FIBO_LOG_INFO("[%s]:start_flash_timer error\n", __func__);
        }
        ret = true;
    }

    return (void *)NULL;
}

void fibo_firmware_recovery_run()
{
    pthread_t ptid;
    pthread_create(&ptid, NULL, &fibo_recovery_monitor, NULL);
    FIBO_LOG_INFO("[%s] Recovery thread creat!\n", __func__);
}
/*
 * recovery end
 * */

static gboolean sim_status_handler(FibocomGdbusHelper *object, const char *value, gpointer userdata)
{
    e_error_code status;
    char port_status[32] = {0};

    FIBO_LOG_INFO("sim_status_handler invoked! %s \n", value);

    if (NULL != strstr(value, "mccmnc changed"))
    {
        FIBO_LOG_INFO("sim card mccmnc changed");
        g_usleep (1000 * 1000 * 5);

        status = check_port_state(port_status);
        if (ERROR == status)
        {
            FIBO_LOG_ERROR("get port state failed");
            return TRUE;
        }
        else
        {
            if (NULL == strstr(port_status, "normalport"))
            {
                FIBO_LOG_ERROR("port state is abnormal, no need to handle");
                return TRUE;
            }
            else
            {
                fw_update();
            }
        }
    }

#if 0
    if (NULL != strstr(value, "removed"))
    {
        FIBO_LOG_INFO("no need to handle");
        return TRUE;
    }

    status = check_port_state(port_status);
    if (ERROR == status)
    {
        FIBO_LOG_ERROR("get port state failed");
        return TRUE;
    }
    else
    {
        if (NULL == strstr(port_status, "normalport"))
        {
            FIBO_LOG_ERROR("port state is abnormal, no need to handle");
            return TRUE;
        }
    }

    if (NULL != strstr(value, "mccmnc changed"))
    {
        FIBO_LOG_INFO("sim card mccmnc changed");
        fw_update();
    }
#endif
    return TRUE;
}

unsigned char find_ini(const char *filename, const char *section, const char *key, unsigned long long *section_pos, unsigned long long *key_pos)
{
    FILE *fpr = NULL;
    unsigned long long i = 0;
    char sLine[1024] = {0};
    char *wTmp = NULL;
    unsigned char flag = 0;

    fpr = fopen(filename, "r");
    if (NULL == fpr)
    {
        FIBO_LOG_ERROR("can't open file");
        return -1;
    }

    while(NULL != fgets(sLine, 1024, fpr))
    {
        if(*sLine == '[')
        {
            if(strncmp(section, sLine+1, strlen(section)) == 0)
            {
                *section_pos = i;
                ++i;
                flag = 1; //get section
                if (key == NULL)
                {
                    goto END;
                }

                while(NULL != fgets(sLine, 1024, fpr))
                {
                    if(*sLine == '[')
                    {
                        goto END;
                    }
                    else
                    {
                        if(strncmp(key, sLine, strlen(key)) == 0)
                        {
                            *key_pos = i;
                            flag = 2; //get key
                        }
                    }

                    ++i;
                }
                goto END;
            }
        }

        ++i;
    }

END:
    fclose(fpr);
    FIBO_LOG_INFO("find ini flag: %d", flag);

    if (2 == flag)
    {
        FIBO_LOG_INFO("get key success");
        return 0;
    }
    else
    {
        FIBO_LOG_ERROR("get key failed");
        return -1;
    }
}

int get_keyString(const char *filename, const char *section, const char *key, char *result)
{
    FILE *fpr = NULL;
    unsigned long long section_pos;
    unsigned long long key_pos;
    unsigned long long i = 0;
    char *wTmp = NULL;
    char sLine[1024] = {0};

    if(find_ini(filename, section, key, &section_pos, &key_pos) != 0)
    {
        return -1;
    }

    fpr = fopen(filename, "r");
    if (NULL == fpr)
    {
        FIBO_LOG_ERROR("can't open file");
        return -1;
    }

    while (NULL != fgets(sLine, 1024, fpr))
    {
        if(i == key_pos)
        {
            wTmp = strchr(sLine, '=');
            ++wTmp;
            while (isspace(*wTmp))
            {
                ++wTmp;
            }
            strncpy(result, wTmp, strlen(wTmp));
            result[strlen(wTmp)-2] = '\0';
        }

        ++i;
    }

    fclose(fpr);
    return 0;
}

void log_init()
{
    int ret;
    char result[8] = {0};

    FIBO_LOG_INFO("entry");

    ret = get_keyString(INI_PATH, "BASE_CONFIG", "LOG_LV", result);
    if (ret)
    {
        FIBO_LOG_ERROR("get ini config failed");
    }
    else
    {
        FIBO_LOG_INFO("log level is %s", result);
        g_debug_level = atoi(result);
        FIBO_LOG_INFO("debug level is set to %d", g_debug_level);
    }

}

int check_port_state(char *state)
{
    e_error_code ret;

    ret = call_helper_method_final(NULL, state, GET_PORT_STATE);
    if (ERROR == ret)
    {
        FIBO_LOG_ERROR("call helper to get port state failed");
        return ret;
    }

    return ret;
}

bool dbus_servie_is_ready()
{
    char *name = NULL;

    name = g_dbus_proxy_get_name_owner((GDBusProxy*)(proxy));
    if (name != NULL)
    {
        FIBO_LOG_INFO("get owner name");
        return TRUE;
    }
    else
    {
        FIBO_LOG_ERROR("name is null");
        return FALSE;
    }
}

int main(int argc, char *argv[])
{
    flash_info checkInfo;
    GDBusConnection *conn = NULL;
    GError *connerror = NULL;
    GError *proxyerror = NULL;
    bool new_pkg = FALSE;
    bool need_flash_flag = FALSE;
    int ret;
    char port_status[32] = {0};
    e_error_code status = UNKNOWPROJECT;
    FILE *g_file = NULL;

    log_init();

    FIBO_LOG_INFO("FW Flash service entry");
    openlog("FWFlashService", LOG_CONS | LOG_PID, LOG_USER);

    g_file = fopen(CONFIG_FILE_PATH, "r+");
    if (NULL == g_file)
    {
        FIBO_LOG_INFO("FwFlashSrv file not exist, create one");

        memset(&checkInfo, 0, sizeof(flash_info));
        g_file = fopen(CONFIG_FILE_PATH, "w");

        fwrite(&checkInfo, sizeof(flash_info), 1, g_file);
        fclose(g_file);
    }
    else
    {
        FIBO_LOG_INFO("FwFlashSrv file exist");
        fclose(g_file);
    }

    conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM,NULL,&connerror);
    if(connerror != NULL)
    {
        FIBO_LOG_ERROR("g_bus_get_sync connect error! %s \n",connerror->message);
        g_error_free(connerror);
        goto FINISH;
    }

    proxy = fibocom_gdbus_helper_proxy_new_sync(conn,G_DBUS_PROXY_FLAGS_NONE,"com.fibocom.helper","/com/fibocom/helper",NULL,&proxyerror);
    if(proxy == NULL)
    {
        FIBO_LOG_ERROR("helper_com_fibocom_helper_proxy_new_sync error! %s \n",proxyerror->message);
        g_error_free(proxyerror);
        goto FINISH;
    }

    fibo_firmware_recovery_run();
    gMainloop = g_main_loop_new(NULL, FALSE);

    status = check_port_state(port_status);
    if (ERROR == status)
    {
        FIBO_LOG_ERROR("get port state failed");
    }
    else
    {
        if (strstr(port_status, "normalport") != NULL)
        {
            FIBO_LOG_INFO("port state is normal, start FW flash flow");

            new_pkg = check_new_package();
            if (new_pkg == TRUE)
            {
                fw_update();
            }
            else
            {
                need_flash_flag = check_flash_flag();
                if (need_flash_flag == TRUE)
                {
                    fw_update();
                }
                else
                {
                    check_imei_change();
                }
            }

            g_signal_connect(proxy, "simcard-change", G_CALLBACK(sim_status_handler),NULL);
            g_signal_connect(proxy, "cellular-state",G_CALLBACK(modem_status_handler),NULL);
            g_signal_connect(proxy,"fastboot-status",G_CALLBACK(fastboot_status_handler),NULL);
        }
    }

    g_main_loop_run(gMainloop);
    g_object_unref(proxy);

FINISH:
    closelog();
    if (g_file != NULL)
    {
        fclose(g_file);
    }

    return 0;
}
