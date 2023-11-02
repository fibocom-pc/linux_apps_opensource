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
#include <fcntl.h>
#include <sys/inotify.h>
#include "fibo_flash_main.h"
#include "fibocom-helper-gdbus-generated.h"
#include "safe_str_lib.h"


#define BUF_LEN (1024 * (sizeof(struct inotify_event) + NAME_MAX + 1))

static const char *allow_cmds[CMD_MAX_LIST] = {
    "dmidecode -t 2 | grep 'Product Name' | cut -d ':' -f 2",
    "dmidecode -t 1 | grep 'SKU Number' | cut -d ':' -f 2"
};

mdmver_details g_curmdm_versions;
static GMainLoop *gMainloop = NULL;
FibocomGdbusHelper *proxy;
char g_strType[256] = {0};
int g_debug_level = LOG_DEBUG;
e_flow_state flash_flow_state = FW_UPDATE_FLOW_UNLOCK;

/*
 * recovery:
 * */
static const recovery_list oem_vid_pid_arry[] = {
        "5106","413c,8213","413c8213",
        "5125","413c,8215","413c8215"
};

/*
 g_full_flags.flag_arry[0]:   9008->reboot -> flag = 1
 g_full_flags.flag_arry[1]:   9008->reboot->reboot_flag =1 > ready_falsh_flag = 1-> flash
 g_full_flags.flag_arry[2]:    modem port state:0 nopoert 1: flashport/fastbootport/normalport
*/
g_flags g_full_flags = {UNKOWN_TYPE, 0, 0, 0};
int reboot_count = 0;
struct sigevent evp;
struct itimerspec ts;
struct itimerspec newts;
timer_t timer;
gboolean reboot_modem(gpointer data);
static int flash_flag = 0;
pthread_mutex_t mutex;

void normalport_process();
void flashport_process();
void noport_process();
void fastbootport_process();
gboolean flash_fw_with_recovery(char *ap, char *modem, char *oem);

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

    fibocom_gdbus_helper_call_send_mesg_sync(proxy, atcommand_in, &atcommand_out, NULL, &callError);
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
        FIBO_LOG_INFO("get current full fw versions success");
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
    char defaultDev[16] = "dev:default;";
    char strOem[32] = "oem:";
    char str_fw[128] = "";
    bool need_update = FALSE;

    if (NULL == fw_ver->dev_pack)
    {
        FIBO_LOG_INFO("parse dev from xml is null");
        if (0 == strncmp(curmdm_ver->dev_pack, curmdm_ver->oem_pack, 4))
        {
            FIBO_LOG_INFO("no need update");
            return FALSE;
        }

        if (NULL == fw_ver->oem_pack)
        {
            FIBO_LOG_ERROR("param is null, can't flash default dev");
            return FALSE;
        }

        strcat(strOem, fw_ver->oem_pack);
        strcat(str_fw, strOem);
        strncat(str_fw, ";", 1);
        strcat(str_fw, defaultDev);

        memset(g_strType, 0, sizeof(g_strType));
        strcpy(g_strType, str_fw);
        need_update = TRUE;

        FIBO_LOG_INFO("send flash fw str:[%s] to helper", g_strType);
    }

   if((NULL == strstr(curmdm_ver->dev_pack, fw_ver->dev_pack)) && (0 != strlen(curmdm_ver->dev_pack)))
    {
        strcat(strDev, fw_ver->dev_pack);
        strncat(strDev, ";", 1);

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
    char defaultDev[16] = "dev:default;";
    bool ap_need_update = FALSE;
    bool md_need_update = FALSE;
    bool oem_need_update = FALSE;
    bool op_need_update = FALSE;
    bool dev_need_update = FALSE;
    int len;

    if (NULL != fw_ver->ap_ver)
    {
        if((NULL == strstr(curmdm_ver->ap_ver, fw_ver->ap_ver)) && (0 != strlen(curmdm_ver->ap_ver)))
        {
            strcat(strAp, fw_ver->ap_ver);
            strcat(str_fw, strAp);
            strncat(str_fw, ";", 1);
            ap_need_update = TRUE;
        }
    }

    if (NULL != fw_ver->fw_ver)
    {
        if((NULL == strstr(curmdm_ver->fw_ver, fw_ver->fw_ver)) && (0 != strlen(curmdm_ver->fw_ver)))
        {
            strcat(strMd, fw_ver->fw_ver);
            strcat(str_fw, strMd);
            strncat(str_fw, ";", 1);
            md_need_update = TRUE;
        }
    }

    if (NULL != fw_ver->oem_pack)
    {
        if((NULL == strstr(curmdm_ver->oem_pack, fw_ver->oem_pack)) && (0 != strlen(curmdm_ver->oem_pack)))
        {
            strcat(strOem, fw_ver->oem_pack);
            strcat(str_fw, strOem);
            strncat(str_fw, ";", 1);
            oem_need_update = TRUE;
        }
    }

    if (NULL != fw_ver->cust_pack)
    {
        if((NULL == strstr(curmdm_ver->cust_pack, fw_ver->cust_pack)) && (0 != strlen(curmdm_ver->cust_pack)))
        {
            strcat(strOp, fw_ver->cust_pack);
            strcat(str_fw, strOp);
            strncat(str_fw, ";", 1);
            op_need_update = TRUE;
        }
    }

    if (NULL != fw_ver->dev_pack)
    {
        if((NULL == strstr(curmdm_ver->dev_pack, fw_ver->dev_pack)) && (0 != strlen(curmdm_ver->dev_pack)))
        {
            strcat(strDev, fw_ver->dev_pack);
            strcat(str_fw, strDev);
            strncat(str_fw, ";", 1);
            dev_need_update = TRUE;
        }
    }
    else
    {
        FIBO_LOG_INFO("parse dev from xml is null");

        if (TRUE == oem_need_update)
        {
            strcat(str_fw, defaultDev);
            dev_need_update = TRUE;
        }
        else
        {
            if ((NULL != fw_ver->oem_pack) && (0 != strncmp(curmdm_ver->dev_pack, curmdm_ver->oem_pack, 4)))
            {
                strcat(strOem, fw_ver->oem_pack);
                strcat(str_fw, strOem);
                strncat(str_fw, ";", 1);
                strcat(str_fw, defaultDev);
                dev_need_update = TRUE;
            }
        }
#if 0
/*        if (NULL == fw_ver->oem_pack)
        {
            FIBO_LOG_ERROR("param is null, can't flash default dev");
            dev_need_update = FALSE;
        }
        else
        {
            if (TRUE == oem_need_update)
            {
                strcat(str_fw, defaultDev);
                dev_need_update = TRUE;
            }
            else
            {
                if (0 != strncmp(curmdm_ver->dev_pack, curmdm_ver->oem_pack, 4))
                {
                    strcat(strOem, fw_ver->oem_pack);
                    strcat(str_fw, strOem);
                    strncat(str_fw, ";", 1);
                    strcat(str_fw, defaultDev);
                    dev_need_update = TRUE;
                }
            }
        } */
#endif
    }

    FIBO_LOG_INFO("flash fw is:%s", str_fw);
    memcpy(g_strType, str_fw, sizeof(str_fw));
    FIBO_LOG_INFO("send flash fw str:[%s] to helper", g_strType);

    if ((TRUE == ap_need_update) || (TRUE == md_need_update) || (TRUE == oem_need_update) ||
        (TRUE == op_need_update) || (TRUE == dev_need_update))
    {
        FIBO_LOG_INFO("need to update");
        return TRUE;
    }
    else
    {
        FIBO_LOG_INFO("no need to update");
        return FALSE;
    }
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
    e_error_code ret = OK;
    int retry = 0;
    int i;

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

        for (i = 0; i < 3; i++)
        {
            g_usleep(1000 * 200);
            ret = call_helper_method_final(g_strType, NULL, FLASH_FW);
            if (ERROR == ret)
            {
                FIBO_LOG_ERROR("call_helper_method_final error, to retry");
                continue;
            }
            else
            {
                FIBO_LOG_ERROR("call_helper_method_final ok");
                break;
            }
        }

        if (ERROR == ret)
        {
            FIBO_LOG_ERROR("call_helper_method_final error");
            set_package_flag(FLASH_FAIL);
        }

#if 0
        ret = call_helper_method_final(g_strType, NULL, FLASH_FW);
        if (ERROR == ret)
        {
            FIBO_LOG_ERROR("call_helper_method_final error");
            set_package_flag(FLASH_FAIL);

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
#endif
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
    char ac_present[40] = "/sys/class/power_supply/AC/online";
    int ret = 0;
    int fd;
    int fp;
    char capacity[10] = {0};
    char ac_online[8] = {0};
    int bat_threshold;
    int power_limit;
    char result[8] = {0};

    FIBO_LOG_INFO("check current battery capacity whether satisfy update");

    fp = open(ac_present, O_RDONLY);
    if (0 > fp)
    {
        FIBO_LOG_ERROR("cannot open file: %s", ac_present);
    }
    else
    {
        read(fp, ac_online, 5);
        FIBO_LOG_INFO("ac online: %s", ac_online);
        close(fp);

        if (1 == atoi(ac_online))
        {
            FIBO_LOG_INFO("AC is present, to update");
            return TRUE;
        }
    }

    ret = get_keyString(INI_PATH, "BASE_CONFIG", "POWER_LIMIT",result);
    if (ret)
    {
        FIBO_LOG_ERROR("get ini config failed");
        return TRUE;
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
        return TRUE;
    }
    else
    {
        bat_threshold = atoi(result);
        FIBO_LOG_INFO("battery threshold is %d", atoi(result));
    }

    fd = open(path, O_RDONLY);
    if (0 > fd)
    {
        FIBO_LOG_ERROR("cannot open file: %s", path);
        return TRUE;
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

    status = get_subSysID(subSysid);
    if (ERROR == status)
    {
        FIBO_LOG_ERROR("failed to get subsysid");
        get_subSysID_from_file(subSysid);
    }
    else
    {
        FIBO_LOG_INFO("get subSysid:%s", subSysid);

        if (0 != strlen(subSysid))
        {
            FIBO_LOG_INFO("subSysid is not null, save it");
            save_cur_subSysid(subSysid);
        }
    }

    if(0 == strlen(subSysid))
    {
        FIBO_LOG_ERROR("get subSysID failed, do not flash");
        return;
    }

    status = get_mccmnc(mccmncid);
    if (status == ERROR)
    {
        FIBO_LOG_ERROR("failed to get mccmnc");
    }

    if (update_need_sim_enable())
    {
        if (0 == strlen(mccmncid))
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

    status = get_modem_version_info();
    if (ERROR == status)
    {
        FIBO_LOG_WARNING("failed to get modem current full versions");
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
            reset_update_retry();
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
            reset_update_retry();
        }
    }
    else if (FORCE == update_option)
    {
        FIBO_LOG_INFO("FW update is force flash, need to flash full packages");

        memcpy(&g_curmdm_versions.ap_ver, "default", strlen("default")+1);
        memcpy(&g_curmdm_versions.fw_ver, "default", strlen("default")+1);
        memcpy(&g_curmdm_versions.cust_pack, "default", strlen("default")+1);
        memcpy(&g_curmdm_versions.oem_pack, "default", strlen("default")+1);
        memcpy(&g_curmdm_versions.dev_pack, "default", strlen("default")+1);

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
    if ((FLASH_START == pkg_flag) || (DECOMPRESS_SUCCESS == pkg_flag))
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
            FIBO_LOG_INFO("decompress package success");
            set_package_flag(DECOMPRESS_SUCCESS);
            remove(NEW_PACKAGE_PATH);
        }

        new_pkg = TRUE;
        fclose(zip_file);
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
            FIBO_LOG_INFO("[%s]current flags is :%d,%d,%d\n, value flags is :%d,%d,%d\n",__func__,
                          g_full_flags.flag_arry[0],
                          g_full_flags.flag_arry[1],
                          g_full_flags.flag_arry[2],
                          value.flag_arry[0],
                          value.flag_arry[1],
                          value.flag_arry[2]);
            for(i = 0; i < 3; i++)
            {
                if(value.flag_arry[i] == -1)
                {
                    continue;
                }
                else
                {
                    pthread_mutex_lock(&mutex);
                    g_full_flags.flag_arry[i] = value.flag_arry[i];
                    pthread_mutex_unlock(&mutex);
                }

            }

            FIBO_LOG_INFO("[%s]:Now set/get flags is :%d,%d,%d\n",__func__,
                          g_full_flags.flag_arry[0],
                          g_full_flags.flag_arry[1],
                          g_full_flags.flag_arry[2]);
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
            g_timeout_add(12000,(GSourceFunc)reboot_modem, NULL);
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
        FIBO_LOG_INFO("[%s]: >>>>--it_value.tv_sec:%ld,it_value.tv_nsec:%ld,it_interval.tv_sec:%ld, it_interval.tv_nsec:%ld--------<<<<\n",
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
    g_flags flag;
    FIBO_LOG_INFO("flash_status_handler  invoked! %s \n", value);
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
        else if(strstr(value,"flash ok"))
        {
            flash_flag = 0;
            flag.type = SET;
            flag.flag_arry[REBOOTFLAG] = 0;
            flag.flag_arry[READYFLASHFLAG] = 0;
            flag.flag_arry[PORTSTATEFLAG] = NO_PORT;
            (void)get_set_reboot_flag(flag);
        }
        else if(strstr(value,"flash error"))
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

gboolean fastboot_reboot_callback()
{
    int ret = false;
    int i = 0;
    e_port_state state = UNKNOW_PORT;
    //port is narml:1   flash port:2 dump:4 , not need reset modem
    FIBO_LOG_INFO("[%s] : flags :%d,%d,%d!!!\n", __func__,
                  g_full_flags.flag_arry[REBOOTFLAG],
                  g_full_flags.flag_arry[READYFLASHFLAG],
                  g_full_flags.flag_arry[PORTSTATEFLAG]);

    if(g_full_flags.flag_arry[PORTSTATEFLAG] != FASTBOOT_PORT)
    {
        FIBO_LOG_NOTICE("[%s] : Not need rest modem, now is not fastboot port\n", __func__);
        return false;
    }

    for(i = 0; i < 3; i++)
    {
        ret = call_helper_method_final(NULL, NULL, RESET_MODEM_HW);
        if(ret == ERROR)
        {
            FIBO_LOG_ERROR("[%s] : rest modem error of call_helper_method_final!!\n", __func__);
        }
        else
        {
            FIBO_LOG_NOTICE("[%s] : rest modem OK\n", __func__);
            break;
        }
    }

    return false;
}

void normalport_process()
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
    flag.flag_arry[PORTSTATEFLAG] = NORMAL_PORT;
    (void)get_set_reboot_flag(flag);

    FIBO_LOG_NOTICE("[%s][%d]: will check OEM\n", __func__, __LINE__)
    for(int i = 0; i < 3; i++)
    {
        ret = comparative_oem_version();
        if(ret == true)
        {
            break;
        }
        else
        {
            FIBO_LOG_ERROR("[%s][%d]:comparative_oem_version error !\n", __func__, __LINE__);
            sleep(1);
        }
    }
}
void flashport_process()
{
    g_flags      flag;
    mdmver_details fwinfo;
    int ret = 0;
    flag.type = SET;
    (void)get_fwinfo( &fwinfo);

    memset(fwinfo.oem_pack, 0, DEV_SUBSYSID_LEN);
    memset(fwinfo.ap_ver, 0, DEV_SUBSYSID_LEN);
    memset(fwinfo.fw_ver, 0, DEV_SUBSYSID_LEN);
    if(g_full_flags.flag_arry[REBOOTFLAG] == 0)
    {
        ret = stop_flash_timer();
        if(!ret)
        {
            perror("timer_settime error\n");
            FIBO_LOG_INFO("[%s]: >>>>-----stop_flash_timer error-----<<<<\n", __func__);
        }

        flag.flag_arry[REBOOTFLAG] = -1;
        flag.flag_arry[READYFLASHFLAG] = -1;
        flag.flag_arry[PORTSTATEFLAG] = FLASH_PORT;
        (void)get_set_reboot_flag(flag);
        FIBO_LOG_INFO("[%s]: >>>>-REBOOTFLAG is 0-----<<<<\n", __func__);
        //now is flashport, but reboot flags is 0, reboot modem with helper of gpio reset
        reboot_modem(NULL);
    }
    else if(g_full_flags.flag_arry[REBOOTFLAG] == 1)
    {
        FIBO_LOG_INFO("[%s]: >>>>-REBOOTFLAG is 1-----<<<<\n", __func__);
        //stop timer
        ret = stop_flash_timer();
        if(!ret)
        {
            perror("timer_settime error\n");
            FIBO_LOG_INFO("[%s]: >>>>-----stop_flash_timer error-----<<<<\n", __func__);
        }

        flag.flag_arry[REBOOTFLAG] = -1;
        flag.flag_arry[READYFLASHFLAG] = 1;
        flag.flag_arry[PORTSTATEFLAG] = FLASH_PORT;
        (void)get_set_reboot_flag(flag);
        flash_fw_with_recovery(fwinfo.ap_ver, fwinfo.fw_ver, fwinfo.oem_pack);
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
        flag.flag_arry[PORTSTATEFLAG] = FLASH_PORT;
        (void)get_set_reboot_flag(flag);
        flash_fw_with_recovery(fwinfo.ap_ver, fwinfo.fw_ver, fwinfo.oem_pack);
    }
}
void noport_process()
{
    g_flags      flag;
    flag.type = SET;
    int ret = 0;

    //no port, add 3min timer
    ret = start_flash_timer(3);
    if(!ret)
    {
        perror("start timer error\n");
        FIBO_LOG_INFO("start timer error!\n");
    }
    else
    {
        FIBO_LOG_INFO("[%s]:Now is noport start 3min timer OK\n", __func__);
    }
    reboot_count = 0;
    flag.flag_arry[REBOOTFLAG] = -1;
    flag.flag_arry[READYFLASHFLAG] = -1;
    flag.flag_arry[PORTSTATEFLAG] = NO_PORT;
    (void)get_set_reboot_flag(flag);
}
void fastbootport_process()
{
    g_flags      flag;
    flag.type = SET;
    int ret = 0;

    FIBO_LOG_INFO("[%s]:Now is fastbootport\n", __func__);
    ret = stop_flash_timer();
    if(!ret)
    {
        perror("stop_flash_timer error\n");
        FIBO_LOG_INFO("[%s]: >>>>-----stop_flash_timer error-----<<<<\n", __func__);
    }

    flag.flag_arry[REBOOTFLAG] = 0;
    flag.flag_arry[READYFLASHFLAG] = 0;
    flag.flag_arry[PORTSTATEFLAG] = FASTBOOT_PORT;
    (void)get_set_reboot_flag(flag);

    FIBO_LOG_NOTICE("[%s]:Now is fastboot port, will >>>---start 3min timer---<<<...[%s-%s]\n", __func__, __DATE__, __TIME__);
    //add timer 3min
    g_timeout_add(3*60*1000,(GSourceFunc)fastboot_reboot_callback, NULL);
}

void dumpport_process()
{
    g_flags      flag;
    flag.type = SET;
    int ret = 0;

    FIBO_LOG_INFO("[%s]:Now is dump port\n", __func__);
    ret = stop_flash_timer();
    if(!ret)
    {
        perror("stop_flash_timer error\n");
        FIBO_LOG_INFO("[%s]: >>>>-----stop_flash_timer error-----<<<<\n", __func__);
    }

    flag.flag_arry[REBOOTFLAG] = 0;
    flag.flag_arry[READYFLASHFLAG] = 0;
    flag.flag_arry[PORTSTATEFLAG] = DUMP_PORT;
    (void)get_set_reboot_flag(flag);
}
//fw switch code
static gboolean fastboot_status_handler(FibocomGdbusHelper *object, const char *value, gpointer userdata)
{
    e_error_code ret;
    int retry = 0;

    if(NULL == value)
    {
        FIBO_LOG_INFO("Value is null\n");
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
    else if(strstr(value,"flash ok"))
    {
        FIBO_LOG_INFO("fastboot flash success");
        set_package_flag(FLASH_SUCCESS);
    }
    else if(strstr(value,"flash fail"))
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
                normalport_process();
                break;
            case FLASH_PORT:
                flashport_process();
                break;
            case NO_PORT:
                noport_process();
                break;
            case FASTBOOT_PORT:
                fastbootport_process();
                break;
            case DUMP_PORT:
                dumpport_process();
                break;
            default:
                FIBO_LOG_INFO("[%s]:Error port type\n", __func__);
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

gboolean reboot_modem(gpointer data)
{
    g_flags flag;
    FIBO_LOG_INFO("[%s] :enter!!!\n", __func__);
    int ret = 0;
    FIBO_LOG_INFO("[%s] : ready_flash_flag :%d,%d,%d!!!\n", __func__,
                  g_full_flags.flag_arry[REBOOTFLAG],
                  g_full_flags.flag_arry[READYFLASHFLAG],
                  g_full_flags.flag_arry[PORTSTATEFLAG]);

    /* g_full_flags.flag_arry[PORTSTATEFLAG]:
    * 0: noport
    * 1: normal port
    * 2: flash port
    * 3: fastboot port
    * 4: dump port
    */
    if(reboot_count == 15 ||
    (g_full_flags.flag_arry[READYFLASHFLAG]  == 1 && g_full_flags.flag_arry[PORTSTATEFLAG] == FLASH_PORT))
    {
        reboot_count = 0;
        FIBO_LOG_INFO("[%s] : ready_flash_flag 1 or reboot_flag is 15 or normal port\n"
                      "set reboot_flag to 0......\n", __func__);
        return false;
    }

    reboot_count++;
    FIBO_LOG_NOTICE("[%s][%d]: Now is [%d] reset module !!!\n", __func__, __LINE__, reboot_count);
    ret = call_helper_method_final(NULL, NULL, RESET_MODEM_HW);
    if(ret == ERROR)
    {
        FIBO_LOG_ERROR("[%s] : call_helper_method_final error !!!\n", __func__);
        //continue call
        return true;
    }
    else
    {
        flag.type = SET;
        flag.flag_arry[REBOOTFLAG] = 1;
        flag.flag_arry[READYFLASHFLAG] = -1;
        flag.flag_arry[PORTSTATEFLAG] = -1;
        (void)get_set_reboot_flag(flag);
        FIBO_LOG_NOTICE("[%s] : call_helper_method_final OK !!!\n", __func__);
        //call reboot until 9008 is exit!
        return true;
    }
}

gboolean get_port_state(e_port_state *state)
{
    e_port_state portstate = UNKNOW_PORT;
    gboolean ret = false;
    gchar mesg_resp[128] = {0};
    g_flags flag;
    //call_helper_func check port
    ret = call_helper_method_final(NULL, mesg_resp, GET_PORT_STATE);
    if(ret == ERROR)
    {
        FIBO_LOG_ERROR("[%s]:call_helper_method_final() error\n", __func__);
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
    else if(strstr(mesg_resp, "dump"))
    {
        portstate = DUMP_PORT;
        FIBO_LOG_INFO("[%s]:Dump port\n", __func__);
    }

    switch(portstate)
    {
        case NORMAL_PORT:
            *state = NORMAL_PORT;
            ret = true;
            FIBO_LOG_INFO("[%s]:NORMAL_PORT\n", __func__);
            break;
        case FLASH_PORT:
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

gboolean recovery_get_version_of_xml(char **ap, char **modem, char **oem, char *subsys_id)
{
    char subSysid[32] = {0};
    fw_details fw_version = {0,0,0,0,0};
    char package_info_xml[128] = {0};
    char *basepath = FWPACKAGE_PATH;
    flash_info checkInfo;
    FILE *g_file = NULL;
    int count = 0;

    memset(checkInfo.subSysId, 0, DEV_SUBSYSID_LEN);

    for(count = 0; count < 3; count++)
    {
        find_path_of_file("FwPackageInfo.xml", basepath, package_info_xml);
        if(package_info_xml[0] == '\0')
        {
            FIBO_LOG_ERROR("[%s][%d]: package_info_xml is  NULL, retry!!\n", __func__, __LINE__);
            //package is not exit, wait 2s and rerty
            sleep(2);
            continue;
        }
        else
        {
            FIBO_LOG_NOTICE("[%s][%d]: package_info_xml is not NULL:[%s], break!!\n", __func__, __LINE__, package_info_xml);
            break;
        }
        FIBO_LOG_ERROR("[%s][%d]: rety finashed, but package_info_xml is NULL!!\n", __func__, __LINE__);
        return false;
    }

    if(subsys_id != NULL && *subsys_id)
    {
        memcpy(checkInfo.subSysId, subsys_id, DEV_SUBSYSID_LEN);
        FIBO_LOG_NOTICE("[%s][%d]: subsys_id is not NULL: %s\n", __func__, __LINE__, checkInfo.subSysId);
    }
    else
    {
        FIBO_LOG_ERROR("[%s][%d]: subsys_id is  NULL or *subsys_id is NULL!!\n", __func__, __LINE__);
    }

    if(checkInfo.subSysId[0] != '\0')
    {
        FIBO_LOG_NOTICE("[%s][%d]: find fw version from xml of subSysId\n", __func__, __LINE__);
        find_fw_version(package_info_xml, "default", checkInfo.subSysId);
        FIBO_LOG_NOTICE("[%s][%d]: find fw version from xml of subSysId >>OK<<\n", __func__, __LINE__);
    }
    else
    {
        FIBO_LOG_NOTICE("[%s][%d]: find fw version from xml of default\n", __func__, __LINE__);
        find_fw_version_default(package_info_xml, "default", "default");
        FIBO_LOG_NOTICE("[%s][%d]: find fw version from xml of default >>OK<<\n", __func__, __LINE__);
    }

    FIBO_LOG_NOTICE("[%s][%d]: start get_fwinfo!\n", __func__, __LINE__);
    get_fwinfo(&fw_version);
    if((fw_version.ap_ver != NULL) && (fw_version.fw_ver != NULL))
    {
        FIBO_LOG_NOTICE("[%s][%d]: get_fwinfo >>OK<<\n", __func__, __LINE__);
        FIBO_LOG_NOTICE("md:%s,ap:%s\n",fw_version.fw_ver, fw_version.ap_ver);
        memcpy(*modem, fw_version.fw_ver, strlen(fw_version.fw_ver) + 1);
        memcpy(*ap, fw_version.ap_ver, strlen(fw_version.ap_ver) + 1);
        if(fw_version.oem_pack != NULL)
        {
            FIBO_LOG_NOTICE("oem:%s\n", fw_version.oem_pack);
            memcpy(*oem, fw_version.oem_pack, strlen(fw_version.oem_pack) + 1);
        }
        else if(checkInfo.subSysId[0] != '\0' && fw_version.oem_pack == NULL)
        {
            FIBO_LOG_NOTICE("ERROR: oem is NULL\n");
            return false;
        }

        return true;
    }
    else
    {
        FIBO_LOG_ERROR("[%s][%d]:ERROR of get_fwinfo\n", __func__, __LINE__);
        return false;
    }
}

gboolean flash_fw_with_recovery(char *ap, char *modem, char *oem)
{
    int ret = 0;
    char flashinfo[256] = {0};

    ret = recovery_get_version_of_xml(&ap, &modem, &oem, NULL);
    if(ret == false)
    {
        FIBO_LOG_ERROR("[%s]:Get Version of xml error\n", __func__);
    }
    else
    {
        if(ap && *ap && modem && *modem)
        {
            if(check_power_status() == false)
            {
                FIBO_LOG_INFO("[%s]:Need recovery, But the battery is Low!!!\n", __func__);
                return false;
            }

            snprintf(flashinfo, 256, "ap:%s;md:%s;", ap, modem);
            FIBO_LOG_NOTICE("[%s]:ap:%s,modem:%s, flash_info:%s\n", __func__, ap, modem, flashinfo);

            FIBO_LOG_INFO("[%s]:start recovery......\n", __func__);
            ret = call_helper_method_final(flashinfo, NULL, FLASH_FW_EDL);
            if(ret == ERROR)
            {
                FIBO_LOG_ERROR("[%s]:flash error\n", __func__);
                return false;
            }
            return true;
        }
        else
        {
            FIBO_LOG_NOTICE("[%s]:Version is NULL\n", __func__);
        }
    }
    return false;
}

gboolean comparative_oem_version()
{
    int ret = false;
    gchar oem_version[256] = {0};
    gchar oem_usbid[256] = {0};
    gchar flash_command[128] = {0};
    int recovery_flag = 0;
    int i = 0;
    mdmver_details versions;
    char *oem = NULL;
    char *dev = NULL;
    char *modem = NULL;
    char *ap = NULL;

    memset(versions.oem_pack, 0, DEV_SUBSYSID_LEN);
    memset(versions.dev_pack, 0, DEV_SUBSYSID_LEN);
    memset(versions.ap_ver, 0, DEV_SUBSYSID_LEN);
    memset(versions.fw_ver, 0, DEV_SUBSYSID_LEN);

    oem = versions.oem_pack;
    dev = versions.dev_pack;
    modem = versions.fw_ver;
    ap = versions.ap_ver;

    ret = call_helper_method_final(NULL, oem_version, GET_OEM_VERSION);
    if(ret == ERROR)
    {
        FIBO_LOG_ERROR("[%s][%d]:call_helper_method_final error!\n", __func__, __LINE__);
        return false;
    }

    ret = call_helper_method_final(NULL, oem_usbid, GET_OEM_ID);
    if(ret == ERROR)
    {
        FIBO_LOG_ERROR("[%s][%d]:call_helper_method_final error!\n", __func__, __LINE__);
        return false;
    }

    for(i = 0; i < sizeof(oem_vid_pid_arry) / sizeof(recovery_list); i++)
    {
        if(strncmp(oem_vid_pid_arry[i].id.id, oem_usbid, 9) == 0)
        {
            FIBO_LOG_NOTICE("[%s][%d] oemusbid find \n", __func__,__LINE__);
            recovery_get_version_of_xml(&(ap), &(modem), &(oem), oem_vid_pid_arry[i].subsysid.id);
            if(versions.oem_pack[0] != '\0')
            {
                if(strncmp(oem_version, versions.oem_pack, 4) != 0)
                {
                    sprintf(flash_command, "oem:%s;", versions.oem_pack);
                    FIBO_LOG_NOTICE("[%s][%d]Need recovery OEM:versions.oem_pack:[%s]\nNow start flash OEM....\n", __func__, __LINE__, flash_command);
                    ret = call_helper_method_final(flash_command,NULL,FLASH_FW);
                    if(ret == OK)
                    {
                        FIBO_LOG_NOTICE("[%s][%d]:call_helper_method_final OK!\n", __func__, __LINE__);
                        return true;
                    }
                    else
                    {
                        FIBO_LOG_ERROR("[%s][%d]:call_helper_method_final ERROR!\n", __func__, __LINE__);
                        return false;
                    }
                }
                else
                {
                    FIBO_LOG_NOTICE("[%s][%d]:not need recovery oem!\n", __func__, __LINE__);
                    return true;
                }

            }
            else
            {
                FIBO_LOG_ERROR("[%s][%d]OEM version is NULL\n", __func__,__LINE__);
                return false;
            }
        }
    }

    //not find oemusbid from list
    FIBO_LOG_ERROR("[%s][%d]Not find oemusbid from List\n", __func__,__LINE__);
    return true;
}

void *fibo_recovery_monitor(void *arg)
{
    gboolean ret = false;
    e_port_state port_state = UNKNOW_PORT;
    e_port_state *state = &port_state;
    GMainLoop *loop;
    mdmver_details fwinfo;
    int count = 0;
    g_flags flag;

    flag.type = SET;
    flag.flag_arry[REBOOTFLAG] = -1;
    flag.flag_arry[READYFLASHFLAG] = -1;

    memset(fwinfo.oem_pack, 0, DEV_SUBSYSID_LEN);
    memset(fwinfo.dev_pack, 0, DEV_SUBSYSID_LEN);
    memset(fwinfo.fw_ver, 0, DEV_SUBSYSID_LEN);
    memset(fwinfo.ap_ver, 0, DEV_SUBSYSID_LEN);
    gMainloop = g_main_loop_new(NULL, FALSE);
    FIBO_LOG_NOTICE("[%s]:enter recovery thread\nInit timer.....\n", __func__);
    if(!init_flash_timer())
    {
        FIBO_LOG_ERROR("[%s]:init_flash_timer error\n", __func__);
    }

    FIBO_LOG_INFO("[%s]:regester intresting signal......", __func__);
    ret = regester_interesting_siganl();
    if (!ret)
    {
        FIBO_LOG_ERROR("[%s]:regester_interesting_siganl() error\n", __func__);
    }

    FIBO_LOG_INFO("[%s]:star call get_port_state()\n", __func__);
    for (count = 0; count < 3; count++)
    {
        ret = get_port_state(state);
        if(ret)
        {
            FIBO_LOG_ERROR("[%s]:get_port_state() OK\n", __func__);
            break;
        }
        else
        {
            FIBO_LOG_ERROR("[%s]:get_port_state() error, continue....\n", __func__);
        }
        sleep(1);
    }


    if(state && *state == NORMAL_PORT)
    {
        flag.flag_arry[PORTSTATEFLAG] = NORMAL_PORT;
        (void)get_set_reboot_flag(flag);
        for(int i = 0; i < 3; i++)
        {
            ret = comparative_oem_version();
            if(ret == true)
            {
                break;
            }
            else
            {
                FIBO_LOG_ERROR("[%s][%d]:comparative_oem_version error !\n", __func__, __LINE__);
                sleep(1);
            }
        }

        FIBO_LOG_INFO("[%s]:port is normal, wait modemstate envent\n", __func__);
    }
    else if(state && *state == FLASH_PORT && g_full_flags.flag_arry[REBOOTFLAG] == 1)
    {
        flag.flag_arry[PORTSTATEFLAG] = FLASH_PORT;
        (void)get_set_reboot_flag(flag);
        //flash
        FIBO_LOG_INFO("[%s]:is flash port,will flash fw!\n", __func__);
        ret = flash_fw_with_recovery(fwinfo.ap_ver, fwinfo.fw_ver, fwinfo.oem_pack);
        if(ret == false)
        {
            FIBO_LOG_ERROR("[%s]:is flash port,flash fw error!\n", __func__);
        }
    }
    else if(state && *state == FLASH_PORT && g_full_flags.flag_arry[REBOOTFLAG] == 0)
    {
        flag.flag_arry[PORTSTATEFLAG] = FLASH_PORT;
        (void)get_set_reboot_flag(flag);
        FIBO_LOG_INFO("[%s]:flag is 0,reboot is process\n", __func__);
        reboot_modem(NULL);
    }
    else if(state && *state == NO_PORT)
    {
        flag.flag_arry[PORTSTATEFLAG] = NO_PORT;
        (void)get_set_reboot_flag(flag);
        //add timer 3min
        if(!start_flash_timer(3))
        {
            FIBO_LOG_ERROR("[%s]:start_flash_timer error\n", __func__);
        }
        ret = true;
    }
    else if(state && *state == DUMP_PORT)
    {
        flag.flag_arry[PORTSTATEFLAG] = DUMP_PORT;
        (void)get_set_reboot_flag(flag);
        FIBO_LOG_ERROR("[%s]:Now is dump port, pls collect dump log...[%s-%s]\n", __func__, __DATE__, __TIME__);
        ret = true;
    }
    else if(state && *state == FASTBOOT_PORT)
    {
        flag.flag_arry[PORTSTATEFLAG] = FASTBOOT_PORT;
        (void)get_set_reboot_flag(flag);
        FIBO_LOG_NOTICE("[%s]:Now is fastboot port, will start 3min timer...[%s-%s]\n", __func__, __DATE__, __TIME__);
        //add timer 3min
        g_timeout_add(3*60*1000,(GSourceFunc)fastboot_reboot_callback, NULL);
        ret = true;
    }
    else if(state && *state == UNKNOW_PORT)
    {
        FIBO_LOG_NOTICE("[%s]:Now is unknow port, will start 3min timer...[%s-%s]\n", __func__, __DATE__, __TIME__);
        if(!start_flash_timer(3))
        {
            FIBO_LOG_ERROR("[%s]:start_flash_timer error\n", __func__);
        }
        ret = true;
    }

    g_main_loop_run(gMainloop);
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

void *fibo_monitor_package(void *arg)
{
    int selret = 0;
    int read_cnt = 0;
    int monitor_pkg_fd = -1;
    int monitor_pkg_wd = -1;
    unsigned int watch_flag = IN_MODIFY | IN_CREATE | IN_DELETE
                              | IN_DELETE_SELF | IN_MOVE | IN_MOVE_SELF;
    fd_set read_fds;
    char buffer[BUF_LEN];
    int buffer_i = 0;
    bool new_pkg = FALSE;

    monitor_pkg_fd = inotify_init();
    if (monitor_pkg_fd < 0)
    {
        FIBO_LOG_ERROR("inotify_init error %d %s\n", errno, strerror(errno));
        return -1;
    }

    while (TRUE)
    {
        if (monitor_pkg_wd < 0)
        {
            /* Watch config file. */
            monitor_pkg_wd = inotify_add_watch(monitor_pkg_fd, FILE_MONITOR_PATH, watch_flag);
            if (monitor_pkg_wd < 0)
            {
                FIBO_LOG_ERROR("inotify_add_watch %d %s\n", errno, strerror(errno));
            }
            else
            {
                FD_ZERO(&read_fds);
                FD_SET(monitor_pkg_fd, &read_fds);
                selret = select(monitor_pkg_fd + 1, &read_fds, NULL, NULL, NULL);
            }
        }

        if (selret < 0)
        {
            FIBO_LOG_ERROR("select error %d\n", errno);
            continue;
        }
        else if (selret == 0)
        {
            continue;
        }
        else if (!FD_ISSET(monitor_pkg_fd, &read_fds))
        {
            FIBO_LOG_INFO("inot_fd not in fdset\n");
            continue;
        }

        read_cnt = read(monitor_pkg_fd, buffer, BUF_LEN);
        if (read_cnt <= 0)
        {
            FIBO_LOG_INFO("read <= 0 (%d)\n", read_cnt);
            continue;
        }

        buffer_i = 0;
        while (buffer_i < read_cnt)
        {
            /* Parse events and queue them. */
            struct inotify_event *pevent = (struct inotify_event*)&buffer[buffer_i];

            if (pevent->mask & IN_MODIFY)
            {
                FIBO_LOG_INFO("config %s modified\n", FILE_MONITOR_PATH);

                sleep(15);
                new_pkg = check_new_package();
                if (TRUE == new_pkg)
                {
                    FIBO_LOG_INFO("new package, need to update");
                    fw_update();
                }
            }
            else if (pevent->mask & (IN_DELETE | IN_DELETE_SELF | IN_MOVE | IN_MOVE_SELF))
            {
                FIBO_LOG_INFO("config %s was deleted or removed\n", FILE_MONITOR_PATH);
                int ret = inotify_rm_watch(monitor_pkg_fd, monitor_pkg_wd);
                if (ret < 0)
                {
                    FIBO_LOG_ERROR("rm_inotify_wd error %d\n", ret);
                }

                monitor_pkg_wd = -1;
            }
            else
            {
                FIBO_LOG_INFO("Unrecognized event mask %d\n", pevent->mask);
            }

            buffer_i += sizeof(struct inotify_event) + pevent->len;
        }
    }

    /** Remove watch. */
    if (inotify_rm_watch(monitor_pkg_fd, monitor_pkg_wd) < 0)
    {
        FIBO_LOG_ERROR("inotify_rm_watch error %d\n", errno);
    }

    close(monitor_pkg_fd);
    return 0;
}

void fibo_monitor_package_run()
{
    pthread_t ptid;
    pthread_create(&ptid, NULL, &fibo_monitor_package, NULL);
    FIBO_LOG_INFO("monitor package create\n", __func__);
}

static gboolean sim_status_handler(FibocomGdbusHelper *object, const char *value, gpointer userdata)
{
    e_error_code status;
    char port_status[32] = {0};

    FIBO_LOG_INFO("sim_status_handler invoked! %s \n", value);

    if (NULL != strstr(value, "mccmnc changed"))
    {
        FIBO_LOG_INFO("sim card mccmnc changed");

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

    return TRUE;
}

int find_ini(const char *filename, const char *section, const char *key, int *section_pos, int *key_pos)
{
    FILE *fpr = NULL;
    int i = 0;
    char sLine[1024] = {0};
    char *wTmp = NULL;
    e_ini_flag flag = INI_FLAG_INIT;

    fpr = fopen(filename, "r");
    if (NULL == fpr)
    {
        FIBO_LOG_ERROR("can't open file");
        return ERROR;
    }

    while(NULL != fgets(sLine, 1024, fpr))
    {
        if(*sLine == '[')
        {
            if(strncmp(section, sLine+1, strlen(section)) == 0)
            {
                *section_pos = i;
                ++i;
                flag = GET_SECTION; //get section
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
                            flag = GET_KEY; //get key
                            goto END;
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

    if (GET_KEY == flag)
    {
        FIBO_LOG_INFO("get key success");
        return OK;
    }
    else
    {
        FIBO_LOG_ERROR("get key failed");
        return ERROR;
    }
}

int get_keyString(const char *filename, const char *section, const char *key, char *result)
{
    FILE *fpr = NULL;
    int section_pos;
    int key_pos;
    int i = 0;
    char *wTmp = NULL;
    char sLine[1024] = {0};

    if(find_ini(filename, section, key, &section_pos, &key_pos) != OK)
    {
        return ERROR;
    }

    fpr = fopen(filename, "r");
    if (NULL == fpr)
    {
        FIBO_LOG_ERROR("can't open file");
        return ERROR;
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

            if (NULL != strstr(result, "\r\n"))
            {
                FIBO_LOG_INFO("get result string has carriage return");
                result[strlen(wTmp)-2] = '\0';
            }
            else
            {
                result[strlen(wTmp)-1] = '\0';
            }

            break;
        }

        ++i;
    }

    fclose(fpr);
    return OK;
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
    bool normal_port = FALSE;
    int ret;
    char port_status[32] = {0};
    e_error_code status = UNKNOWPROJECT;
    FILE *g_file = NULL;
    int i;

    log_init();

    FIBO_LOG_INFO("FW Flash service entry");
    openlog("FWFlashService", LOG_CONS | LOG_PID, LOG_USER);

    FIBO_LOG_INFO("fibo_flash_service version:%s", FLASH_VERSION_STRING);

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

    /* create monitor package thread */
    fibo_monitor_package_run();
    /* create recovery thread */
    fibo_firmware_recovery_run();
    gMainloop = g_main_loop_new(NULL, FALSE);

    for (i = 0; i < 30; i++)
    {
        g_usleep(1000 * 1000 * 2);
        status = check_port_state(port_status);
        if (ERROR == status)
        {
            FIBO_LOG_ERROR("get port state failed");
            continue;
        }
        else
        {
            if (strstr(port_status, "normalport") == NULL)
            {
                FIBO_LOG_INFO("port state is abnormal, wait...");
                continue;
            }
            else
            {
                normal_port = TRUE;
                FIBO_LOG_INFO("port state is normal, start FW flash flow");
                break;
            }
        }
    }

    if (TRUE == normal_port)
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
