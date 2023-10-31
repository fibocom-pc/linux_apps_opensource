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
 * @file static_config.c
 * @author ziqi.zhao@fibocom.com (zhaoziqi)
 * @brief
 * @version 1.0
 * @date 2023-09-23
 *
 *
 **/

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "fibo_cfg_log.h"
#include "fibo_parse_xml.h"
#include "fibo_list.h"
#include "fibo_config_parse.h"
#include "fibo_static_config.h"
#include "fibo_config_helper.h"

#define FIBO_STATIC_CONFIG_START "start_service"
#define FIBO_STATIC_CONFIG_DEBUG_LEVEL "debug_level"
#define FIBO_STATIC_CONFIG_DEVICE_MODE_GET "device_mode_get"
#define FIBO_STATIC_CONFIG_SIM_SLOTS_SWITCH "sim_slots_switch"
#define FIBO_STATIC_CONFIG_FCCLOCK_ENABLE "fcc_lock_enable"
#define FIBO_STATIC_CONFIG_WDISABLE_ENABLE "wdisable_enable"
#define FIBO_STATIC_CONFIG_GNSS_TYPE_ENABLE "gnss_enable"
#define FIBO_STATIC_CONFIG_NET_TYPE_SET "net_type_set"
#define FIBO_STATIC_CONFIG_BAND_CONF_ENABLE "band_config_enable"
#define FIBO_STATIC_CONFIG_CUSTOMIZATIONSOLUTIONTYPE "customizationsolutiontype"
#define FIBO_STATIC_CONFIG_SARDOWNLOADTYPE "sardownloadtype"
#define FIBO_STATIC_CONFIG_PROJECTTYPE "projecttype"
#define FIBO_STATIC_CONFIG_SATTYPE "sartype"
#define FIBO_STATIC_CONFIG_SARMAPTYPE "sarmaptype"
#define FIBO_STATIC_CONFIG_BODYSARSTATE "bodysarstate"
#define FIBO_STATIC_CONFIG_TASARSTATE "tasarstate"
#define FIBO_STATIC_CONFIG_ANTURNERSTATE "antturnerstate"

#define FIBO_APP_CONFIG_INI "fbwwanConfig.ini"
#define FIBO_ESIM_DISABLE_XML "eSIMRegionRestrictTable.xml"
#define FIBO_DEVICEMODE_MAPPING_XML "DeviceModeToScenarioIndexMappingTable.xml"
#define FIBO_REGION_MAPPING_XML "RegionMappingTable.xml"
#define FIBO_APP_CONFIG_PATH "/opt/fibocom/fibo_fw_pkg/fibo_config_file" // set config file path
#define FIBO_APP_CONFIG_INI_PATH "/opt/fibocom/fibo_config_service"

#define FIBO_REGION_MAPPING_VER "1.1.2"

#define STATUS_IS_NO "-1"
#define STATUS_IS_HW "0"
#define STATUS_IS_SW "1"

#define SAR_STATUS_IS_HW "0"
#define SAR_STATUS_IS_SW "1"

#define ANTENNA_STATUS_IS_OFF "0"
#define ANTENNA_STATUS_IS_NO "1"
#define ANTENNA_STATUS_IS_HW "0"
#define ANTENNA_STATUS_IS_SW "1"

#define STATUS_IS_ENABLE "1"
#define STATUS_IS_DISABLE "0"

#define LOAD_NET_TYPE_2G "0"
#define LOAD_NET_TYPE_3G "1"
#define LOAD_NET_TYPE_4G "2"

#define DEFAULT_LOG_LEVEL INFO_LOG_LEVEL
#define DEFAULT_SIM_SLOTS_1 "0"
#define SIM_SLOTS_2 "1"
#define DEFAULT_NET_TYPE LOAD_NET_TYPE_4G 

#define DEVICE_MODE_SIGNAL 0
#define DEVICE_MODE_FILE 1


#define GET_CURRENT_CONFIG(cid, status, type)                                                               \
    do                                                                                                      \
    {                                                                                                       \
        mesg_info *response = NULL;                                                                         \
        CFG_LOG_DEBUG("send message to dbus ,cid:%d", cid)                                                  \
        if (send_message_get_response(cid, "", 0, &response))                                               \
        {                                                                                                   \
            if (GET_DATA_SUCCESS == response->rtcode)                                                       \
            {                                                                                               \
                CFG_LOG_INFO("set cid:%d success!", cid);                                                   \
                if (STATUS_QUERY == type)                                                                   \
                {                                                                                           \
                    if (0 == strncmp(response->payload, STATUS_IS_HW, strlen(STATUS_IS_HW)))                \
                    {                                                                                       \
                        status = STATUS_HW;                                                                 \
                    }                                                                                       \
                    else if (0 == strncmp(response->payload, STATUS_IS_SW, strlen(STATUS_IS_SW)))           \
                    {                                                                                       \
                        status = STATUS_SW;                                                                 \
                    }                                                                                       \
                    else if (0 == strncmp(response->payload, STATUS_IS_NO, strlen(STATUS_IS_NO)))           \
                    {                                                                                       \
                        status = STATUS_OFF;                                                                \
                    }                                                                                       \
                    else                                                                                    \
                    {                                                                                       \
                        status = STATUS_UNKNOWN;                                                            \
                        CFG_LOG_ERROR("[%d]send message error", type);                                      \
                    }                                                                                       \
                }                                                                                           \
                else if (TYPE_QUERY == type)                                                                \
                {                                                                                           \
                    if (0 == strncmp(response->payload, STATUS_IS_ENABLE, strlen(STATUS_IS_ENABLE)))        \
                    {                                                                                       \
                        status = STATUS_ENABLE;                                                             \
                    }                                                                                       \
                    else if (0 == strncmp(response->payload, STATUS_IS_DISABLE, strlen(STATUS_IS_DISABLE))) \
                    {                                                                                       \
                        status = STATUS_DISABLE;                                                            \
                    }                                                                                       \
                    else                                                                                    \
                    {                                                                                       \
                        status = STATUS_UNKNOWN;                                                            \
                        CFG_LOG_ERROR("[%d]payload unknown payload:%s", type, response->payload);           \
                    }                                                                                       \
                }                                                                                           \
            }                                                                                               \
            else                                                                                            \
            {                                                                                               \
                status = STATUS_UNKNOWN;                                                                    \
                CFG_LOG_ERROR("set cid:%d fail!", cid);                                                     \
            }                                                                                               \
        }                                                                                                   \
        else                                                                                                \
        {                                                                                                   \
            status = STATUS_UNKNOWN;                                                                        \
            CFG_LOG_ERROR("send message error");                                                            \
        }                                                                                                   \
        if (NULL != response)                                                                               \
        {                                                                                                   \
            free(response);                                                                                 \
            response = NULL;                                                                                \
        }                                                                                                   \
    } while (0);

// ex:get version
#define GET_CURRENT_CONFIG_DATA(cid, status, rsppayload, rsp_len)                   \
    do                                                                              \
    {                                                                               \
        mesg_info *response = NULL;                                                 \
        CFG_LOG_DEBUG("send message to dbus ,cid:%d", cid)                          \
        if (send_message_get_response(cid, "", 0, &response))                       \
        {                                                                           \
            if (GET_DATA_SUCCESS == response->rtcode)                               \
            {                                                                       \
                status = GET_DATA_SUCCESS;                                          \
                rsppayload = malloc(response->payload_lenth + 1);                   \
                if (NULL != rsppayload)                                             \
                {                                                                   \
                    memset(rsppayload, 0, response->payload_lenth + 1);             \
                    memcpy(rsppayload, response->payload, response->payload_lenth); \
                    rsp_len = response->payload_lenth;                              \
                }                                                                   \
            }                                                                       \
            else                                                                    \
            {                                                                       \
                status = STATUS_UNKNOWN;                                            \
                CFG_LOG_ERROR("set cid:%d fail!", cid);                             \
            }                                                                       \
        }                                                                           \
        else                                                                        \
        {                                                                           \
            status = STATUS_UNKNOWN;                                                \
            CFG_LOG_ERROR("send message error");                                    \
        }                                                                           \
        if (NULL != response)                                                       \
        {                                                                           \
            free(response);                                                         \
            response = NULL;                                                        \
        }                                                                           \
    } while (0);

#define SET_STATIC_CONFIG(cid, payload, len, status)                                                                  \
    do                                                                                                                \
    {                                                                                                                 \
        mesg_info *response = NULL;                                                                                   \
        CFG_LOG_DEBUG("set cid:%d payload:%s!", cid, payload)                                                         \
        if (send_message_get_response(cid, payload, len, &response))                                                  \
        {                                                                                                             \
            if (GET_DATA_SUCCESS == response->rtcode)                                                                 \
            {                                                                                                         \
                status = GET_DATA_SUCCESS;                                                                            \
                CFG_LOG_INFO("set cid:%d success!", cid);                                                             \
            }                                                                                                         \
            else                                                                                                      \
            {                                                                                                         \
                status = STATUS_UNKNOWN;                                                                              \
                CFG_LOG_ERROR("set cid:%d fail!", cid);                                                               \
            }                                                                                                         \
        }                                                                                                             \
        else                                                                                                          \
        {                                                                                                             \
            status = STATUS_UNKNOWN;                                                                                  \
            CFG_LOG_INFO("set cid:%d ,retcode:%d,error!", cid, ((response == NULL) ? UNKNOW_CODE : response->rtcode)) \
        }                                                                                                             \
        if (NULL != response)                                                                                         \
        {                                                                                                             \
            free(response);                                                                                           \
            response = NULL;                                                                                          \
        }                                                                                                             \
    } while (0);

static struct list_head s_ini_list = {};
static esim_disable_parse_t parse_data = {};
static region_map_xml_parse_t region_map_data = {};
static devicemode_static_xml_parse_t static_parse_data = {};
log_level glog_level = LOG_LEVEL_INFO;

static bool fibo_compaer_config_item(config_parse_t *list_data, char *config_item, char min_value, char max_value)
{
    config_parse_t *cur = NULL;
    list_for_each_entry(cur, &s_ini_list, list)
    {
        if (0 == strncmp(cur->key, config_item, strlen(config_item)))
        {
            if(min_value <= cur->keyval && max_value >= cur->keyval)
            {
                strncpy(list_data->key, cur->key, strlen(cur->key));
                list_data->keyval = cur->keyval;
                return true;
            }
            break;
            
        }
    }
    return false;
}

int fibo_get_start_state(void)
{
    config_parse_t list_data = {};

    if (fibo_compaer_config_item(&list_data, FIBO_STATIC_CONFIG_START,SERVICE_STOP,SERVICE_RUN))
    {
        CFG_LOG_DEBUG("get config value success,key=%s ,value=%d", list_data.key, list_data.keyval);
        return list_data.keyval;
    }

    return 1;
}

static int cfg_log_set_level(log_level level)
{
    if (level < LOG_LEVEL_DEBUG || level > LOG_LEVEL_CRITICAL)
    {
        CFG_LOG_ERROR("set log level errr %d", level);
        return -1;
    }
    glog_level = level;

    return 0;
}

static bool fibo_set_debug_level(void)
{
    config_parse_t list_data = {};
    if (fibo_compaer_config_item(&list_data, FIBO_STATIC_CONFIG_DEBUG_LEVEL,DEBUG_LOG_LEVEL,CRITICAL_LOG_LEVEL))
    {
        cfg_log_set_level((log_level)list_data.keyval);
        CFG_LOG_DEBUG("set log level OK level:%d", glog_level);
    }
    else
    {
        CFG_LOG_INFO("get config value failed,set default log level");
        cfg_log_set_level(DEFAULT_LOG_LEVEL);
        return false;
    }
    return true;
}

int fibo_device_mode_get(void)
{
    config_parse_t list_data = {};
    if (fibo_compaer_config_item(&list_data, FIBO_STATIC_CONFIG_DEVICE_MODE_GET,DEVICE_MODE_SIGNAL,DEVICE_MODE_FILE))
    {
        CFG_LOG_DEBUG("get config value success,key=%s ,value=%d", list_data.key, list_data.keyval);
        return list_data.keyval;
    }

    CFG_LOG_INFO("get config value failed,use default config");
    return DEVICE_MODE_FILE;
}

static bool fibo_set_sim_slots_switch(void)
{
    config_parse_t list_data = {0};
    char status = 0;

    GET_CURRENT_CONFIG(GET_SIM_SLOTS_STATUS, status, TYPE_QUERY);
    if (STATUS_UNKNOWN == status)
    {
        CFG_LOG_ERROR("GET_SIM_SLOTS_STATUS error!");
        return false;
    }
    CFG_LOG_INFO("GET_SIM_SLOTS_STATUS status = %d", status);
    if (fibo_compaer_config_item(&list_data, FIBO_STATIC_CONFIG_SIM_SLOTS_SWITCH,SIM_SLOTS_FUNC_OFF,SIM_SLOTS_SWITCH_2))
    {
        if(list_data.keyval == SIM_SLOTS_FUNC_OFF)
        {
            CFG_LOG_INFO("SIM_SLOTS_SWITCH do nothing");
            return true;
        }
        if (status == list_data.keyval)
        {
            CFG_LOG_INFO("sim_slots_status correct ,do nothing");
            return true;
        }
        else
        {
            status = 0;
            if (list_data.keyval == SIM_SLOTS_SWITCH_1)
            {
                SET_STATIC_CONFIG(SET_SIM_SLOTS, DEFAULT_SIM_SLOTS_1, strlen(DEFAULT_SIM_SLOTS_1), status);
            }
            else if (list_data.keyval == SIM_SLOTS_SWITCH_2)
            {
                SET_STATIC_CONFIG(SET_SIM_SLOTS, SIM_SLOTS_2, strlen(SIM_SLOTS_2), status);
            }
            if (STATUS_UNKNOWN == status)
            {
                CFG_LOG_ERROR("setting error");
                return false;
            }
        }
    }
    else
    {
        CFG_LOG_INFO("get config value failed, set default value");
        status = 0;
        SET_STATIC_CONFIG(SET_SIM_SLOTS, DEFAULT_SIM_SLOTS_1, strlen(DEFAULT_SIM_SLOTS_1), status);
        if (STATUS_UNKNOWN == status)
        {
            CFG_LOG_ERROR("setting error");
            return false;
        }
    }
    // reset modem disable esim take effect
    CFG_LOG_INFO("SET_SIM_SLOTS ok  restart modem");
    SET_STATIC_CONFIG(RESET_MODEM_SW, "", 0, status);
    if (STATUS_UNKNOWN == status)
    {
        CFG_LOG_ERROR("setting error");
        return false;
    }
    return true;
}

static bool fibo_set_fcclock_enable(void)
{
    config_parse_t list_data = {0};
    if (fibo_compaer_config_item(&list_data, FIBO_STATIC_CONFIG_FCCLOCK_ENABLE,STATUS_FUNC_OFF,STATUS_ENABLE))
    {
        CFG_LOG_DEBUG("get config value success,key=%s ,value=%d", list_data.key, list_data.keyval);
        // do something
        if(STATUS_FUNC_OFF == list_data.keyval)
        {
            CFG_LOG_INFO("FCCLOCK do nothing");
            return true;
        }
    }
    else
    {
        CFG_LOG_ERROR("get config value failed,not setting");
        return false;
    }
    return true;
}

static bool fibo_set_wdisable_enable(void)
{
    config_parse_t list_data = {0};
    char status = 0;

    GET_CURRENT_CONFIG(GET_WDISABLE_STATUS, status, TYPE_QUERY);
    if (STATUS_UNKNOWN == status)
    {
        CFG_LOG_ERROR("GET_WDISABLE_STATUS error!");
        return false;
    }
    if (fibo_compaer_config_item(&list_data, FIBO_STATIC_CONFIG_WDISABLE_ENABLE,STATUS_FUNC_OFF,STATUS_ENABLE))
    {
        if(STATUS_FUNC_OFF == list_data.keyval)
        {
            CFG_LOG_INFO("WDISABLE do nothing");
            return true;
        }
        if (status == list_data.keyval)
        {
            CFG_LOG_INFO("wdisable status correct ,do nothing");
        }
        else
        {
            status = 0;
            if (list_data.keyval == STATUS_DISABLE)
            {
                SET_STATIC_CONFIG(SET_WDISABLE_ENABLE, STATUS_IS_DISABLE, strlen(STATUS_IS_DISABLE), status);
            }
            else
            {
                SET_STATIC_CONFIG(SET_WDISABLE_ENABLE, STATUS_IS_ENABLE, strlen(STATUS_IS_ENABLE), status);
            }
            if (STATUS_UNKNOWN == status)
            {
                CFG_LOG_ERROR("setting error");
                return false;
            }
        }
    }
    else
    {
        CFG_LOG_ERROR("get config value failed,not setting");
        return false;
    }
    return true;
}

static bool fibo_set_gnss_enable(void)
{
    char status = 0;
    config_parse_t list_data = {0};

    GET_CURRENT_CONFIG(GET_GNSS_STATUS, status, TYPE_QUERY);
    if (STATUS_UNKNOWN == status)
    {
        CFG_LOG_ERROR("GET_GNSS_STATUS error");
        return false;
    }
    if (fibo_compaer_config_item(&list_data, FIBO_STATIC_CONFIG_GNSS_TYPE_ENABLE,STATUS_FUNC_OFF,STATUS_ENABLE))
    {
        if(STATUS_FUNC_OFF == list_data.keyval)
        {
            CFG_LOG_INFO("GNSS do nothing");
            return true;
        }
        if (status == list_data.keyval)
        {
            CFG_LOG_INFO("gnss status correct ,do nothing");
        }
        else
        {
            status = 0;
            if (list_data.keyval == STATUS_DISABLE)
            {
                SET_STATIC_CONFIG(SET_GNSS_ENABLE, STATUS_IS_DISABLE, strlen(STATUS_IS_DISABLE), status);
            }
            else
            {
                SET_STATIC_CONFIG(SET_GNSS_ENABLE, STATUS_IS_ENABLE, strlen(STATUS_IS_ENABLE), status);
            }
            if (STATUS_UNKNOWN == status)
            {
                CFG_LOG_ERROR("setting error");
                return false;
            }
        }
    }
    else
    {
        CFG_LOG_ERROR("get config value failed,not setting");
        return false;
    }
    return true;
}

static bool fibo_set_bodysar_type(void)
{
    char status = 0;
    char value = 0;
    config_parse_t list_data = {0};

    if (SAR_TYPE_BODYSAR != fibo_get_sartype())
    {
        CFG_LOG_INFO("set sar type is tasar");
        return true;
    }

    SET_STATIC_CONFIG(SET_BODYSAR_ENABLE, STATUS_IS_ENABLE, 1, status);
    if (STATUS_UNKNOWN == status)
    {
        CFG_LOG_ERROR("SET_TASAR_ENABLE error");
        return false;
    }

    GET_CURRENT_CONFIG(GET_BODYSAR_CTRL_MODE, status, STATUS_QUERY);
    if (STATUS_UNKNOWN == status)
    {
        CFG_LOG_ERROR("GET_BODYSAR_CTRL_MODE error");
        return false;
    }
    if (fibo_compaer_config_item(&list_data, FIBO_STATIC_CONFIG_BODYSARSTATE,STATUS_HW,STATUS_SW))
    {
        if (status == list_data.keyval)
        {
            CFG_LOG_INFO("bodysar status correct ,do nothing");
        }
        else
        {
            status = 0;
            if (list_data.keyval == STATUS_HW)
            {
                SET_STATIC_CONFIG(SET_BODYSAR_CTRL_MODE, SAR_STATUS_IS_HW, strlen(SAR_STATUS_IS_HW), status);
            }
            else if (list_data.keyval == STATUS_SW)
            {
                SET_STATIC_CONFIG(SET_BODYSAR_CTRL_MODE, SAR_STATUS_IS_SW, strlen(SAR_STATUS_IS_SW), status);
            }
            if (STATUS_UNKNOWN == status)
            {
                CFG_LOG_ERROR("setting error");
                return false;
            }
        }
    }
    else
    {
        CFG_LOG_ERROR("get config value failed,not setting");
        return false;
    }
    return true;
}

static bool fibo_set_tasar_type(void)
{
    char status = 0;
    char value = 0;
    config_parse_t list_data = {0};

    if (SAR_TYPE_TASAR != fibo_get_sartype())
    {
        CFG_LOG_INFO("set sar type is bodysar");
        return true;
    }

    SET_STATIC_CONFIG(SET_TASAR_ENABLE, STATUS_IS_ENABLE, 1, status);
    if (STATUS_UNKNOWN == status)
    {
        CFG_LOG_ERROR("SET_TASAR_ENABLE error");
        return false;
    }

    GET_CURRENT_CONFIG(GET_TASAR_CTRL_MODE, status, STATUS_QUERY);
    if (STATUS_UNKNOWN == status)
    {
        CFG_LOG_ERROR("GET_TASAR_CTRL_MODE error");
        return false;
    }
    if (fibo_compaer_config_item(&list_data, FIBO_STATIC_CONFIG_TASARSTATE,STATUS_HW,STATUS_SW))
    {
        if (status == list_data.keyval)
        {
            CFG_LOG_INFO("wdisable status correct ,do nothing");
        }
        else
        {
            status = 0;
            if (list_data.keyval == STATUS_HW)
            {
                SET_STATIC_CONFIG(SET_TASAR_CTRL_MODE, SAR_STATUS_IS_HW, strlen(SAR_STATUS_IS_HW), status);
            }
            else if (list_data.keyval == STATUS_SW)
            {
                SET_STATIC_CONFIG(SET_TASAR_CTRL_MODE, SAR_STATUS_IS_SW, strlen(SAR_STATUS_IS_SW), status);
            }
            if (STATUS_UNKNOWN == status)
            {
                CFG_LOG_ERROR("setting error");
                return false;
            }
        }
    }
    else
    {
        CFG_LOG_ERROR("get config value failed,not setting");
        return false;
    }
    return true;
}

static bool fibo_set_antenna_type(void)
{
    char status = 0;
    config_parse_t list_data = {0};
    char value = 0;

    if (fibo_compaer_config_item(&list_data, FIBO_STATIC_CONFIG_ANTURNERSTATE,STATUS_OFF,STATUS_SW))
    {
        if (STATUS_OFF == list_data.keyval)
        {
            SET_STATIC_CONFIG(SET_ANTENNA_ENABLE, ANTENNA_STATUS_IS_OFF, strlen(ANTENNA_STATUS_IS_OFF), status);
            if (STATUS_UNKNOWN == status)
            {
                CFG_LOG_ERROR("set config value failed");
                return false;
            }
            CFG_LOG_INFO("set antenna disable success");
            return true;
        }
        else
        {
            GET_CURRENT_CONFIG(GET_ANTENNA_STATUS, status, TYPE_QUERY);
            if (STATUS_UNKNOWN == status)
            {
                CFG_LOG_ERROR("GET_ANTENNA_STATUS error");
                return false;
            }
            else if (STATUS_OFF == status)
            {
                SET_STATIC_CONFIG(SET_ANTENNA_ENABLE, ANTENNA_STATUS_IS_NO, strlen(ANTENNA_STATUS_IS_NO), status);
            }

            GET_CURRENT_CONFIG(GET_ANTENNA_CTRL_MODE, status, STATUS_QUERY);
            if (STATUS_UNKNOWN == status)
            {
                CFG_LOG_ERROR("GET_ANTENNA_CTRL_MODE error");
                return false;
            }

            if (status == list_data.keyval)
            {
                CFG_LOG_INFO("antenna status correct ,do nothing");
                return true;
            }
            status = 0;
            if (list_data.keyval == STATUS_HW)
            {
                SET_STATIC_CONFIG(SET_ANTENNA_CTRL_MODE, ANTENNA_STATUS_IS_HW, strlen(ANTENNA_STATUS_IS_HW), status);
            }
            else if (list_data.keyval == STATUS_SW)
            {
                SET_STATIC_CONFIG(SET_ANTENNA_CTRL_MODE, ANTENNA_STATUS_IS_SW, strlen(ANTENNA_STATUS_IS_SW), status);
            }
            else if (list_data.keyval == STATUS_OFF)
            {
                SET_STATIC_CONFIG(SET_ANTENNA_ENABLE, STATUS_IS_DISABLE, 1, status);
            }
            if (STATUS_UNKNOWN == status)
            {
                CFG_LOG_ERROR("setting error");
                return false;
            }
        }
    }
    else
    {
        CFG_LOG_ERROR("get config value failed,not setting");
        return false;
    }
    return true;
}

static bool fibo_set_band_config_enable(void)
{
    config_parse_t list_data = {0};
    if (fibo_compaer_config_item(&list_data, FIBO_STATIC_CONFIG_BAND_CONF_ENABLE,STATUS_FUNC_OFF,STATUS_ENABLE))
    {
        CFG_LOG_DEBUG("get config value success,key=%s ,value=%d", list_data.key, list_data.keyval);
        // do something
    }
    else
    {
        CFG_LOG_ERROR("get config value failed,not setting");
        return false;
    }
    return true;
}


static bool fibo_set_net_type(void)
{
    config_parse_t list_data = {0};
    char status = 0;
    char *rsp_data = NULL;
    int payload_len = 0;

    return true;
    GET_CURRENT_CONFIG_DATA(GET_NET_WORK_TYPE, status, rsp_data, payload_len);
    if (STATUS_UNKNOWN == status)
    {
        CFG_LOG_ERROR("GET_NET_WORK_TYPE error!");
        return false;
    }
    if (fibo_compaer_config_item(&list_data, FIBO_STATIC_CONFIG_NET_TYPE_SET,NET_TYPE_FUNC_OFF,NET_TYPE_5G))
    {
        if(STATUS_FUNC_OFF == list_data.keyval)
        {
            CFG_LOG_INFO("NET_TYPE do nothing");
            return true;
        }
        if (status == list_data.keyval)
        {
            CFG_LOG_INFO("wdisable status correct ,do nothing");
        }
        else
        {
            status = 0;
            char data[4] ={0};
            sprintf(data,"%d",list_data.keyval);
            SET_STATIC_CONFIG(SET_NET_WORK_TYPE, data, strlen(data), status);
            if (STATUS_UNKNOWN == status)
            {
                CFG_LOG_ERROR("setting error");
                return false;
            }
        }
    }
    else
    {
        CFG_LOG_INFO("get config value failed,set default value");
        /* set default net type 4G */
        SET_STATIC_CONFIG(SET_NET_WORK_TYPE, DEFAULT_NET_TYPE, strlen(DEFAULT_NET_TYPE), status);
        if (STATUS_UNKNOWN == status)
        {
            CFG_LOG_ERROR("setting error");
            return false;
        }
    }
    return true;
}

/* get infomation */
custom_solucion_type fibo_get_customizationsolutiontype(void)
{
    config_parse_t list_data = {0};
    if (fibo_compaer_config_item(&list_data, FIBO_STATIC_CONFIG_CUSTOMIZATIONSOLUTIONTYPE,SOLTION_DISABLE,SOLTION_XML))
    {
        CFG_LOG_DEBUG("get config value success,key=%s ,value=%d", list_data.key, list_data.keyval);
        return (custom_solucion_type)list_data.keyval;
    }
    CFG_LOG_ERROR("get config value failed,not setting");
    return SLUCTION_TYPE_UNKNOWN;
}

sar_download_type get_sardownloadtype(void)
{
    config_parse_t list_data = {0};
    if (fibo_compaer_config_item(&list_data, FIBO_STATIC_CONFIG_SARDOWNLOADTYPE,DOWN_LOAD_FLASH,DOWN_LOAD_AT))
    {
        CFG_LOG_DEBUG("get config value success,key=%s ,value=%d", list_data.key, list_data.keyval);
        return (sar_download_type)list_data.keyval;
    }
    CFG_LOG_ERROR("get config value failed,not setting");
    return DOWN_LOAD_UNKNOWN;
}

sar_type fibo_get_sartype(void)
{
    config_parse_t list_data = {0};
    if (fibo_compaer_config_item(&list_data, FIBO_STATIC_CONFIG_SATTYPE,SAR_TYPE_NOTHING,SAR_TYPE_TASAR))
    {
        CFG_LOG_DEBUG("get config value success,key=%s ,value=%d", list_data.key, list_data.keyval);
        return (sar_type)list_data.keyval;
    }
    return SAR_TYPE_UNKNOWN;
}

sar_map_type fibo_get_sarmaptype(void)
{
    config_parse_t list_data = {0};
    if (fibo_compaer_config_item(&list_data, FIBO_STATIC_CONFIG_SARMAPTYPE,SARMAP_TYPE_NO,SARMAP_TYPE_5))
    {
        CFG_LOG_DEBUG("get config value success,key=%s ,value=%d", list_data.key, list_data.keyval);
        return (sar_map_type)list_data.keyval;
    }
    CFG_LOG_ERROR("get config value failed,not setting");
    return SAR_MAP_TYPE_UNKNOWN;
}

switch_status fibo_get_antturnerstate(void)
{
    config_parse_t list_data = {0};
    if (fibo_compaer_config_item(&list_data, FIBO_STATIC_CONFIG_ANTURNERSTATE,STATUS_OFF,STATUS_SW))
    {
        CFG_LOG_DEBUG("get config value success,key=%s ,value=%d", list_data.key, list_data.keyval);
        return (switch_status)list_data.keyval;
    }

    CFG_LOG_ERROR("get config value failed,not setting");
    return STATUS_UNKNOWN;
}

// list_for_each_entry(cur, list,list)
// {
//     printf("key:%s,keyMAIN:%d\n",cur->key,cur->keyval);
// }

static bool fibo_disable_esim_parse(esim_disable_parse_t *parse_data)
{
    char file_path[256] = {0};
    fibo_sku_black_xml_t *sku_black = NULL;
    fibo_mcc_black_xml_t *mcc_black = NULL;

    sprintf(file_path, "%s/%s", FIBO_APP_CONFIG_PATH, FIBO_ESIM_DISABLE_XML);
    if (access(file_path, F_OK))
    {
        CFG_LOG_ERROR("file:%s,file is not exeist", file_path);
        return false;
    }
    INIT_LIST_HEAD(&parse_data->sku_black_list);
    INIT_LIST_HEAD(&parse_data->mcc_black_list);
    fibo_parse_esim_xml_data(file_path, &parse_data->xml_parse_rule, &parse_data->sku_black_list, &parse_data->mcc_black_list);

    /* list_for_each_entry(sku_black, &parse_data->sku_black_list, list)
    {
        CFG_LOG_DEBUG("list sku:%s", sku_black->sku);
    }
    list_for_each_entry(mcc_black, &parse_data->mcc_black_list, list)
    {
        CFG_LOG_DEBUG("list sku:%s", mcc_black->mcc);
    } */
    return true;
}

static bool fibo_region_mapping_parse(region_map_xml_parse_t *parse_data)
{
    char file_path[256] = {0};
    fibo_select_rule_xml_t *select_rule = NULL;
    fibo_sar_custom_t *custom_rule = NULL;

    sprintf(file_path, "%s/%s", FIBO_APP_CONFIG_PATH, FIBO_REGION_MAPPING_XML);
    if (access(file_path, F_OK))
    {
        CFG_LOG_ERROR("file:%s,file is not exeist", file_path);
        return false;
    }
    INIT_LIST_HEAD(&parse_data->select_rule_list);
    INIT_LIST_HEAD(&parse_data->sar_custom_list);
    fibo_parse_region_mapping_data(file_path, FIBO_REGION_MAPPING_VER, parse_data->region_ver,
                                   &parse_data->select_rule_list, &parse_data->sar_custom_list);
    return true;
}

char *get_region_regulatory(char *mcc)
{
    char *regulatory = NULL;
    fibo_select_rule_xml_t *select_rule = NULL;
    list_for_each_entry(select_rule, &region_map_data.select_rule_list, list)
    {
        if (0 == strcmp("default", select_rule->mcc))
        {
            regulatory = select_rule->regulatory;
            continue;
        }
        if (0 == strncmp(mcc, select_rule->mcc, strlen(select_rule->mcc)))
        {
            regulatory = select_rule->regulatory;
            break;
        }
    }
    CFG_LOG_DEBUG("get_region_regulatory:%s", regulatory);
    return regulatory;
}

bool fibo_devicemode_mapping_parse(devicemode_static_xml_parse_t *parse_data)
{
    char file_path[256] = {0};
    fibo_wwan_project_xml_t *wwanid_list = NULL;
    fibo_wwancfg_disable_xml_t *disable_list = NULL;

    fibo_sar_xml5_t xmldata = {0};

    sprintf(file_path, "%s/%s", FIBO_APP_CONFIG_PATH, FIBO_DEVICEMODE_MAPPING_XML);
    if (access(file_path, F_OK))
    {
        CFG_LOG_ERROR("file:%s,file is not exeist", file_path);
        return false;
    }
    INIT_LIST_HEAD(&parse_data->wwan_project_list);
    INIT_LIST_HEAD(&parse_data->wwancfg_disable_list);
    fibo_parse_devicemode_static_data(file_path, parse_data);

    return true;
}

static bool get_system_info(char *cmd, char *find_key, int value_start, int value_len, char *data)
{
    FILE *fp = NULL;
    char line[64];
    int cnt = 0;
    int len = 0;
    char *p = NULL;

    if (fp = popen(cmd, "r"))
    {
        while (fgets(line, 64, fp))
        {
            p = strstr(line, find_key);
            if (NULL != p)
            {
                p = strstr(p, ":");
                // CFG_LOG_DEBUG("line:%s", line);
                memcpy(data, p + value_start, value_len);
                pclose(fp);
                return true;
            }
        }
    }
    return false;
}

static bool get_system_wwanconfig_info(char *cmd, char *data, int *data_len)
{
    FILE *fp = NULL;
    char line[64];
    int cnt = 0;
    int len = 0;

    bool find_data = false;
    int key_cnt = 0;
    int key1_cnt = 0;

    if (fp = popen(cmd, "r"))
    {
        while (fgets(line, 64, fp))
        {
            if (strstr(line, "Header and Data:"))
            {
                find_data = true;
                continue;
            }
            if (find_data)
            {
                // CFG_LOG_DEBUG("LINE###: %s,len:%d,cnt:%d", line,(int)strlen(line),cnt);
                if (50 > strlen(line)) // This method is not accurate
                {
                    cnt = 0;
                    continue;
                }
                if (cnt == 1)
                {
                    for (int i = 0; i < 64; i++)
                    {
                        if (line[i] >= '0' && line[i] <= 'z')
                        {
                            data[len++] = line[i];
                        }
                    }
                    break;
                }
                cnt++;
            }
        }
        *data_len = len;
        pclose(fp);
        return true;
    }
    return false;
}

static oem_type get_current_oem(void)
{
    char data[64] = {0};
    int start = 0;
    int len = 0;
    oem_type oem = UNKNOW;

    start = 2;
    len = 8;
    get_system_info("sudo dmidecode -t 1", "Manufacturer:", start, len, data);
    if (0 == strncmp(data, "LENOVO", strlen("LENOVO")))
    {
        oem = LENOVO;
    }
    else if (0 == strncmp(data, "HP", strlen("HP")))
    {
        oem = HP;
    }
    else if (0 == strncmp(data, "Dell", strlen("Dell")))
    {
        oem = DELL;
    }
    else
    {
        CFG_LOG_ERROR("get oem error,oem:%s", data);
    }
    CFG_LOG_DEBUG("oem:%d", oem);
    return oem;
}

static char wwanconfigid[64] = {0};
static char skuid[64] = {0};

char *fibo_get_wwanconfigid(void)
{
    char data[64] = {0};
    int len = 0;

    get_system_wwanconfig_info("sudo dmidecode -t 133", data, &len);

    sprintf(wwanconfigid, "%c%c%c%c.%c%c%c%c.%c%c%c%c.%c%c%c%c", data[12], data[13], data[10], data[11],
            data[15], data[17], data[19], data[21], data[24], data[25], data[22], data[23], data[28], data[29], data[26], data[27]);
    CFG_LOG_DEBUG("wwanconfigid:%s,len:%d", wwanconfigid, len);
    return wwanconfigid;
}

char *fibo_get_skuid(void)
{

    int start = 0;
    int len = 0;
    oem_type oem = UNKNOW;

    oem = get_current_oem();

    if (DELL == oem)
    {
        start = 3;
        len = 3;
        get_system_info("sudo dmidecode -t 1", "SKU Number:", start, len, skuid);
        CFG_LOG_DEBUG("skuid:%s,len:%d", skuid, len);
    }
    else if (LENOVO == oem)
    {
        // reserve
    }
    else if (HP == oem)
    {
        start = 3;
        len = 3;
        get_system_info("sudo dmidecode -t 2", "Product Name:", start, len, skuid);
        CFG_LOG_DEBUG("skuid:%s,len:%d", skuid, len);
    }
    else
    {
        CFG_LOG_ERROR("OEM type known");
        return NULL;
    }

    return skuid;
}

static bool region_mapping_data_test(void)
{
    fibo_select_rule_xml_t *select_rule = NULL;
    fibo_sar_custom_t *custom_rule = NULL;
    list_for_each_entry(select_rule, &region_map_data.select_rule_list, list)
    {
        CFG_LOG_DEBUG("list mcc:%s", select_rule->mcc);
    }
    list_for_each_entry(custom_rule, &region_map_data.sar_custom_list, list)
    {
        CFG_LOG_DEBUG("list regulatory:%s", custom_rule->regulatory);
    }
}

static bool fibo_parse_devicemode_mapping_test(void)
{
    fibo_wwan_project_xml_t *wwanid_list = NULL;
    fibo_wwancfg_disable_xml_t *disable_list = NULL;

    list_for_each_entry(wwanid_list, &static_parse_data.wwan_project_list, list)
    {
        CFG_LOG_DEBUG("list projectid:%s", wwanid_list->projectid);
    }
    list_for_each_entry(disable_list, &static_parse_data.wwancfg_disable_list, list)
    {
        CFG_LOG_DEBUG("list regulatory:%s", disable_list->wwanconfigid);
    }
}

static bool fibo_get_sar_index_test(void)
{
    char index = 0;
    sar_index_para_t input_data = {0};

    input_data.sar_map_type = SARMAP_TYPE_1;
    strncpy(input_data.wwanconfigid, "default", strlen("default"));
    input_data.standard = "CE";
    input_data.device.device_mode = 1;
    input_data.device.sensor1 = 0;
    input_data.device.sensor2 = 1;
    input_data.device.sensor3 = 1;

    fibo_get_sar_index(&input_data, &index);
    CFG_LOG_DEBUG("list sar_index:%d", (int)index);

    memset(&input_data, 0, sizeof(input_data));
    input_data.sar_map_type = SARMAP_TYPE_2;
    strncpy(input_data.wwanconfigid, "default", strlen("default"));
    input_data.standard = "CE";
    input_data.device.device_mode = 1;
    input_data.device.sensor1 = 0;
    input_data.device.sensor2 = 1;
    input_data.device.sensor3 = 1;
    fibo_get_sar_index(&input_data, &index);

    memset(&input_data, 0, sizeof(input_data));
    input_data.sar_map_type = SARMAP_TYPE_3;
    strncpy(input_data.wwanconfigid, "default", strlen("default"));
    input_data.standard = "CE";
    input_data.device.device_mode = 1;
    input_data.device.sensor1 = 0;
    input_data.device.sensor2 = 1;
    input_data.device.sensor3 = 1;
    fibo_get_sar_index(&input_data, &index);
    CFG_LOG_DEBUG("list sar_index:%d", (int)index);

    memset(&input_data, 0, sizeof(input_data));
    input_data.sar_map_type = SARMAP_TYPE_4;
    strncpy(input_data.wwanconfigid, "default", strlen("default"));
    input_data.standard = "CE";
    input_data.device.device_mode = 1;
    input_data.device.sensor1 = 0;
    input_data.device.sensor2 = 1;
    input_data.device.sensor3 = 1;
    fibo_get_sar_index(&input_data, &index);
    CFG_LOG_DEBUG("list sar_index:%d", (int)index);

    memset(&input_data, 0, sizeof(input_data));
    input_data.sar_map_type = SARMAP_TYPE_5;
    strncpy(input_data.wwanconfigid, "5000.0001.0000.0000", strlen("5000.0001.0000.0000"));
    input_data.standard = "CE";
    input_data.device.device_mode = 1;
    input_data.device.sensor1 = 0;
    input_data.device.sensor2 = 1;
    input_data.device.sensor3 = 1;
    fibo_get_sar_index(&input_data, &index);
    CFG_LOG_DEBUG("list sar_index:%d", (int)index);
}

static bool fibo_get_antenna_index_test(void)
{
    char index = 0;
    fibo_get_antenna_index("5000.0007.0000.0000", 5, &index);
    CFG_LOG_DEBUG("list xmldata:%d", (int)index);
}

void test_data(void)
{
    region_mapping_data_test();
    fibo_parse_devicemode_mapping_test();
    fibo_get_sar_index_test();
    fibo_get_antenna_index_test();
    CFG_LOG_DEBUG("wwanconfigid:%s", fibo_get_wwanconfigid());
    CFG_LOG_DEBUG("skuid:%s", fibo_get_skuid());
}

bool destory_list_memeory()
{
    config_parse_t *config_list = NULL;
    fibo_wwan_project_xml_t *wwanid_list = NULL;
    fibo_wwancfg_disable_xml_t *disable_list = NULL;
    fibo_sku_black_xml_t *sku_black = NULL;
    fibo_mcc_black_xml_t *mcc_black = NULL;
    fibo_select_rule_xml_t *select_rule = NULL;
    fibo_sar_custom_t *custom_rule = NULL;

    struct list_head *pos = NULL;
    struct list_head *q = NULL;
    CFG_LOG_DEBUG("destory list start");
    list_for_each_safe(pos, q, &s_ini_list)
    {
        config_list = list_entry(pos, config_parse_t, list);
        list_del(pos);
        free(config_list);
    }

    list_for_each_safe(pos, q, &static_parse_data.wwan_project_list)
    {
        wwanid_list = list_entry(pos, fibo_wwan_project_xml_t, list);
        list_del(pos);
        free(wwanid_list);
    }

    list_for_each_safe(pos, q, &static_parse_data.wwancfg_disable_list)
    {
        disable_list = list_entry(pos, fibo_wwancfg_disable_xml_t, list);
        list_del(pos);
        free(disable_list);
    }

    list_for_each_safe(pos, q, &parse_data.sku_black_list)
    {
        sku_black = list_entry(pos, fibo_sku_black_xml_t, list);
        list_del(pos);
        free(sku_black);
    }

    list_for_each_safe(pos, q, &parse_data.mcc_black_list)
    {
        mcc_black = list_entry(pos, fibo_mcc_black_xml_t, list);
        list_del(pos);
        free(mcc_black);
    }

    list_for_each_safe(pos, q, &region_map_data.select_rule_list)
    {
        select_rule = list_entry(pos, fibo_select_rule_xml_t, list);
        list_del(pos);
        free(select_rule);
    }

    list_for_each_safe(pos, q, &region_map_data.sar_custom_list)
    {
        custom_rule = list_entry(pos, fibo_sar_custom_t, list);
        list_del(pos);
        free(custom_rule);
    }
    CFG_LOG_DEBUG("destory list end");
    return true;
}

bool fibo_get_antenna_index(char *wwanconfigid, char device_mode, char *index)
{
    char file_path[256] = {0};
    bool ret = false;
    fibo_antenna_xml_t antenna_data = {0};

    sprintf(file_path, "%s/%s", FIBO_APP_CONFIG_PATH, FIBO_DEVICEMODE_MAPPING_XML);
    if (access(file_path, F_OK))
    {
        CFG_LOG_ERROR("file:%s,file is not exeist", file_path);
        return false;
    }
    antenna_data.wwanconfig_id = wwanconfigid;
    antenna_data.device_mode = device_mode;

    ret = fibo_parse_antenna_dynamic_data(file_path, &antenna_data);
    *index = antenna_data.index;
    CFG_LOG_DEBUG("list antenna_data:%d", (int)*index);
    return ret;
}

bool fibo_get_sar_index(sar_index_para_t *input_data, char *index)
{
    char file_path[256] = {0};
    bool ret = false;
    fibo_wwancfg_disable_xml_t *disable_list = NULL;

    sprintf(file_path, "%s/%s", FIBO_APP_CONFIG_PATH, FIBO_DEVICEMODE_MAPPING_XML);
    if (access(file_path, F_OK))
    {
        CFG_LOG_ERROR("file:%s,file is not exeist", file_path);
        return false;
    }

    list_for_each_entry(disable_list, &static_parse_data.wwancfg_disable_list, list)
    {
        if (0 == strcmp(disable_list->wwanconfigid, wwanconfigid))
        {
            CFG_LOG_INFO("wwanconfigid:%s disable config.", disable_list->wwanconfigid);
            return false;
        }
    }
    if (SARMAP_TYPE_1 == input_data->sar_map_type)
    {
        fibo_sar_xml1_t xmldata = {0};

        xmldata.standard = input_data->standard;
        ret = fibo_parse_devicemode_index_data(file_path, wwanconfigid, SAR_MAP_TYPE_1, (void *)&xmldata);
        CFG_LOG_DEBUG("list xmldata:%d", (int)xmldata.index);
        *index = xmldata.index;
    }
    else if (SARMAP_TYPE_2 == input_data->sar_map_type)
    {
        fibo_sar_xml2_t xmldata = {0};

        xmldata.standard = input_data->standard;
        xmldata.device_mode = input_data->device.device_mode;

        ret = fibo_parse_devicemode_index_data(file_path, wwanconfigid, SAR_MAP_TYPE_2, (void *)&xmldata);
        CFG_LOG_DEBUG("list xmldata:%d", (int)xmldata.index);
        *index = xmldata.index;
    }
    else if (SARMAP_TYPE_3 == input_data->sar_map_type)
    {
        fibo_sar_xml3_t xmldata = {0};

        xmldata.standard = input_data->standard;
        xmldata.device_mode = input_data->device.device_mode;
        xmldata.sensor1 = input_data->device.sensor1;
        ret = fibo_parse_devicemode_index_data(file_path, wwanconfigid, SAR_MAP_TYPE_3, (void *)&xmldata);
        CFG_LOG_DEBUG("list xmldata:%d", (int)xmldata.index);
        *index = xmldata.index;
    }
    else if (SARMAP_TYPE_4 == input_data->sar_map_type)
    {
        fibo_sar_xml4_t xmldata = {0};

        xmldata.standard = input_data->standard;
        xmldata.device_mode = input_data->device.device_mode;
        xmldata.sensor1 = input_data->device.sensor1;
        xmldata.sensor2 = input_data->device.sensor2;
        ret = fibo_parse_devicemode_index_data(file_path, wwanconfigid, SAR_MAP_TYPE_4, (void *)&xmldata);
        CFG_LOG_DEBUG("list xmldata:%d", (int)xmldata.index);
        *index = xmldata.index;
    }
    else if (SARMAP_TYPE_5 == input_data->sar_map_type)
    {
        fibo_sar_xml5_t xmldata = {0};

        xmldata.standard = input_data->standard;
        xmldata.device_mode = input_data->device.device_mode;
        xmldata.sensor1 = input_data->device.sensor1;
        xmldata.sensor2 = input_data->device.sensor2;
        xmldata.sensor3 = input_data->device.sensor3;
        ret = fibo_parse_devicemode_index_data(file_path, wwanconfigid, SAR_MAP_TYPE_5, (void *)&xmldata);
        CFG_LOG_DEBUG("list xmldata:%d", (int)xmldata.index);
        *index = xmldata.index;
    }
    return ret;
}

static bool sku_disable_esim = false;
bool fibo_set_disableesim_for_sku(void)
{
    fibo_sku_black_xml_t *sku_black = NULL;
    char *current_sku = NULL;
    int status = 0;

    current_sku = fibo_get_skuid();
    if (NULL == current_sku)
    {
        CFG_LOG_ERROR("can not found skuid not handle disable esim");
        return false;
    }

    GET_CURRENT_CONFIG(GET_DISABLE_ESIM_STATUS, status, TYPE_QUERY);
    if (STATUS_UNKNOWN == status)
    {
        CFG_LOG_ERROR("GET_DISABLE_ESIM_STATUS error");
        return false;
    }
    else if (STATUS_DISABLE == status)
    {
        CFG_LOG_INFO("Current state is esim enable,no need action!");
        return true;
    }
    else if (STATUS_ENABLE == status)
    {
        CFG_LOG_INFO("Current state is esim enabled");
    }

    list_for_each_entry(sku_black, &parse_data.sku_black_list, list)
    {
        if (0 == strncmp(current_sku, sku_black->sku, strlen(current_sku)))
        {
            sku_disable_esim = true;
            CFG_LOG_INFO("find this SKU in black list disable esim,current_sku:%s", current_sku);
            SET_STATIC_CONFIG(SET_DISABLE_ESIM, STATUS_IS_DISABLE, strlen(STATUS_IS_DISABLE), status);
            if (STATUS_UNKNOWN == status)
            {
                CFG_LOG_ERROR("setting error");
                return false;
            }
            // reset modem disable esim take effect
            SET_STATIC_CONFIG(RESET_MODEM_SW, "", 0, status);
            if (STATUS_UNKNOWN == status)
            {
                CFG_LOG_ERROR("setting error");
                return false;
            }
        }
    }
    return true;
}

bool fibo_set_disableesim_for_mcc(void)
{
    fibo_mcc_black_xml_t *mcc_black = NULL;
    char *current_sku = NULL;
    char *current_mcc = NULL;
    int status = 0;

    if (sku_disable_esim)
    {
        CFG_LOG_INFO("this module is disable esim not care for mcc change");
        return true;
    }

    GET_CURRENT_CONFIG(GET_DISABLE_ESIM_STATUS, status, STATUS_QUERY);
    if (STATUS_UNKNOWN == status)
    {
        CFG_LOG_ERROR("GET_DISABLE_ESIM_STATUS error");
        return false;
    }
    else if (STATUS_DISABLE == status)
    {
        CFG_LOG_INFO("Current state is esim disableenable,no need action!");
        return true;
    }
    else if (STATUS_ENABLE == status)
    {
        CFG_LOG_INFO("Current state is esim enable abled");
    }

    current_mcc = fibo_get_mcc_value();
    list_for_each_entry(mcc_black, &parse_data.mcc_black_list, list)
    {
        if (0 == strcmp(current_mcc, mcc_black->mcc))
        {
            CFG_LOG_INFO("find this mcc in black list disable esim,current_mcc:%s", current_mcc);
            SET_STATIC_CONFIG(SET_DISABLE_ESIM, STATUS_IS_ENABLE, strlen(STATUS_IS_ENABLE), status);
            if (STATUS_UNKNOWN == status)
            {
                CFG_LOG_ERROR("setting error");
                return false;
            }
            // reset modem disable esim take effect
            SET_STATIC_CONFIG(RESET_MODEM_SW, "", 0, status);
            if (STATUS_UNKNOWN == status)
            {
                CFG_LOG_ERROR("setting error");
                return false;
            }
            break;
        }
    }
    return true;
}

bool fibo_get_config_and_set(void)
{
    int result = 0;
    result += fibo_set_debug_level();
    /* result += fibo_set_fcclock_enable(); */
    result += fibo_set_sim_slots_switch();
    /* result += fibo_set_wdisable_enable();
    result += fibo_set_gnss_enable();
    result += fibo_set_band_config_enable();
    result += fibo_set_net_type();
    result += fibo_set_bodysar_type();
    result += fibo_set_tasar_type();
    result += fibo_set_antenna_type();
    result += fibo_set_disableesim_for_sku(); */
    CFG_LOG_DEBUG("result = %d", result);
    /* if (result == 11) */
    if (result == 2)
    {
        CFG_LOG_DEBUG("set static config successfully!");
        return true;
    }
    else
    {
        CFG_LOG_DEBUG("set static config fail!");
        return false;
    }
}

bool fibo_static_ini_cfg()
{
    char file_path[128] = {0};
    INIT_LIST_HEAD(&s_ini_list);

    sprintf(file_path, "%s/%s", FIBO_APP_CONFIG_INI_PATH, FIBO_APP_CONFIG_INI);
    if (access(file_path, F_OK))
    {
        sprintf(file_path, "%s/%s", "./", FIBO_APP_CONFIG_INI);
        if (access(file_path, F_OK))
        {
            CFG_LOG_ERROR("file:%s,file is not exeist", file_path);
            return false;
        }
    }
    if (0 != fibo_config_parse(file_path, &s_ini_list))
    {
        CFG_LOG_CRITICAL("INI file parse error! exit");
        return false;
    }

    return true;
}

bool fibo_static_config_paese()
{
    bool result = true;

    if (!fibo_disable_esim_parse(&parse_data))
    {
        CFG_LOG_ERROR("parse disable_esim xml file failed!");
        result = false;
    }
    if (!fibo_region_mapping_parse(&region_map_data))
    {
        CFG_LOG_ERROR("parse region_mapping xml file failed!");
        result = false;
    }

    if (!fibo_devicemode_mapping_parse(&static_parse_data))
    {
        CFG_LOG_ERROR("parse devicemode_mapping_parse xml static data failed!");
        result = false;
    }
    // return true;
    get_current_oem();
    // test_data();
    // destory_list_memeory(); // destory malloc memory
    result = true;
    return result;
}
static bool static_config_doing = false; 
bool static_config_set(void)
{
    if(static_config_doing)
    {
        CFG_LOG_INFO("service_status config is config...!");
        return true;
    }
    if (!get_static_config_flg())
    {
        static_config_doing = true;
        if (fibo_get_config_and_set())
        {
            set_static_config_flg(true);
            static_config_doing = false;
            CFG_LOG_INFO("service_status config successfully!");
            return true;
        }
        else
        {
            static_config_doing = false;
            CFG_LOG_ERROR("service_status config fail!");
            return false;
        }
        
    }
    return true;
}


void fibo_deinit(void)
{
    destory_list_memeory();
}