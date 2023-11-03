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
 * @file dynamic_config.c
 * @author ziqi.zhao@fibocom.com (zhaoziqi)
 * @brief
 * @version 1.0
 * @date 2023-09-23
 *
 *
 **/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <semaphore.h>
#include <sys/sem.h>
#include "fibo_cfg_log.h"
#include "fibo_static_config.h"
#include "fibo_config_helper.h"
#include "fibo_dynamic_config.h"

#define STATUS_IS_NO "-1"
#define STATUS_IS_HW "0"
#define STATUS_IS_SW "1"

#define STATUS_IS_ENABLE "1"
#define STATUS_IS_DISABLE "0"

#define GET_CURRENT_MODEM_CONFIG(cid, status, type)                                                         \
    do                                                                                                      \
    {                                                                                                       \
        mesg_info *response = NULL;                                                                         \
        CFG_LOG_INFO("send message to dbus ,cid:%d", cid)                                                   \
        if (send_message_get_response(cid, "", 0, &response))                                               \
        {                                                                                                   \
            if (GET_DATA_SUCCESS == response->rtcode)                                                       \
            {                                                                                               \
                CFG_LOG_DEBUG("set cid:%d success!", cid);                                                  \
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
                        CFG_LOG_ERROR("[%d]payload unknown payload:%s", type, response->payload);           \
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

#define GET_CURRENT_MODEM_CONFIG_DATA(cid, status, rsppayload, rsp_len)             \
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

#define SET_DYNAMIC_CONFIG(cid, payload, len, status)                                                                 \
    do                                                                                                                \
    {                                                                                                                 \
        mesg_info *response = NULL;                                                                                   \
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

static int msg_id = -1;
static device_mode_sensor_t old_data = {0};

int get_dev_sensor_from_file(const char *key)
{
    FILE *fp = NULL;
    int code = 0;
    char *p = NULL;
    char strBuf[64] = {0};
    // return code;

    fp = fopen("/opt/fibocom/fibo_config_service/devicemode_sensor.txt", "r");
    if (fp == NULL)
    {
        // CFG_LOG_ERROR("can not open file:%s", key);
        return -1;
    }
    while (fgets(strBuf, 64, fp))
    {
        p = strstr(strBuf, key);
        if (NULL != p)
        {
            p = strstr(p, ":");
            code = atoi(p + 1);
            break;
        }
    }
    fclose(fp);
    return code;
}

int get_device_mode()
{
    int mode = 0;
    /* *****test start ***** */
    char *key = "devicemode";
    mode = get_dev_sensor_from_file(key);
    if (-1 == mode)
    {
        mode = 0;
    }
    // CFG_LOG_DEBUG("get data Key:%s,value:%d", key,mode);
    /* *****test end ***** */
    return mode;
}

int get_sensor1()
{
    int sensor = 0;
    /* *****test start ***** */
    char *key = "sensor1";
    sensor = get_dev_sensor_from_file(key);
    if (-1 == sensor)
    {
        sensor = 0;
    }
    // CFG_LOG_DEBUG("get data Key: %s,value:%d", key,sensor);
    /* *****test end ***** */
    return sensor;
}

int get_sensor2()
{
    int sensor = 0;
    /* *****test start ***** */
    char *key = "sensor2";
    sensor = get_dev_sensor_from_file(key);
    if (-1 == sensor)
    {
        sensor = 0;
    }
    // CFG_LOG_DEBUG("get data Key: %s,value:%d", key,sensor);
    /* *****test end ***** */
    return sensor;
}

int get_sensor3()
{
    int sensor = 0;
    /* *****test start ***** */
    char *key = "sensor3";
    sensor = get_dev_sensor_from_file(key);
    if (-1 == sensor)
    {
        sensor = 0;
    }
    // CFG_LOG_DEBUG("get data Key: %s,value:%d", key,sensor);
    /* *****test end ***** */
    return sensor;
}

int get_index_from_file(const char *key)
{
    FILE *fp = NULL;
    int code = 0;
    char *p = NULL;
    bool found = false;
    char strBuf[64] = {0};
    // return code;

    fp = fopen("/opt/fibocom/fibo_config_service/bios_index.txt", "r");
    if (fp == NULL)
    {
        // CFG_LOG_ERROR("can not open file:%s", key);
        return -1;
    }
    while (fgets(strBuf, 64, fp))
    {
        if(found)
        {
            code = atoi(strBuf);
            break;
        }
        
        if(NULL != strstr(strBuf, key))
        {
            found = true;
        }
    }
    fclose(fp);
    return code;
}

int get_index_from_bios(char *key)
{
    int index = 0;
    /* *****test start ***** */
    index = get_index_from_file(key);
    if (-1 == index)
    {
        index = 0;
    }
    // CFG_LOG_DEBUG("get data Key:%s,value:%d", key,mode);
    /* *****test end ***** */
    return index;
}


static void send_event_by_device_mode_change(int msg_id, sar_map_type map_type, device_mode_sensor_t *new_data)
{

    int result = 0;
    msg_st_t msg = {0};
    int msg_len = sizeof(msg_st_t) - sizeof(long int);
    /* CFG_LOG_DEBUG("devicemode info old device_mode:%d,old sensor1:%d,old sensor2:%d,old sensor3:%d,",
                (int)old_data->device_mode, (int)old_data->sensor1, (int)old_data->sensor2, (int)old_data->sensor3);
    CFG_LOG_DEBUG("devicemode info map_type:%d,device_mode:%d,sensor1:%d,sensor2:%d,sensor3:%d,",
                              (int)map_type, (int)new_data->device_mode, (int)new_data->sensor1, (int)new_data->sensor2, (int)new_data->sensor3); */
    if (SARMAP_TYPE_1 == map_type)
    {
        // do nothing
    }
    else
    {
        if (old_data.device_mode == new_data->device_mode && old_data.sensor1 == new_data->sensor1 && old_data.sensor2 == new_data->sensor2 && old_data.sensor3 == new_data->sensor3)
        {
            return;
        }
        CFG_LOG_INFO("devicemode and sensor changed,send message");
        msg.msg_type = DEVICE_MODE_CHANGE;
        msg.device.device_mode = new_data->device_mode;
        msg.device.sensor1 = new_data->sensor1;
        msg.device.sensor2 = new_data->sensor2;
        msg.device.sensor3 = new_data->sensor3;
        result = msgsnd(msg_id, (void *)&msg, msg_len, 0);
        if (-1 == result)
        {
            CFG_LOG_ERROR("send mccmnc change event error");
        }
        else
        {
            /*  old_data.device_mode = new_data->device_mode;
             old_data.sensor1 = new_data->sensor1;
             old_data.sensor2 = new_data->sensor2;
             old_data.sensor3 = new_data->sensor3; */
            CFG_LOG_DEBUG("send msg success,devicemode info map_type:%d,device_mode:%d,sensor1:%d,sensor2:%d,sensor3:%d,",
                          (int)map_type, (int)new_data->device_mode, (int)new_data->sensor1, (int)new_data->sensor2, (int)new_data->sensor3);
        }
    }
}

bool msg_init(void)
{
    key_t key = ftok(".", 'z');

    msg_id = msgget(key, 0666 | IPC_CREAT);

    if (-1 == msg_id)
    {
        CFG_LOG_ERROR("create message error ");
        return NULL;
    }
    return true;
}

int get_msg_id(void)
{
    return msg_id;
}

void *event_from_file_thread(void *arg)
{
    int result = 0;

    sar_map_type map_type;
    device_mode_sensor_t new_data = {0};

    map_type = fibo_get_sarmaptype();
    while (1)
    {
        if (map_type >= SARMAP_TYPE_1 && map_type <= SARMAP_TYPE_5)
        {
            if (map_type >= SARMAP_TYPE_2)
            {
                new_data.device_mode = get_device_mode();
            }
            if (map_type >= SARMAP_TYPE_3)
            {
                new_data.sensor1 = get_sensor1();
            }
            if (map_type >= SARMAP_TYPE_4)
            {
                new_data.sensor2 = get_sensor2();
            }
            if (map_type >= SARMAP_TYPE_5)
            {
                new_data.sensor3 = get_sensor3();
            }
            send_event_by_device_mode_change(msg_id, map_type, &new_data);
        }
        sleep(1);
    }
}

void *event_from_signal_thread(void *arg)
{
    char mccmnc_old[8] = {0};
    int result = 0;
    sar_map_type map_type;
    device_mode_sensor_t old_data = {0};
    device_mode_sensor_t new_data = {0};

    map_type = fibo_get_sarmaptype();

    /* through signal or callback get devicemode and sensor information */
    if (map_type >= SARMAP_TYPE_1 && map_type <= SARMAP_TYPE_5)
    {
        if (map_type >= SARMAP_TYPE_2)
        {
            new_data.device_mode = get_device_mode();
        }
        if (map_type >= SARMAP_TYPE_3)
        {
            new_data.sensor1 = get_sensor1();
        }
        if (map_type >= SARMAP_TYPE_4)
        {
            new_data.sensor2 = get_sensor2();
        }
        if (map_type >= SARMAP_TYPE_5)
        {
            new_data.sensor3 = get_sensor3();
        }
        send_event_by_device_mode_change(msg_id, map_type, &new_data);
    }
}

bool get_body_sar_enable(void)
{
    int status = 0;

    GET_CURRENT_MODEM_CONFIG(GET_BODYSAR_STATUS, status, TYPE_QUERY);
    if (STATUS_ENABLE == status)
    {
        return true;
    }
    return false;
}

bool get_body_sar_is_sw_mode(void)
{
    int status = 0;

    GET_CURRENT_MODEM_CONFIG(GET_BODYSAR_CTRL_MODE, status, STATUS_QUERY);
    if (STATUS_SW == status)
    {
        return true;
    }
    return false;
}

bool get_ta_sar_enable(void)
{
    int status = 0;

    GET_CURRENT_MODEM_CONFIG(GET_TASAR_STATUS, status, TYPE_QUERY);
    if (STATUS_ENABLE == status)
    {
        return true;
    }
    return false;
}

bool get_ta_sar_is_sw_mode(void)
{
    int status = 0;

    GET_CURRENT_MODEM_CONFIG(GET_TASAR_CTRL_MODE, status, STATUS_QUERY);
    if (STATUS_SW == status)
    {
        return true;
    }
    return false;
}

bool get_antenna_enable(void)
{
    int status = 0;

    GET_CURRENT_MODEM_CONFIG(GET_ANTENNA_STATUS, status, TYPE_QUERY);
    if (STATUS_ENABLE == status)
    {
        return true;
    }
    return false;
}

bool get_antenna_is_sw_mode(void)
{
    int status = 0;

    GET_CURRENT_MODEM_CONFIG(GET_ANTENNA_CTRL_MODE, status, STATUS_QUERY);
    if (STATUS_SW == status)
    {
        return true;
    }
    return false;
}

static bool get_sar_index(msg_st_t *msg, char *mcc, char *index)
{
    bool result = false;
    sar_index_para_t input_data = {0};

    strcpy(input_data.wwanconfigid, fibo_get_wwanconfigid());
    if (SLUCTION_TYPE_SW_BIOS == fibo_get_customizationsolutiontype())
    {
        // get index from bios reserved
        char *regulatory = get_region_regulatory(mcc);
        *index = get_index_from_bios(regulatory);
        CFG_LOG_INFO("get sar index:%d,from bios", *index);
        return true;
    }
    else if (SLUCTION_TYPE_SW_XML == fibo_get_customizationsolutiontype())
    {
        input_data.sar_map_type = fibo_get_sarmaptype();

        input_data.standard = get_region_regulatory(mcc);
        CFG_LOG_DEBUG("wwanconfigid:%s,regulatory:%s", input_data.wwanconfigid, input_data.standard);
        CFG_LOG_DEBUG("get sar wwanconfigid:%s device_mode:%d,sensor1:%d,sensor2:%d,sensor3:%d",
                      input_data.wwanconfigid, msg->device.device_mode, msg->device.sensor1,
                      msg->device.sensor2, msg->device.sensor3);
        input_data.device.device_mode = msg->device.device_mode;
        input_data.device.sensor1 = msg->device.sensor1;
        input_data.device.sensor2 = msg->device.sensor2;
        input_data.device.sensor3 = msg->device.sensor3;
        result = fibo_get_sar_index(&input_data, index);
        CFG_LOG_INFO("get sar index:%d,result:%d", *index, result);
        return result;
    }
    return false;
}

static bool set_antenna_index(msg_st_t *msg)
{
    char index = 0;
    char wwanconfigid[64] = {0};
    int status = 0;
    char payload[8] = {0};
    bool result = false;

    strcpy(wwanconfigid, fibo_get_wwanconfigid());
    if (STATUS_OFF == fibo_get_antturnerstate())
    {
        return false;
    }
    if (get_antenna_enable())
    {
        if (get_antenna_is_sw_mode())
        {
            result = fibo_get_antenna_index(wwanconfigid, msg->device.device_mode, &index);
            if (!result)
            {
                CFG_LOG_ERROR("not find index from xml");
                return false;
            }
            sprintf(payload, "%d", index);
            CFG_LOG_INFO("get antenna index ok,index:%d,payload:%s", index, payload);
            SET_DYNAMIC_CONFIG(SET_ANTENNA_INDEX, payload, strlen(payload), status);
            if (GET_DATA_SUCCESS == status)
            {
                CFG_LOG_INFO("set antenna index:%d success!", index);
                return true;
            }
        }
    }
    return false;
}

static bool set_sar_index(msg_st_t *msg, char *mcc, bool is_simchange)
{
    char sar_index = 0;
    sar_type sartype = SAR_TYPE_UNKNOWN;
    sartype = fibo_get_sartype();
    bool ret = false;

    int status = 0;
    char payload[8] = {0};

    CFG_LOG_DEBUG("sartype:%d", sartype);
    if (is_simchange)
    {
        if (DOWN_LOAD_AT == get_sardownloadtype())
        {
            // reserved
        }
        else if (DOWN_LOAD_FLASH == get_sardownloadtype())
        {
            // The image is processed by the flash service
        }
    }

    if (SAR_TYPE_NOTHING == sartype)
    {
        return false;
    }
    else if (SAR_TYPE_BODYSAR == sartype)
    {
        if (get_body_sar_enable())
        {
            if (get_body_sar_is_sw_mode())
            {
                ret = get_sar_index(msg, mcc, &sar_index);
                if (!ret)
                {
                    CFG_LOG_ERROR("not find index from xml");
                    return false;
                }
                sprintf(payload, "%d", sar_index);
                CFG_LOG_INFO("get sar index ok,index:%d,payload:%s", sar_index, payload);
                SET_DYNAMIC_CONFIG(SET_BODYSAR_INDEX, payload, strlen(payload), status);
                if (GET_DATA_SUCCESS == status)
                {
                    CFG_LOG_INFO("set bodysar index:%d success!", sar_index);
                    return true;
                }
            }
        }
    }
    else if (SAR_TYPE_TASAR == fibo_get_sartype())
    {
        if (get_ta_sar_enable())
        {
            if (get_ta_sar_is_sw_mode())
            {
                ret = get_sar_index(msg, mcc, &sar_index);
                if (!ret)
                {
                    CFG_LOG_ERROR("not find index from xml");
                    return false;
                }
                sprintf(payload, "%d", sar_index);
                CFG_LOG_INFO("get sar index ok,index:%d,payload:%s", sar_index, payload);
                SET_DYNAMIC_CONFIG(SET_TASAR_INDEX, payload, strlen(payload), status);
                if (GET_DATA_SUCCESS == status)
                {
                    CFG_LOG_INFO("set tasar index:%d success!", sar_index);
                    return true;
                }
            }
        }
    }
    return false;
}

static bool set_sar_antenna_config(msg_st_t *msg, char *mcc, bool is_simchange)
{

    if (old_data.device_mode == msg->device.device_mode && old_data.sensor1 == msg->device.sensor1 && old_data.sensor2 == msg->device.sensor2 && old_data.sensor3 == msg->device.sensor3)
    {
        CFG_LOG_INFO("devicemode and sensor not change not send index...")
        return true;
    }
    CFG_LOG_DEBUG("[old]:device_mode:%d,sensor1:%d,sensor2:%d sensor3:%d[new]:device_mode:%d,sensor1:%d,sensor2:%d sensor3:%d[mcc]:%s",
                  old_data.device_mode, old_data.sensor1,
                  old_data.sensor2, old_data.sensor3, msg->device.device_mode, msg->device.sensor1,
                  msg->device.sensor2, msg->device.sensor3, mcc);
    set_sar_index(msg, mcc, is_simchange);
    set_antenna_index(msg);

    old_data.device_mode = msg->device.device_mode;
    old_data.sensor1 = msg->device.sensor1;
    old_data.sensor2 = msg->device.sensor2;
    old_data.sensor3 = msg->device.sensor3;

    return true;
}

void get_regulatory_from_xml(char *mcc,char *regulatory)
{
    char *data = NULL;
    char mcc_data[16] = {0};
    if(NULL == mcc)
    {
        CFG_LOG_DEBUG("mcc is NULL,using default");
        strncpy(mcc_data, "default", strlen("default"));
    }
    else
    {
        strncpy(mcc_data, mcc, strlen(mcc));
    }
    
    data = get_region_regulatory(mcc);
    if(NULL == data)
    {
        strncpy(regulatory, "FCC", strlen("FCC"));
    }
    else
    {
        strncpy(regulatory, data, strlen(data));
    }
}

void set_regulatory_to_bios(char *regulatory)
{
    /* set data to bios  reserved*/
    if(0 == strncmp(regulatory,"FCC",strlen("FCC")))
    {
        // set 1 regulatory to bios
    }
    else if(0 == strncmp(regulatory,"CE",strlen("CE")))
    {
        // set 2 regulatory to bios
    }
    else if(0 == strncmp(regulatory,"ISED",strlen("ISED")))
    {
        //set 3  regulatory to bios
    }
}

void *dynamic_thread(void *arg)
{
    int msg_size = 0;
    msg_st_t msg = {0};
    char mcc_data[16] = {0};
    int msg_len = 0;

    msg_len = sizeof(msg_st_t) - sizeof(long int);

    while (1)
    {
        CFG_LOG_DEBUG("wait mesg...");
        msg_size = msgrcv(msg_id, (void *)&msg, msg_len, 0, 0);
        CFG_LOG_DEBUG("<<<<<--- receive msg,msg_size:%d,msg_type:%d", msg_size, (int)msg.msg_type);
        CFG_LOG_DEBUG("receive msg,mcc:%s,devicemode:%d,sensor1:%d,sensor2:%d,sensor3:%d", msg.mccmnc, msg.device.device_mode, msg.device.sensor1, msg.device.sensor2, msg.device.sensor3);
        if (msg_size >= 0)
        {
            if (msg.msg_type == MCCMNC_CHANGE)
            {
                strcpy(mcc_data, msg.mccmnc);
                if (SLUCTION_TYPE_SW_BIOS == fibo_get_customizationsolutiontype())
                {
                    char regulatory[16] = {0};
                    get_regulatory_from_xml(mcc_data,regulatory);

                    /* set  regulatory to bios*/
                    set_regulatory_to_bios(regulatory);
                }
                else if (SLUCTION_TYPE_SW_XML == fibo_get_customizationsolutiontype())
                {
                    set_sar_antenna_config(&msg, mcc_data, true);
                }
            }
            else if (msg.msg_type == DEVICE_MODE_CHANGE)
            {
                char *data = fibo_get_mcc_value();
                if (data == NULL)
                {
                    strncpy(mcc_data, "default", strlen("default"));
                }
                else
                {
                    strncpy(mcc_data, data, strlen(data));
                }
                set_sar_antenna_config(&msg, mcc_data, false);
            }
        }
    }
}

void dynamic_deinit(void)
{
    msgctl(msg_id, IPC_RMID, NULL);
}