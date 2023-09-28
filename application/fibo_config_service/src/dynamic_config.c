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
#include<semaphore.h>
#include<sys/sem.h>
#include "cfg_log.h"
#include "static_config.h"
#include "config_helper.h"

#define STATUS_IS_NO "0"
#define STATUS_IS_HW "1"
#define STATUS_IS_SW "2"

#define STATUS_IS_ENABLE "1"
#define STATUS_IS_DISABLE "0"

typedef enum
{
    MCCMNC_CHANGE = 1,
    DEVICE_MODE_CHANGE,
} mesage_type;

typedef struct msg_st_s
{
    long int msg_type;
    char mccmnc[4];
    char device_mode;
    char sensor1;
    char sensor2;
    char sensor3;
} msg_st_t;


typedef struct device_mode_sensor_s
{
    char device_mode;
    char sensor1;
    char sensor2;
    char sensor3;
} device_mode_sensor_t;

#define GET_CURRENT_MODEM_CONFIG(cid, status, type)                                                         \
    do                                                                                                      \
    {                                                                                                       \
        mesg_info *response = NULL;                                                                         \
        if (!get_dbus_connect_flg())                                                                        \
        {                                                                                                   \
            status = STATUS_DBUS_ERROR;                                                                     \
            CFG_LOG_ERROR("dbus can not send message");                                                     \
        }                                                                                                   \
        CFG_LOG_DEBUG("send message to dbus ,cid:%d", cid)                                                  \
        if (send_message_get_response(cid, "", 0, &response))                                               \
        {                                                                                                   \
            if (GET_DATA_SUCCESS == response->rtcode)                                                       \
            {                                                                                               \
                status = GET_DATA_SUCCESS;                                                                  \
                CFG_LOG_INFO("set cid:%d success!", cid);                                                   \
                if (STATUS_QUERY == type)                                                                   \
                {                                                                                           \
                    if (0 == strncmp(response->payload, STATUS_IS_NO, strlen(STATUS_IS_NO)))                \
                    {                                                                                       \
                        status = STATUS_OFF;                                                                 \
                    }                                                                                       \
                    else if (0 == strncmp(response->payload, STATUS_IS_HW, strlen(STATUS_IS_HW)))           \
                    {                                                                                       \
                        status = STATUS_HW;                                                                 \
                    }                                                                                       \
                    else if (0 == strncmp(response->payload, STATUS_IS_SW, strlen(STATUS_IS_SW)))           \
                    {                                                                                       \
                        status = STATUS_SW;                                                                 \
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
                status = GET_DATA_FAIL;                                                                     \
                CFG_LOG_ERROR("set cid:%d fail!", cid);                                                     \
            }                                                                                               \
        }                                                                                                   \
        else                                                                                                \
        {                                                                                                   \
            status = GET_DATA_FAIL;                                                                         \
            CFG_LOG_ERROR("send message error");                                                            \
        }                                                                                                   \
        if (NULL != response)                                                                               \
        {                                                                                                   \
            free(response);                                                                                 \
            response = NULL;                                                                                \
        }                                                                                                   \
    } while (0);

#define GET_CURRENT_MODEM_CONFIG_DATA(cid, status, type, rsppayload, rsp_len)       \
    do                                                                              \
    {                                                                               \
        mesg_info *response = NULL;                                                 \
        if (!get_dbus_connect_flg())                                                \
        {                                                                           \
            status = STATUS_DBUS_ERROR;                                             \
            CFG_LOG_ERROR("dbus can not send message");                             \
        }                                                                           \
        CFG_LOG_DEBUG("send message to dbus ,cid:%d", cid)                          \
        if (send_message_get_response(cid, "", 0, &response))                       \
        {                                                                           \
            if (GET_DATA_SUCCESS == response->rtcode)                               \
            {                                                                       \
                status = GET_DATA_SUCCESS;                                          \
                CFG_LOG_INFO("set cid:%d success!", cid);                           \
                if (DATA_QUERY == type)                                             \
                {                                                                   \
                    status = GET_DATA_SUCCESS;                                      \
                    memcpy(rsppayload, response->payload, response->payload_lenth); \
                    rsp_len = response->payload_lenth;                              \
                }                                                                   \
            }                                                                       \
            else                                                                    \
            {                                                                       \
                status = GET_DATA_FAIL;                                             \
                CFG_LOG_ERROR("set cid:%d fail!", cid);                             \
            }                                                                       \
        }                                                                           \
        else                                                                        \
        {                                                                           \
            status = GET_DATA_FAIL;                                                 \
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
        if (!get_dbus_connect_flg())                                                                                  \
        {                                                                                                             \
            status = STATUS_DBUS_ERROR;                                                                               \
            CFG_LOG_ERROR("dbus can not send message");                                                               \
        }                                                                                                             \
        if (send_message_get_response(cid, payload, len, &response))                                                  \
        {                                                                                                             \
            if (GET_DATA_SUCCESS == response->rtcode)                                                                 \
            {                                                                                                         \
                status = GET_DATA_SUCCESS;                                                                            \
                CFG_LOG_INFO("set cid:%d success!", cid);                                                             \
            }                                                                                                         \
            else                                                                                                      \
            {                                                                                                         \
                status = GET_DATA_FAIL;                                                                               \
                CFG_LOG_ERROR("set cid:%d fail!", cid);                                                               \
                if (NULL != response)                                                                                 \
                {                                                                                                     \
                    free(response);                                                                                   \
                    response = NULL;                                                                                  \
                }                                                                                                     \
                return false;                                                                                         \
            }                                                                                                         \
        }                                                                                                             \
        else                                                                                                          \
        {                                                                                                             \
            status = GET_DATA_FAIL;                                                                                   \
            CFG_LOG_INFO("set cid:%d ,retcode:%d,error!", cid, ((response == NULL) ? UNKNOW_CODE : response->rtcode)) \
        }                                                                                                             \
        if (NULL != response)                                                                                         \
        {                                                                                                             \
            free(response);                                                                                           \
            response = NULL;                                                                                          \
        }                                                                                                             \
    } while (0);

static sem_t mcc_sem_id;
static sem_t device_sem_id;
static int msg_id = -1;


int get_data_from_file(const char *key)
{
    FILE *fp = NULL;
    int code = 0;
    char *p = NULL;
    char strBuf[64] = {0};
    // return code;

    fp = fopen("./test.txt", "r");
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
    mode = get_data_from_file(key);
    // CFG_LOG_DEBUG("get data Key:%s,value:%d", key,mode);
    /* *****test end ***** */
    return mode;
}

int get_sensor1()
{
    int sensor = 0;
    /* *****test start ***** */
    char *key = "sensor1";
    sensor = get_data_from_file(key);
    // CFG_LOG_DEBUG("get data Key: %s,value:%d", key,sensor);
    /* *****test end ***** */
    return sensor;
}

int get_sensor2()
{
    int sensor = 0;
    /* *****test start ***** */
    char *key = "sensor2";
    sensor = get_data_from_file(key);
    // CFG_LOG_DEBUG("get data Key: %s,value:%d", key,sensor);
    /* *****test end ***** */
    return sensor;
}

int get_sensor3()
{
    int sensor = 0;
    /* *****test start ***** */
    char *key = "sensor3";
    sensor = get_data_from_file(key);
    // CFG_LOG_DEBUG("get data Key: %s,value:%d", key,sensor);
    /* *****test end ***** */
    return sensor;
}

static void send_event_by_mcc_change(int msg_id, char *mccmnc_old)
{
    int result = 0;
    char *mccmnc_new = NULL;
    msg_st_t msg = {0};

    int msg_len = sizeof(msg_st_t) - sizeof(long int);

    fibo_set_disableesim_for_mcc();
    fibo_set_sim_change(false);
    mccmnc_new = fibo_get_mcc_value();
    CFG_LOG_DEBUG("get mcc success,mccmnc_new:%s", mccmnc_new);
    if (mccmnc_new == NULL)
    {
        // goto dev_monitor;
        CFG_LOG_ERROR("get mcc error");
        return;
    }
    if (0 != strcmp(mccmnc_old, mccmnc_new))
    {
        msg.msg_type = MCCMNC_CHANGE;
        strncpy(msg.mccmnc, mccmnc_new, sizeof(msg.mccmnc));
        result = msgsnd(msg_id, (void *)&msg, msg_len, 0);
        if (result)
        {
            CFG_LOG_ERROR("send mccmnc change event error,result:%d", result);
        }
        else
        {
            CFG_LOG_DEBUG("send msg success,mcc change mccmnc_new:%s", mccmnc_new);
            strncpy(mccmnc_old, mccmnc_new, strlen(mccmnc_new));
        }
    }
}

static void send_event_by_device_mode_change(int msg_id, sar_map_type map_type, device_mode_sensor_t *old_data, device_mode_sensor_t *new_data)
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
    else if (SARMAP_TYPE_2 == map_type)
    {
        if (old_data->device_mode != new_data->device_mode)
        {
            msg.msg_type = DEVICE_MODE_CHANGE;
            msg.device_mode = new_data->device_mode;
            result = msgsnd(msg_id, (void *)&msg, msg_len, 0);
            if (-1 == result)
            {
                CFG_LOG_ERROR("send mccmnc change event error");
            }
            else
            {
                old_data->device_mode = new_data->device_mode;
                CFG_LOG_DEBUG("send msg success,devicemode info map_type:%d,device_mode:%d",
                              (int)map_type, (int)new_data->device_mode);
            }
        }
    }
    else if (SARMAP_TYPE_3 == map_type)
    {
        if (old_data->device_mode != new_data->device_mode || old_data->sensor1 != new_data->sensor1)
        {
            msg.msg_type = DEVICE_MODE_CHANGE;
            msg.device_mode = new_data->device_mode;
            msg.sensor1 = new_data->sensor1;
            result = msgsnd(msg_id, (void *)&msg, msg_len, 0);
            if (-1 == result)
            {
                CFG_LOG_ERROR("send mccmnc change event error");
            }
            else
            {
                old_data->device_mode = new_data->device_mode;
                old_data->sensor1 = new_data->sensor1;
                CFG_LOG_DEBUG("send msg success,devicemode info map_type:%d,device_mode:%d,sensor1:%d",
                              (int)map_type, (int)new_data->device_mode, (int)new_data->sensor1);
            }
        }
    }
    else if (SARMAP_TYPE_4 == map_type)
    {
        if (old_data->device_mode != new_data->device_mode || old_data->sensor1 != new_data->sensor1 || old_data->sensor2 != new_data->sensor2)
        {
            msg.msg_type = DEVICE_MODE_CHANGE;
            msg.device_mode = new_data->device_mode;
            msg.sensor1 = new_data->sensor1;
            msg.sensor2 = new_data->sensor2;
            result = msgsnd(msg_id, (void *)&msg, msg_len, 0);
            if (-1 == result)
            {
                CFG_LOG_ERROR("send mccmnc change event error");
            }
            else
            {
                old_data->device_mode = new_data->device_mode;
                old_data->sensor1 = new_data->sensor1;
                old_data->sensor2 = new_data->sensor2;
                CFG_LOG_DEBUG("send msg success,devicemode info map_type:%d,device_mode:%d,sensor1:%d,sensor2:%d",
                              (int)map_type, (int)new_data->device_mode, (int)new_data->sensor1, (int)new_data->sensor2);
            }
        }
    }
    else if (SARMAP_TYPE_5 == map_type)
    {
        if (old_data->device_mode != new_data->device_mode || old_data->sensor1 != new_data->sensor1 || old_data->sensor2 != new_data->sensor2 || old_data->sensor3 != new_data->sensor3)
        {
            msg.msg_type = DEVICE_MODE_CHANGE;
            msg.device_mode = new_data->device_mode;
            msg.sensor1 = new_data->sensor1;
            msg.sensor2 = new_data->sensor2;
            msg.sensor3 = new_data->sensor3;
            result = msgsnd(msg_id, (void *)&msg, msg_len, 0);
            if (-1 == result)
            {
                CFG_LOG_ERROR("send mccmnc change event error");
            }
            else
            {
                old_data->device_mode = new_data->device_mode;
                old_data->sensor1 = new_data->sensor1;
                old_data->sensor2 = new_data->sensor2;
                old_data->sensor3 = new_data->sensor3;
                CFG_LOG_DEBUG("send msg success,devicemode info map_type:%d,device_mode:%d,sensor1:%d,sensor2:%d,sensor3:%d,",
                              (int)map_type, (int)new_data->device_mode, (int)new_data->sensor1, (int)new_data->sensor2, (int)new_data->sensor3);
            }
        }
    }
}



static bool msg_init()
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

sem_t *get_mcc_sem_id(void)
{
    return &mcc_sem_id;
}

sem_t *get_device_sem_id(void)
{
    return &device_sem_id;
}

void *event_from_file_thread(void *arg)
{
    char mccmnc_old[16] = {0};

    int result = 0;

    sar_map_type map_type;

    device_mode_sensor_t old_data = {0};
    device_mode_sensor_t new_data = {0};

    if(!msg_init())
    {
        CFG_LOG_ERROR("msg_init failed");
        return NULL;
    }
    map_type = fibo_get_sarmaptype();
    while (1)
    {
        if (false == fibo_get_sim_reign())
        {
            sleep(1); // sim not region not dynamic config
            continue;
        }
        if (fibo_get_sim_change())
        {
            send_event_by_mcc_change(msg_id, mccmnc_old);
            CFG_LOG_DEBUG("mccmnc_old:%s", mccmnc_old);
        }
        if (map_type >= SARMAP_TYPE_1 && map_type <= SARMAP_TYPE_5)
        {
            new_data.device_mode = get_device_mode();
            new_data.sensor1 = get_sensor1();
            new_data.sensor2 = get_sensor2();
            new_data.sensor3 = get_sensor3();
            
            send_event_by_device_mode_change(msg_id,map_type,&old_data,&new_data);
            
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

    if(!msg_init())
    {
        CFG_LOG_ERROR("msg_init failed");
        return NULL;
    }

    if(0 != sem_init(&mcc_sem_id, 0, 0))
    {
        CFG_LOG_ERROR("mcc_sem failed");
        return NULL;
    }
    
    if(0 != sem_init(&device_sem_id, 0, 0))
    {
        CFG_LOG_ERROR("device_sem failed");
        return NULL;
    }

    map_type = fibo_get_sarmaptype();

    while(1)
    {
        if(0 == sem_wait(&mcc_sem_id))
        {
            CFG_LOG_DEBUG("sem_get value");
            send_event_by_mcc_change(msg_id, mccmnc_old);
            CFG_LOG_DEBUG("mccmnc_old:%s", mccmnc_old);
        }
        else if(0 == sem_wait(&device_sem_id))
        {
            CFG_LOG_DEBUG("sem_get value");
            new_data.device_mode = get_device_mode();
            new_data.sensor1 = get_sensor1();
            new_data.sensor2 = get_sensor2();
            new_data.sensor3 = get_sensor3();
            send_event_by_device_mode_change(msg_id,map_type,&old_data,&new_data);
        }
    }
}


bool get_body_sar_enable(void)
{
    int status = 0;

    GET_CURRENT_MODEM_CONFIG(GET_BODYSAR_STATUS, status, STATUS_QUERY);
    if (STATUS_ENABLE == status)
    {
        return true;
    }
    else
    {
        return false;
    }
}

bool get_body_sar_is_sw_mode(void)
{
    int status = 0;

    GET_CURRENT_MODEM_CONFIG(GET_BODYSAR_CTRL_MODE, status, TYPE_QUERY);
    if (STATUS_SW == status)
    {
        return true;
    }
    return true;
}

bool get_ta_sar_enable(void)
{
    int status = 0;

    GET_CURRENT_MODEM_CONFIG(GET_TASAR_STATUS, status, STATUS_QUERY);
    if (STATUS_ENABLE == status)
    {
        return true;
    }
    else
    {
        return false;
    }
}

bool get_ta_sar_is_sw_mode(void)
{
    int status = 0;

    GET_CURRENT_MODEM_CONFIG(GET_TASAR_CTRL_MODE, status, TYPE_QUERY);
    if (STATUS_SW == status)
    {
        return true;
    }
    return false;
}

bool get_antenna_enable(void)
{
    int status = 0;

    GET_CURRENT_MODEM_CONFIG(GET_ANTENNA_STATUS, status, STATUS_QUERY);
    if (STATUS_ENABLE == status)
    {
        return true;
    }
    else
    {
        return false;
    }
}

bool get_antenna_is_sw_mode(void)
{
    int status = 0;

    GET_CURRENT_MODEM_CONFIG(GET_ANTENNA_CTRL_MODE, status, TYPE_QUERY);
    if (STATUS_SW == status)
    {
        return true;
    }
    return true;
}

static bool get_sar_index(msg_st_t *msg, char *mcc, char *index)
{
    sar_map_type map_type = 0;
    char *regulatory = NULL;
    char wwanconfigid[64] = {0};
    bool result = false;

    strcpy(wwanconfigid, fibo_get_wwanconfigid());
    if (SLUCTION_TYPE_SW_BIOS == fibo_get_customizationsolutiontype())
    {
        // reserved
    }
    else if (SLUCTION_TYPE_SW_XML == fibo_get_customizationsolutiontype())
    {
        map_type = fibo_get_sarmaptype();

        regulatory = get_region_regulatory(mcc);
        CFG_LOG_DEBUG("wwanconfigid:%s,regulatory:%s", wwanconfigid, regulatory);
        CFG_LOG_DEBUG("get sar wwanconfigid:%s device_mode:%d,sensor1:%d,sensor2:%d,sensor3:%d",
                      wwanconfigid, msg->device_mode, msg->sensor1,
                      msg->sensor2, msg->sensor3);
        result = fibo_get_sar_index(map_type, wwanconfigid, regulatory, msg->device_mode, msg->sensor1,
                                   msg->sensor2, msg->sensor3, index);
        CFG_LOG_DEBUG("get sar index:%d,result:%d", *index, result);
        return result;
    }
    return false;
}

static bool get_antenna_index(msg_st_t *msg)
{
    char index = 0;
    char wwanconfigid[64] = {0};
    int status = 0;
    char payload[8] = {0};
    bool result = false;

    strcpy(wwanconfigid, fibo_get_wwanconfigid());
    if (ANTENNA_TYPE_DISABLE == fibo_get_antturnerstate())
    {
        return false;
    }
    if (get_antenna_enable())
    {
        if (get_antenna_is_sw_mode())
        {
            result = fibo_get_antenna_index(wwanconfigid, msg->device_mode, &index);
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
}

bool set_sar_config(msg_st_t *msg, char *mcc, bool is_simchange)
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
        else if (DOWN_LOAD_IMAGE == get_sardownloadtype())
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
}

bool set_sar_antenna_config(msg_st_t *msg, char *mcc, bool is_simchange)
{
    set_sar_config(msg, mcc, is_simchange);
    get_antenna_index(msg);
}

void *dynamic_thread(void *arg)
{
    int msg_size = 0;
    msg_st_t msg = {0};
    char mcc_data[16] = {0};
    int msg_len = 0;

    msg_len = sizeof(msg_st_t) - sizeof(long int);

    if(!msg_init())
    {
        CFG_LOG_ERROR("msg_init failed");
        return NULL;
    }

    while (1)
    {
        CFG_LOG_DEBUG("recive msg,msg_size************************");
        msg_size = msgrcv(msg_id, (void *)&msg, msg_len, 0, 0);
        CFG_LOG_DEBUG("recive msg,msg_size:%d,msg_type:%d", msg_size, (int)msg.msg_type);
        CFG_LOG_DEBUG("recive msg,mcc:%s,devicemode:%d,sensor1:%d,sensor2:%d,sensor3:%d", msg.mccmnc, msg.device_mode, msg.sensor1, msg.sensor2, msg.sensor3);
        if (msg_size >= 0)
        {
            if (msg.msg_type == MCCMNC_CHANGE)
            {
                strcpy(mcc_data, msg.mccmnc);
                if (SLUCTION_TYPE_SW_BIOS == fibo_get_customizationsolutiontype())
                {
                    // reserved
                }
                else if (SLUCTION_TYPE_SW_XML == fibo_get_customizationsolutiontype())
                {
                    set_sar_antenna_config(&msg, mcc_data, true);
                }
            }
            else if (msg.msg_type == DEVICE_MODE_CHANGE)
            {

                set_sar_antenna_config(&msg, mcc_data, false);
            }
        }
    }
}



void dynamic_deinit(void)
{
    sem_destroy(&mcc_sem_id);
    sem_destroy(&device_sem_id);
    msgctl(msg_id, IPC_RMID,NULL);
}