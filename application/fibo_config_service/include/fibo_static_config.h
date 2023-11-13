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
 * @file static_config.h
 * @author ziqi.zhao@fibocom.com (zhaoziqi)
 * @brief
 * @version 1.0
 * @date 2023-09-23
 *
 *
 **/

#ifndef __STATIC_CONFIG_H__
#define __STATIC_CONFIG_H__

#include <stdio.h>

typedef enum log_level_s
{
    DEBUG_LOG_LEVEL = 0,
    INFO_LOG_LEVEL,
    NOTICE_LOG_LEVEL,
    WARNING_LOG_LEVEL,
    ERROR_LOG_LEVEL,
    CRITICAL_LOG_LEVEL,
    LOG_LEVEL_UNKNOWN = -1,
} log_level_t;

typedef enum sar_map_type_s
{
    SARMAP_TYPE_NO = 0,
    SARMAP_TYPE_1,
    SARMAP_TYPE_2,
    SARMAP_TYPE_3,
    SARMAP_TYPE_4,
    SARMAP_TYPE_5,
    SAR_MAP_TYPE_UNKNOWN = -1,
} sar_map_type;

typedef enum sar_type_s
{
    SAR_TYPE_NOTHING = 0,
    SAR_TYPE_BODYSAR,
    SAR_TYPE_TASAR,
    SAR_TYPE_UNKNOWN = -1,
} sar_type;

typedef enum custom_solucion_type_t
{
    SLUCTION_TYPE_NO = 1,
    SLUCTION_TYPE_SW_BIOS,
    SLUCTION_TYPE_SW_XML,
    SLUCTION_TYPE_UNKNOWN = -1,
} custom_solucion_type;

typedef enum net_type_t
{
    NET_TYPE_FUNC_OFF = 0,
    NET_TYPE_2G,
    NET_TYPE_3G,
    NET_TYPE_4G,
    NET_TYPE_5G,
    NET_TYPE_UNKNOWN = -1,
} net_type;

typedef enum soltion_type_t
{
    SOLTION_DISABLE = 1,
    SOLTION_BIOS,
    SOLTION_XML,
    SOLTION_UNKNOWN = -1,
} soltion_type;

typedef enum sar_download_type_t
{
    DOWN_LOAD_FLASH = 1,
    DOWN_LOAD_AT,
    DOWN_LOAD_UNKNOWN = -1,
} sar_download_type;

typedef enum
{
    STATUS_OFF = 0,
    STATUS_HW,
    STATUS_SW,
    STATUS_UNKNOWN = -1,
} switch_status;

typedef enum
{
    SIM_SLOTS_FUNC_OFF = 0,
    SIM_SLOTS_SWITCH_1,
    SIM_SLOTS_SWITCH_2,
    SIM_SLOTS__UNKNOWN = -1,
} sim_slots;

typedef enum
{
    STATUS_FUNC_OFF = 0,
    STATUS_DISABLE,
    STATUS_ENABLE,
} enable_status;

typedef enum
{
    SERVICE_STOP = 0,
    SERVICE_RUN,
} service_status;


typedef enum
{
    STATUS_QUERY = 0,
    TYPE_QUERY,
    DATA_QUERY,
} send_message_type;

typedef enum
{
    DELL = 0,
    LENOVO,
    HP,
    UNKNOW = -1,
} oem_type;

typedef struct device_mode_sensor_s
{
    char device_mode;
    char sensor1;
    char sensor2;
    char sensor3;
} device_mode_sensor_t;

typedef struct sar_index_para_s
{
    sar_map_type sar_map_type;
    char wwanconfigid[64];
    char *standard;
    device_mode_sensor_t device;
} sar_index_para_t;

int fibo_device_mode_get(void);
int fibo_get_start_state(void);

sar_map_type fibo_get_sarmaptype(void);

sar_download_type get_sardownloadtype(void);

sar_type fibo_get_sartype(void);

bool fibo_get_config_and_set(void);

switch_status fibo_get_antturnerstate(void);

custom_solucion_type fibo_get_customizationsolutiontype(void);

char *get_region_regulatory(char *mcc);

bool fibo_get_sar_index(sar_index_para_t *input_data, char *index);

bool fibo_get_antenna_index(char *wwanconfigid, char device_mode, char *index);

bool fibo_set_debug_level(void);
char *fibo_get_wwanconfigid(void);
char *fibo_get_skuid(void);
bool fibo_set_disableesim_for_mcc(void);
bool fibo_static_config_paese();
bool fibo_static_ini_cfg();
void fibo_deinit(void);
bool static_config_set(void);

#endif /* __STATIC_CONFIG_H__ */