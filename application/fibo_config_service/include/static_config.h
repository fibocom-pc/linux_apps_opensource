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

typedef enum sar_map_type_s{
SARMAP_TYPE_1=1,
SARMAP_TYPE_2,
SARMAP_TYPE_3,
SARMAP_TYPE_4,
SARMAP_TYPE_5,
SAR_MAP_TYPE_UNKNOWN=-1,
}sar_map_type;

typedef enum sar_down_type_s{
DOWN_LOAD_IMAGE=1,
DOWN_LOAD_AT,
SAR_DOWN_TYPE_UNKNOWN=-1,
}sar_down_type;

typedef enum sar_type_s{
SAR_TYPE_NOTHING=0,
SAR_TYPE_BODYSAR,
SAR_TYPE_TASAR,
SAR_TYPE_UNKNOWN=-1,
}sar_type;

typedef enum custom_solucion_type_t{
SLUCTION_TYPE_NO=1,
SLUCTION_TYPE_SW_BIOS,
SLUCTION_TYPE_SW_XML,
SLUCTION_TYPE_UNKNOWN=-1,
}custom_solucion_type;


typedef enum antenna_t{
ANTENNA_TYPE_DISABLE=0,
ANTENNA_TYPE_HW,
ANTENNA_TYPE_SW,
ANTENNA_TYPE_UNKNOWN=-1,
}antenna_type;



typedef enum
{
    STATUS_OFF = 0,
    STATUS_HW,
    STATUS_SW,
    STATUS_DBUS_ERROR,
    STATUS_UNKNOWN=-1,
} switch_status;

typedef enum
{
    STATUS_DISABLE=0,
    STATUS_ENABLE,
} enable_status;

typedef enum
{
    STATUS_QUERY=0,
    TYPE_QUERY,
    DATA_QUERY,
} send_message_type;

typedef enum
{
    DELL = 0,
    LENOVO,
    HP,
    UNKNOW=-1,
}oem_type;


int fibo_device_mode_get(void);
int fibo_get_start_state(void);

sar_map_type fibo_get_sarmaptype(void);

sar_down_type get_sardownloadtype(void);

sar_type fibo_get_sartype(void);

bool fibo_get_config_and_set(void);

antenna_type fibo_get_antturnerstate(void);

custom_solucion_type fibo_get_customizationsolutiontype(void);

char *get_region_regulatory(char *mcc);


bool fibo_get_sar_index(sar_map_type sar_map_type,char * wwanconfigid,char *standard,char device_mode, 
char sensor1, char sensor2, char sensor3, char *index);

bool fibo_get_antenna_index(char * wwanconfigid,char device_mode, char *index);

char * fibo_get_wwanconfigid(void);
char * fibo_get_skuid(void);
bool fibo_set_disableesim_for_mcc(void);
bool fibo_static_config_paese();
bool fibo_static_ini_cfg();
#endif /* __STATIC_CONFIG_H__ */