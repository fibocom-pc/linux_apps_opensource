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
 * @file config_helper.h
 * @author ziqi.zhao@fibocom.com (zhaoziqi)
 * @brief 
 * @version 1.0
 * @date 2023-09-23
 * 
 * 
 **/

#ifndef __CONFIG_HELPER_H__
#define __CONFIG_HELPER_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

typedef enum
{
    HELPER,
    MASERVICE,     /* MA service */
    CONFIGSERVICE, /* Config service */
    FWSWITCH,      /* FWswitch service */
    UNKNOW_SERVICE /* unknow service */
}e_service;

typedef enum
{
    ENUM_CID_MIN           = 0x0000,

    /* 0x0001 -0x0FFF is reserved for common cid */
    RESET_MODEM_SW         = 0x0001,

    COMMAND_ENUM_MIN       = 0x1000,
    /* FWswitch service command list */
    GET_AP_VERSION         = 0x1001,
    GET_MD_VERSION,
    GET_OP_VERSION,
    GET_OEM_VERSION,
    GET_DEV_VERSION,
    GET_IMEI,
    GET_MCCMNC,
    GET_SUBSYSID,
    SET_ATTACH_APN,
    FLASH_FW_FASTBOOT,

    /* FWrecovery service command list */
    GET_PORT_STATE         = 0x2001,
    GET_OEM_ID,
    RESET_MODEM_HW,
    FLASH_FW_EDL,

    /* MA service command list */
    GET_FCCLOCK_STATUS     = 0x3001,
    GET_MODEM_RANDOM_KEY,
    SET_FCC_UNLOCK,
    GET_FW_INFO,

    /* config service command list */
    /* body sar */
    SET_BODYSAR_ENABLE = 0x4001,
    GET_BODYSAR_STATUS,
    SET_BODYSAR_CTRL_MODE,
    GET_BODYSAR_CTRL_MODE,
    SET_BODYSAR_INDEX,
    SET_BODYSAR_CFG_DATA,
    SET_BODYSAR_VER,
    GET_BODYSAR_VER,
    /* tasar */
    SET_TASAR_ENABLE,
    GET_TASAR_STATUS,
    SET_TASAR_CTRL_MODE,
    GET_TASAR_CTRL_MODE,
    SET_TASAR_INDEX,
    SET_TASAR_CFG_DATA,
    SET_TASAR_VER,
    GET_TASAR_VER,
    /* antenna */
    SET_ANTENNA_ENABLE,
    GET_ANTENNA_STATUS,
    SET_ANTENNA_CTRL_MODE,
    SET_ANTENNA_WORK_MODE,
    GET_ANTENNA_CTRL_MODE,
    GET_ANTENNA_WORK_MODE,
    SET_ANTENNA_INDEX,
    SET_ANTENNA_GPO_CFG_DATA,
    SET_ANTENNA_MIPI_CFG_DATA,
    SET_ANTENNA_VER,
    GET_ANTENNA_VER,
    /* fcclock */
    SET_FCCLOCK_ENABLE,
    /* network_type */
    SET_NET_WORK_TYPE,
    GET_NET_WORK_TYPE,
    /* bandcfg */
    SET_BAND_CFG_DATA,
    /* wdisable */
    SET_WDISABLE_ENABLE,
    GET_WDISABLE_STATUS,
    /* gnss */
    SET_GNSS_ENABLE,
    GET_GNSS_STATUS,
    /* esim disable */
    GET_DISABLE_ESIM_STATUS,
    SET_DISABLE_ESIM,

    ENUM_CID_MAX
}e_command_cid;

typedef enum {
    GET_DATA_SUCCESS=0,
    GET_DATA_FAIL,
    SERVICE_BUSY,
    UNKNOW_CODE,
}status_code;

typedef struct Header
{
    e_service service_id;
    e_command_cid command_cid;

}Header;

typedef struct Mesg
{
    Header header;
    status_code rtcode;
	int payload_lenth;
    char payload[0];
}mesg_info;



void fibo_dus_init(void);
bool get_dbus_connect_flg(void);
void set_static_config_flg(bool value);
bool get_static_config_flg(void);
bool fibo_dbus_init_status(void);
void fibo_set_sim_change(bool value);
bool fibo_get_sim_change(void);
char *fibo_get_mcc_value(void);

bool register_dbus_event_handler(void);
bool fibo_get_sim_reign(void);
bool dbus_service_is_ready(void);
bool send_message_get_response(e_command_cid cid, char *payload, int len, mesg_info **response);

#endif