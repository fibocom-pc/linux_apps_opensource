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
 * @file fibo_helper_common.h
 * @author rick.chen@fibocom.com (chenhaotian)
 * @brief
 * @version 1.0
 * @date 2023-09-23
 *
 *
 **/

#ifndef _FIBO_HELPER_COMMON_H_
#define _FIBO_HELPER_COMMON_H_

#include <syslog.h>
#include <glib.h>
#include "fibocom-helper-gdbus-generated.h"
#include "stdio.h"
#include "common/fibo_log.h"
// #include "common/fibo_private_log.h"

#ifndef AT_COMMAND_LEN
#define AT_COMMAND_LEN                   256
#endif

// #define MBIM_FUNCTION_SUPPORTED

typedef enum
{
    RET_ERROR        = -1,
    RET_ERR_INTERNAL = RET_ERROR,
    RET_MIN          = RET_ERROR,
    RET_OK           = 0,
    RET_ERR_PROCESS,
    RET_ERR_BUSY,
    RET_ERR_RESOURCE,
    RET_MAX
}fibo_ret_enum_type;

typedef enum
{
    ENUM_MIN      = 0,
    HELPER        = ENUM_MIN, /* Helper     service */
    FWSWITCHSRV   = 1,        /* FWswitch   service */
    FWRECOVSRV    = 2,        /* FWrecovery service */
    MASRV         = 3,        /* MA         service */
    CONFIGSRV     = 4,        /* Config     service */
    ENUM_MAX                  /* unknown    service */
}e_service;

typedef enum
{
    ENUM_CID_MIN           = 0x0000,

    CTL_MBIM_INIT          = 0x0001,
    CTL_MBIM_DEINIT        = 0x0002,
    CTL_MBIM_END           = 0x0003,
    CTL_MBIM_NO_RESP,

    /* 0x0001 -0x0FFF is reserved for common cid */
    RESET_MODEM_SW         = 0x0100,

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

typedef struct
{
    gint        serviceid;
    gint        cid;
    gint        rtcode;
    gint        payloadlen;
    gchar       payload_str[0];
}fibo_async_struct_type;

#endif /* _FIBO_HELPER_COMMON_H_ */

