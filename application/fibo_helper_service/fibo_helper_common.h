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
#include "common/fibo_helper_cid.h"
#include "version.h"

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

typedef struct
{
    gint        serviceid;
    gint        cid;
    gint        rtcode;
    void        *data;
    gint        payloadlen;
    gchar       payload_str[0];
}fibo_async_struct_type;

#endif /* _FIBO_HELPER_COMMON_H_ */

