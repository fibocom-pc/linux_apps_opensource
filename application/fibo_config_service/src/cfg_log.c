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
 * @file cfg_log.c
 * @author ziqi.zhao@fibocom.com (zhaoziqi)
 * @brief 
 * @version 1.0
 * @date 2023-09-23
 * 
 * 
 **/

#include "cfg_log.h"
#include <stdbool.h>

static log_level glog_level = LOG_LEVEL_INFO;

bool should_output_log(log_level level)
{
    return level >= glog_level;
}


int cfg_log_set_level(log_level level)
{
    if (level < LOG_LEVEL_DEBUG || level > LOG_LEVEL_ERR)
    {
        return -1;
    }
    glog_level = level;

    return 0;
}

int cfg_log_get_level()
{
    return glog_level;
}