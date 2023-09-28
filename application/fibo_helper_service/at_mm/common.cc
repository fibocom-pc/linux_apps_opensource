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
 * @author rick.chen@fibocom.com (chenhaotian)
 * @brief
 * @version 1.0
 * @date 2023-09-23
 *
 *
 **/

#include "common.h"
#include "string.h"

int fibo_adapter_send_at_command(const char *req_cmd, char *rspbuf, const char *mbimportname)
{
    std::string  path_final= "/dev/";
    std::string  bufs = rspbuf;
    std::string  cmds = req_cmd;

    path_final += mbimportname;
    printf("path:%s\n", path_final.c_str());

    bufs = sendAt(path_final, cmds);
    if (bufs.empty() && bufs.find("error") != bufs.npos)
    {
       // FIBO_LOG_DEBUG("Command Error:\n%s\n", rspbuf);
       return -1;
    }

    strcpy(rspbuf, bufs.c_str());
    // FIBO_LOG_DEBUG("%s:\n%s\n", req_cmd, bufs.c_str());
    return 0;
}
