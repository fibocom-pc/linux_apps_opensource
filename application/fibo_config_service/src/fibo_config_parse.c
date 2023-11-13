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
 * @file fibo_config_parse.c
 * @author ziqi.zhao@fibocom.com (zhaoziqi)
 * @brief 
 * @version 1.0
 * @date 2023-09-23
 * 
 * 
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "iniparser.h"
#include "fibo_config_parse.h"
#include "fibo_list.h"
#include "fibo_log.h"

#define KEY_NAME_COUNT 64


int fibo_config_parse(char *ini_path, struct list_head *list_data)
{
    int section_cnt = 0;
    int cnt =0;
    char *data[KEY_NAME_COUNT] = {0};
    dictionary *d = NULL;
    config_parse_t *cur=NULL ;
    
    d = iniparser_load(ini_path);
    if (NULL == d)
    {
        FIBO_LOG_ERROR("parse %s failed\n", ini_path);
        return -1;
    }

    section_cnt = iniparser_getnsec(d);

    int y =0;
    for (int i = 0; i < section_cnt; i++) //section_cnt
    {
        cnt = iniparser_getsecnkeys(d,iniparser_getsecname(d,i));
        if (cnt <= 0)
        {
            continue;
        }
        iniparser_getseckeys(d,iniparser_getsecname(d,i),(const char **)data);
        for (int j = 0; j < cnt; j++) //key_count
        { 
            config_parse_t *config_data =NULL;
            config_data = malloc(sizeof(config_parse_t)+1);
            if (NULL == config_data)
            {
                FIBO_LOG_ERROR("Failed to allocate config");
                return -1;
            }
            memset(config_data, 0, sizeof(config_parse_t));
            sprintf(config_data->key,"%s", (strstr(data[j],":")+1));
            config_data->keyval = iniparser_getint(d, data[j], -1);
            
            list_add_tail(&config_data->list, list_data);
        }
    }
    iniparser_freedict(d);

    return 0;
}