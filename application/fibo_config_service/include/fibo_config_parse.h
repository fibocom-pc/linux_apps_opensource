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
 * @file fibo_config_parse.h
 * @author ziqi.zhao@fibocom.com (zhaoziqi)
 * @brief 
 * @version 1.0
 * @date 2023-09-23
 * 
 * 
 **/

#ifndef __FIBO_CONFIG_PARSE_H__
#define __FIBO_CONFIG_PARSE_H__
#include <stdio.h>
#include "fibo_list.h"

typedef struct config_parse_s{
    struct list_head list;
    char key[32];
    int keyval;

}config_parse_t;

int fibo_config_parse(char *ini_path, struct list_head *list_data);


#endif