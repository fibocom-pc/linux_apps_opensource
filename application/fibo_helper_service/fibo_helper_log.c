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
 * @file fibo_helper_basic_func.c
 * @author kangyu.shi@fibocom.com (shikangyu)
 * @brief
 * @version 1.0
 * @date 2023-11-07
 *
 *
 **/

#include <stdio.h>
#include <getopt.h>
#include <syslog.h>
#include <stdlib.h>
#include "fibo_helper_common.h"

int g_debug_level = LOG_INFO;

struct option long_options[] = {
        {"version", no_argument, NULL, 'v'},
        {"debug", required_argument, NULL, 'd'},
        {"loglevel", optional_argument  , NULL, 'l'},
};

static void print_usage(void)
{
    extern const char *__progname;
    fprintf(stderr,
            "%s -v -d -l <Level> ...\n",
            __progname);
    fprintf(stderr,
            " -v                     --force                      print  version\n"
            " -d <debug level:xx>    --debug <debug:num>          LOG Debug\n"
            " -l <id:file path>      --Level <Level:string>       Level for bin\n"
            "\n"
            "Example: \n"
            "./fibo_flash -v -d -l 7\n");
}

void log_set(int argc, char **argv)
{
    int option = 0;

    do{
        option = getopt_long(argc, argv, "vdl:", long_options, NULL);
        switch (option) {
            case 'v':
                FIBO_LOG_ERROR("fibo_helper_service version:%s", HELPER_VERSION_STRING);
                break;
            case 'd':
                FIBO_LOG_ERROR("option d,%s\n", optarg);
                g_debug_level = 7;
                break;
            case 'l':
                if(atoi(optarg) >= 0 && atoi(optarg) <= 7)
                {
                    g_debug_level = atoi(optarg);
                }
                else
                {
                    FIBO_LOG_ERROR("log level is invalue :%s\n", optarg);
                }
                FIBO_LOG_ERROR("log level is :%s,g_debug_level: %d\n", optarg, g_debug_level);
                break;
            case '?':
                print_usage();
                break;
            default:
                break;
        }

    }while(option != -1);
}