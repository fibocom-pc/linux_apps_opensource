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
 * @file cfg_log.h
 * @author ziqi.zhao@fibocom.com (zhaoziqi)
 * @brief
 * @version 1.0
 * @date 2023-09-23
 *
 *
 **/

#ifndef __FIBO_LOG_H__
#define __FIBO_LOG_H__
#include <stdio.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>

#define DEBUG 0

typedef enum log_level_t
{
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO, // default level
    LOG_LEVEL_WARNING,
    LOG_LEVEL_NOTICE,
    LOG_LEVEL_ERR,
    LOG_LEVEL_CRITICAL
} log_level;

bool should_output_log(log_level level);
int cfg_log_set_level(log_level level);

#define CFG_LOG_OPEN() openlog("fibo_config", LOG_CONS | LOG_PID, LOG_USER);
#define CFG_LOG_CLOSE() closelog();

#define CFG_LOG_DEBUG(format, ...)                                                                   \
    do                                                                                               \
    {                                                                                                \
        if (should_output_log(LOG_LEVEL_DEBUG))                                                      \
        {                                                                                            \
            if (DEBUG)                                                                               \
            {                                                                                        \
                syslog(LOG_DEBUG, "[Debug]: %s:%u: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
                printf("[%s][%s][%d]" format " \n", __FILE__, __func__, __LINE__, ##__VA_ARGS__);    \
            }                                                                                        \
            else                                                                                     \
            {                                                                                        \
                syslog(LOG_DEBUG, "[Debug]: %s:%u: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
            }                                                                                        \
        }                                                                                            \
    } while (0);

#define CFG_LOG_INFO(format, ...)                                                                  \
    do                                                                                             \
    {                                                                                              \
        if (should_output_log(LOG_LEVEL_INFO))                                                     \
        {                                                                                          \
            if (DEBUG)                                                                             \
            {                                                                                      \
                syslog(LOG_INFO, "[Info]: %s:%u: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
                printf("[%s][%s][%d]" format " \n", __FILE__, __func__, __LINE__, ##__VA_ARGS__);  \
            }                                                                                      \
            else                                                                                   \
            {                                                                                      \
                syslog(LOG_INFO, "[Info]: %s:%u: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
            }                                                                                      \
        }                                                                                          \
    } while (0);

#define CFG_LOG_WARNING(format, ...)                                                                     \
    do                                                                                                   \
    {                                                                                                    \
        if (should_output_log(LOG_LEVEL_WARNING))                                                        \
        {                                                                                                \
            if (DEBUG)                                                                                   \
            {                                                                                            \
                syslog(LOG_WARNING, "[Warning]: %s:%u: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
                printf("[%s][%s][%d]" format " \n", __FILE__, __func__, __LINE__, ##__VA_ARGS__);        \
            }                                                                                            \
            else                                                                                         \
            {                                                                                            \
                syslog(LOG_WARNING, "[Warning]: %s:%u: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
            }                                                                                            \
        }                                                                                                \
    } while (0);

#define CFG_LOG_NOTICE(format, ...)                                                                    \
    do                                                                                                 \
    {                                                                                                  \
        if (should_output_log(LOG_LEVEL_NOTICE))                                                          \
        {                                                                                              \
            if (DEBUG)                                                                                 \
            {                                                                                          \
                syslog(LOG_NOTICE, "[Notice]: %s:%u: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
                printf("[%s][%s][%d]" format " \n", __FILE__, __func__, __LINE__, ##__VA_ARGS__);      \
            }                                                                                          \
            else                                                                                       \
            {                                                                                          \
                syslog(LOG_NOTICE, "[Notice]: %s:%u: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
            }                                                                                          \
        }                                                                                              \
    } while (0);

#define CFG_LOG_ERROR(format, ...)                                                                 \
    do                                                                                             \
    {                                                                                              \
        if (should_output_log(LOG_LEVEL_ERR))                                                      \
        {                                                                                          \
            if (DEBUG)                                                                             \
            {                                                                                      \
                syslog(LOG_ERR, "[Error]: %s:%u: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
                printf("[%s][%s][%d]" format " \n", __FILE__, __func__, __LINE__, ##__VA_ARGS__);  \
            }                                                                                      \
            else                                                                                   \
            {                                                                                      \
                syslog(LOG_ERR, "[Error]: %s:%u: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
            }                                                                                      \
        }                                                                                          \
    } while (0);

#define CFG_LOG_CRITICAL(format, ...)                                                                  \
    do                                                                                                 \
    {                                                                                                  \
        if (should_output_log(LOG_LEVEL_CRITICAL))                                                          \
        {                                                                                              \
            if (DEBUG)                                                                                 \
            {                                                                                          \
                syslog(LOG_CRIT, "[Critical]: %s:%u: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
                printf("[%s][%s][%d]" format " \n", __FILE__, __func__, __LINE__, ##__VA_ARGS__);      \
            }                                                                                          \
            else                                                                                       \
            {                                                                                          \
                syslog(LOG_CRIT, "[Critical]: %s:%u: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
            }                                                                                          \
        }                                                                                              \
    } while (0);

#endif