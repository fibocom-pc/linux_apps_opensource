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

#ifndef _FIBO_LOG_H_
#define _FIBO_LOG_H_

#include <syslog.h>


#define FIBO_LOG_OPEN(module) openlog(module, LOG_CONS | LOG_PID, LOG_USER);

#define FIBO_LOG_CRITICAL(log, ...) syslog(LOG_CRIT, "[Critical]: %s:%u: "log, __FUNCTION__, __LINE__, ##__VA_ARGS__);

#define FIBO_LOG_ERROR(log, ...) syslog(LOG_ERR, "[Error]: %s:%u: "log, __FUNCTION__, __LINE__, ##__VA_ARGS__);

#define FIBO_LOG_NOTICE(log, ...) syslog(LOG_NOTICE, "[Notice]: %s:%u: "log, __FUNCTION__, __LINE__, ##__VA_ARGS__);

#define FIBO_LOG_WARNING(log, ...) syslog(LOG_WARNING, "[Warning]: %s:%u: "log, __FUNCTION__, __LINE__, ##__VA_ARGS__);

#define FIBO_LOG_INFO(log, ...) syslog(LOG_INFO, "[Info]: %s:%u: "log, __FUNCTION__, __LINE__, ##__VA_ARGS__);

#define FIBO_LOG_DEBUG(log, ...) syslog(LOG_DEBUG, "[Debug]: %s:%u: "log, __FUNCTION__, __LINE__, ##__VA_ARGS__);

#define FIBO_LOG_CLOSE closelog();

#endif /* _FIBO_LOG_H_ */

