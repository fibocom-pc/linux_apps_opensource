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


#ifndef _FIBO_HELPER_TEST_H_
#define _FIBO_HELPER_TEST_H_

#include <gio/gio.h>
#include "libmbim-glib.h"
#include "fibo_helper_common.h"

int fibo_prase_test_func(FibocomGdbusHelper *skeleton,GDBusMethodInvocation  *invocation, GVariant *str, gpointer callback);
void fibocom_test_at_ready(MbimDevice *device, GAsyncResult *res, gpointer user_data);
void test_at_command1(void);
void test_at_command2(void);

#endif /* _FIBO_HELPER_TEST_H_ */

