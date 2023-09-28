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
 * @file dynamic_config.h
 * @author ziqi.zhao@fibocom.com (zhaoziqi)
 * @brief 
 * @version 1.0
 * @date 2023-09-23
 * 
 * 
 **/


#ifndef __DYNAMIC_CONFIG_H__
#define __DYNAMIC_CONFIG_H__
#include<semaphore.h>
#include<sys/sem.h>

void* dynamic_thread(void* arg);

void* event_from_file_thread(void* arg);
void* event_from_signal_thread(void* arg);

sem_t *get_device_sem_id(void);
sem_t *get_mcc_sem_id(void);
#endif