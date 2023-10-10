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
 * @file serial_port.h
 * @author rick.chen@fibocom.com (chenhaotian)
 * @brief
 * @version 1.0
 * @date 2023-09-23
 *
 *
 **/


#ifndef CONFIGSERVICE__SERIAL_PORT_H_
#define CONFIGSERVICE__SERIAL_PORT_H_
#include <iostream>
//#include "log_info.h"

std::string sendAt(const std::string& path, std::string at_command);
#endif //CONFIGSERVICE__SERIAL_PORT_H_
