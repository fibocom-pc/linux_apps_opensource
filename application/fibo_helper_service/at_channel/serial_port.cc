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
 * @file serial_port.cc
 * @author rick.chen@fibocom.com (chenhaotian)
 * @brief
 * @version 1.0
 * @date 2023-09-23
 *
 *
 **/


#include "serial_port.h"
#include <csignal>
#include <fcntl.h>
#include <termios.h>
#include <cstring>
#include <utility>

int speed_arr[] = {B38400, B19200, B9600, B4800, B2400, B1200, B300, B38400,
                   B19200, B9600, B4800, B2400, B1200, B300,};
int name_arr[] = {38400, 19200, 9600, 4800, 2400, 1200, 300, 38400, 19200,
                  9600, 4800, 2400, 1200, 300,};

int serial_port_fd = 0;
void setBaudSpeed(int fd, int speed) {
  int i;
  int status;
  struct termios options{};
  tcgetattr(fd, &options);
  for (i = 0; i < sizeof(speed_arr) / sizeof(int); i++) {
    if (speed == name_arr[i]) {
      tcflush(fd, TCIOFLUSH);
      cfsetispeed(&options, speed_arr[i]);
      cfsetospeed(&options, speed_arr[i]);
      status = tcsetattr(fd, TCSANOW, &options);
      if (status != 0) perror("tcsetattr fd1");
      return;
    }
    tcflush(fd, TCIOFLUSH);
  }
}

bool setParity(int fd, int databits, int stopbits, int parity) {
  struct termios options{};
  if (tcgetattr(fd, &options) != 0) {
    perror("SetupSerial 1");
    return false;
  }
  bzero(&options, sizeof(options));
  options.c_cflag |= CLOCAL | CREAD;
  options.c_cflag &= ~CSIZE;
  switch (databits) {
    case 7:options.c_cflag |= CS7;
      break;
    case 8:options.c_cflag |= CS8;
      break;
    default: fprintf(stderr, "Unsupported data size\n");
      return false;
  }
  switch (parity) {
    case 'n':
    case 'N':options.c_cflag &= ~PARENB;
      options.c_iflag &= ~INPCK;
      break;
    case 'o':
    case 'O':options.c_cflag |= (PARODD | PARENB);
      options.c_iflag |= (INPCK | ISTRIP);
      break;
    case 'e':
    case 'E':options.c_cflag |= PARENB;
      options.c_cflag &= ~PARODD;
      options.c_iflag |= (INPCK | ISTRIP);
      break;
    case 'S':
    case 's':options.c_cflag &= ~PARENB;
      options.c_cflag &= ~CSTOPB;
      break;
    default: fprintf(stderr, "Unsupported parity\n");
      return false;
  }
  switch (stopbits) {
    case 1:options.c_cflag &= ~CSTOPB;
      break;
    case 2:options.c_cflag |= CSTOPB;
      break;
    default: fprintf(stderr, "Unsupported stop bits\n");
      return false;
  }
  if (parity != 'n')
    options.c_iflag |= INPCK;
  options.c_cc[VTIME] = 0;
  options.c_cc[VMIN] = 0;
  tcflush(fd, TCIFLUSH);
  if (tcsetattr(fd, TCSANOW, &options) != 0) {
    perror("SetupSerial 3");
    return false;
  }
  return true;
}

std::string atSender(std::string at_command) {
  std::string at_result;
  char temp[2 * 1024] = {0};
  int length = 0;
  fd_set fs_read;
  struct timeval time{5, 0};

  FD_ZERO(&fs_read);
  FD_SET(serial_port_fd, &fs_read);

  at_command.append("\r\n");
  tcflush(serial_port_fd, TCOFLUSH);
  ssize_t tmp = 0;
    tmp = write(serial_port_fd, at_command.c_str(), at_command.size());
    if(tmp <= 0){
        printf("write of 0 len:%s,%ld\n",at_command.c_str(),at_command.size());
    }

    if (strstr(at_command.c_str(), "at+syscmd") != NULL) {
        at_result = "syscmd do not return";
        return at_result;
    }

   while (select(serial_port_fd + 1, &fs_read, 0, 0, &time) > 0) {
       size_t len = read(serial_port_fd, temp + length, sizeof(temp));
       if (len > 0) {
           length += len;
       }
       else{
           std::cout << "read len is 0,break while" << std::endl;
           break;
       }
       if(strstr(temp,"OK") || strstr(temp,"ERROR"))
       {
           break;
       }
  }

  if (strlen(temp) != 0) {
    at_result.append(temp, length);
  } else {
    at_result = "Read Error";
  }

  return at_result;
}

bool init(const std::string& path) {
//  std::string test_command = "at";
  // check file is exist
  if (access(path.c_str(), F_OK) != 0) {
    return false;
  }

  // open port
  serial_port_fd = open(path.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK);
  if (serial_port_fd == -1) {
    printf("Open port failed\n");
    return false;
  }

  // set baud_rate
  setBaudSpeed(serial_port_fd, 115200);
  if (!setParity(serial_port_fd, 8, 1, 'N')) {
    printf("Set parity failed]n");
    return false;
  }
/*
  std::string res = atSender(test_command);
  if (res.find("OK") != res.npos) {
      //printf("AT INIT ERROR res:%s\n",res.c_str());
    return false;
  }
*/
  return true;
}

std::string sendAt(const std::string& path, std::string at_command) {
  init(path);
  std::string res = atSender(std::move(at_command));
  //printf("res:%s\n",res.c_str());
  close(serial_port_fd);
  return res;
}
