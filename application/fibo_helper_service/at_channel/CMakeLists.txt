cmake_minimum_required(VERSION 3.6)
project(code LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_library(code  STATIC common.cc  serial_port.cc)

