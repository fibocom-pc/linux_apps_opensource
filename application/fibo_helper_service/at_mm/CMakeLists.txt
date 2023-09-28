cmake_minimum_required(VERSION 3.6)
project(code LANGUAGES CXX)

add_library(code  SHARED common.cc common.h serial_port.cc)
target_include_directories(code PUBLIC )

target_link_libraries(code PUBLIC )
