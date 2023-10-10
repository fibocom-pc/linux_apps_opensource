cmake_minimum_required(VERSION 3.6)
project(code LANGUAGES CXX)

add_library(code  STATIC common.cc common.h serial_port.cc)

