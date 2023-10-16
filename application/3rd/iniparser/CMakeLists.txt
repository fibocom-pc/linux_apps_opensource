#/* This program is free software: you can redistribute it and/or modify
# * it under the terms of the GNU General Public License as published by
# * the Free Software Foundation, either version 2 of the License, or
# * (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program.  If not, see <http://www.gnu.org/licenses/>.
# *
# * Copyright (C) 2023, Fibocom Wireless Inc.
# */

cmake_minimum_required(VERSION 3.6)

project(iniparser)
set(path ${CMAKE_CURRENT_SOURCE_DIR}/src/dictionary.h
            ${CMAKE_CURRENT_SOURCE_DIR}/src/iniparser.h)
execute_process(COMMAND cp -raf ${path}  ${PROJECT_BINARY_DIR})

include_directories (./src DIR_LIB_INCLUDES)
aux_source_directory(./src DIR_LIB_SRCS)

add_library(iniparser ${DIR_LIB_SRCS})



    