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

project(qdl)
find_package(LibXml2 REQUIRED)

include_directories (. DIR_LIB_INCLUDES)
aux_source_directory(. DIR_LIB_SRCS)

set(qdl_source_files firehose.c qdl.c sahara.c util.c patch.c program.c ufs.c)

set(ks_source_files ks.c sahara.c util.c)

include_directories(/usr/include/libxml2)

add_executable(ks ${ks_source_files})
add_executable(qdl ${qdl_source_files})

target_link_libraries(qdl LibXml2::LibXml2 udev)
target_link_libraries(ks LibXml2::LibXml2 udev)
