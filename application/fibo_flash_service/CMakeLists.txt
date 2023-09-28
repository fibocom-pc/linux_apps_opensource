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

project(fibo_flash_service)

find_package(LibXml2 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(deps REQUIRED IMPORTED_TARGET glib-2.0 gio-2.0 gio-unix-2.0)

execute_process(COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/FwUpdate.ini ./application/fibo_flash_service)

set(FLASH_MAJOR_VERSION 1)
set(FLASH_MINOR_VERSION 0)
set(FLASH_PATCH_VERSION 0)

set(FLASH_VERSION_STRING ${FLASH_MAJOR_VERSION}.${FLASH_MINOR_VERSION}.${FLASH_PATCH_VERSION})

set(CMAKE_C_COMPILER gcc)
set(FLASH_PREPROCESSOR_DEF "-fstack-protector-strong -O2 -Wformat -Wformat-security  -fPIC -std=gnu99")
add_definitions(${FLAH_PREPROCESSOR_DEF})


add_custom_command(OUTPUT generated/fibocom-helper-gdbus-generated.c
        COMMAND ${GDBUSCODEGEN}  --generate-c-code=fibocom-helper-gdbus-generated --c-namespace=FibocomGdbus --interface-prefix com.fibocom. ${CMAKE_SOURCE_DIR}/application/dbus/introspection/com.fibocom.helper.xml
        COMMAND mkdir -p generated/
        COMMAND mv fibocom-helper-gdbus-generated.h ${CMAKE_SOURCE_DIR}/application/include/common/
        COMMAND mv fibocom-helper-gdbus-generated.c generated/
        )
##################################
# Fibocom linux flash service binary configuration

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../include)
include_directories(${CMAKE_SOURCE_DIR}/application/include/common)
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../libs)

set(source_files
    fibo_flash_main.c fibo_flash_parse_xml.c generated/fibocom-helper-gdbus-generated.c)

add_executable(fibo_flash
    ${source_files})

target_link_libraries(fibo_flash
    PkgConfig::deps
    LibXml2::LibXml2
    libsafestring.a)
