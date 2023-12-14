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

project(fibo_config_service)

find_package(LibXml2 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(deps REQUIRED IMPORTED_TARGET glib-2.0 gio-2.0 gio-unix-2.0)


find_program(GDBUSCODEGEN NAMES gdbus-codegen)
if (NOT GDBUSCODEGEN)
	message(SEND_ERROR "Could not find gdbus-codegen")
endif(NOT GDBUSCODEGEN)

add_custom_command(OUTPUT generated/fibocom-helper-gdbus-generated.c
	COMMAND ${GDBUSCODEGEN}  --generate-c-code=fibocom-helper-gdbus-generated --c-namespace=FibocomGdbus --interface-prefix com.fibocom. ${CMAKE_SOURCE_DIR}/application/dbus/introspection/com.fibocom.helper.xml
	COMMAND mkdir -p generated/
	COMMAND mv fibocom-helper-gdbus-generated.c generated/
	)

execute_process(COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/fbwwanConfig.ini ${PROJECT_BINARY_DIR})
set(CONFIG_MAJOR_VERSION 1)
set(CONFIG_MINOR_VERSION 0)
set(CONFIG_PATCH_VERSION 3)

set(CONFIG_VERSION_STRING "${CONFIG_MAJOR_VERSION}.${CONFIG_MINOR_VERSION}.${CONFIG_PATCH_VERSION}")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/version.h.in"
                "./version.h")

set(CMAKE_C_COMPILER gcc)
set(CONFIG_PREPROCESSOR_DEF "-fstack-protector-strong -O2 -Wformat -Wformat-security  -fPIC -std=gnu99")
add_definitions(${CONFIG_PREPROCESSOR_DEF})

##################################
# Fibocom linux config service binary configuration

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../include)

include_directories(${CMAKE_SOURCE_DIR}/application/include/common)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${PROJECT_BINARY_DIR}/)
include_directories(${PROJECT_BINARY_DIR}/../3rd/iniparser)

include_directories(/usr/include/dbus-1.0
                    /usr/lib/x86_64-linux-gnu/dbus-1.0/include
                    /usr/include/gio-unix-2.0
                    /usr/include/libmount
                    /usr/include/blkid
                    /usr/include/glib-2.0
					/usr/include/libxml2
                    /usr/lib/x86_64-linux-gnu/glib-2.0/include)


aux_source_directory(./src DIR_SRCS)
set(source_files generated/fibocom-helper-gdbus-generated.c)

add_executable(fibo_config ${DIR_SRCS} ${source_files})

target_link_libraries(fibo_config ${PROJECT_BINARY_DIR}/../3rd/iniparser/libiniparser.a)
target_link_libraries(fibo_config  LibXml2::LibXml2 -ldl -lpthread -lm PkgConfig::deps ${CMAKE_DL_LIBS})

