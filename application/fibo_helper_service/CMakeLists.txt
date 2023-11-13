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

project(fibo_helper_service)

find_package(PkgConfig REQUIRED)
find_package(LibXml2 REQUIRED)
pkg_check_modules(deps REQUIRED IMPORTED_TARGET glib-2.0 gio-2.0 gio-unix-2.0 udev)

##################################
# Fibocom linux Gdbus codegen

find_program(GDBUSCODEGEN NAMES gdbus-codegen)
if (NOT GDBUSCODEGEN)
    message(SEND_ERROR "Could not find gdbus-codegen")
endif(NOT GDBUSCODEGEN)

add_custom_command(OUTPUT generated/fibocom-helper-gdbus-generated.c
    COMMAND ${GDBUSCODEGEN}  --generate-c-code=fibocom-helper-gdbus-generated --c-namespace=FibocomGdbus --interface-prefix com.fibocom. ${CMAKE_SOURCE_DIR}/application/dbus/introspection/com.fibocom.helper.xml
    COMMAND mkdir -p generated/
    COMMAND mv fibocom-helper-gdbus-generated.c generated/
    )
include_directories(${CMAKE_SOURCE_DIR}/application/include/common)

set(HELPER_MAJOR_VERSION 1)
set(HELPER_MINOR_VERSION 0)
set(HELPER_PATCH_VERSION 7)

set(HELPER_VERSION_STRING ${HELPER_MAJOR_VERSION}.${HELPER_MINOR_VERSION}.${HELPER_PATCH_VERSION})
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/version.h.in"
                "./version.h")
set(CMAKE_C_COMPILER gcc)
set(HELPER_PREPROCESSOR_DEF "-fstack-protector-strong -O2 -Wformat -Wformat-security  -fPIC -std=gnu99")
##################################
# Fibocom linux helper service binary configuration

add_compile_options(-pthread)
include_directories(${PROJECT_BINARY_DIR}/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../include
                    /usr/include/dbus-1.0
                    /usr/lib/x86_64-linux-gnu/dbus-1.0/include
                    /usr/include/gio-unix-2.0
                    /usr/include/libmount
                    /usr/include/blkid
                    /usr/include/glib-2.0
                    /usr/lib/x86_64-linux-gnu/glib-2.0/include
                    /usr/local/include/libmbim-glib
                    /usr/include/libmbim-glib
                    /usr/include/libmm-glib
                    /usr/include/ModemManager
                    ${CMAKE_CURRENT_SOURCE_DIR})

set(helperd_source_files
    fibo_helper_main.c
    fibo_helper_basic_func.c
    fibo_helper_adapter.c
        fibo_helper_log.c
        generated/fibocom-helper-gdbus-generated.c
    )

set(helperm_source_files
    fibo_helper_mbim_main.c
    fibo_helper_basic_func.c
    fibo_helper_adapter.c
        fibo_helper_log.c
        generated/fibocom-helper-gdbus-generated.c
    )

add_subdirectory(./at_channel code)

add_definitions(${HELPER_PREPROCESSOR_DEF})
add_executable(fibo_helperd
    ${helperd_source_files})

add_executable(fibo_helperm
    ${helperm_source_files})

target_link_libraries(fibo_helperd
            code
            libmbim-glib.so
            dbus-1
            udev
            gio-2.0
            gobject-2.0
            glib-2.0
            mm-glib
            PkgConfig::deps
            LibXml2::LibXml2)

target_link_libraries(fibo_helperm
            code
            libmbim-glib.so
            dbus-1
            udev
            gio-2.0
            gobject-2.0
            glib-2.0
            mm-glib
            PkgConfig::deps
            LibXml2::LibXml2)
