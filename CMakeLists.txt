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

# Note: project version is the fibocom-linux version. Update this as per below description
# It is three part.
# <major>.<minor>.<macro>
# major = If any significant design change that improves complete.
# minor = Small design change specific to any operation.
# macro = small change or bug fix

project(fibocom_linux VERSION 1.0.10)

add_subdirectory (application)

# enable_testing()
# add_subdirectory(test)

install(CODE "MESSAGE(\"start install script.\")")
install(CODE "execute_process(COMMAND bash ${PROJECT_SOURCE_DIR}/install)")
install(CODE "MESSAGE(\"run install script success.\")")

set(DEFAULT_INSTALL_PREFIX "")

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX ${DEFAULT_INSTALL_PREFIX} CACHE PATH "Default installation path" FORCE)
endif()
message(STATUS "Installation prefix: ${CMAKE_INSTALL_PREFIX}")  

install(DIRECTORY "${PROJECT_BINARY_DIR}/release/dpkg/opt/fibocom" FILE_PERMISSIONS  OWNER_EXECUTE OWNER_WRITE OWNER_READ DESTINATION "${CMAKE_INSTALL_PREFIX}/opt")
install(DIRECTORY "${PROJECT_BINARY_DIR}/release/dpkg/usr/lib/udev/rules.d/" DESTINATION "${CMAKE_INSTALL_PREFIX}/usr/lib/udev/rules.d")
# install(DIRECTORY "${PROJECT_BINARY_DIR}/release/dpkg/usr/lib/x86_64-linux-gnu/ModemManager/fcc-unlock.d/"  
#             FILE_PERMISSIONS    OWNER_EXECUTE OWNER_WRITE OWNER_READ
#                                 GROUP_EXECUTE GROUP_READ 
#                                 WORLD_EXECUTE WORLD_READ
#             DESTINATION "${CMAKE_INSTALL_PREFIX}/usr/lib/x86_64-linux-gnu/ModemManager/fcc-unlock.d")
install(DIRECTORY "${PROJECT_BINARY_DIR}/release/dpkg/lib/systemd/system/" DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/systemd/system")
install(DIRECTORY "${PROJECT_BINARY_DIR}/release/dpkg/usr/share/dbus-1/system.d/" DESTINATION "${CMAKE_INSTALL_PREFIX}/usr/share/dbus-1/system.d")
install(CODE "MESSAGE(\"install success!\")")


set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_NAME "linux-apps")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_GROUP "fibocom")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION "WWAN Linux apps")
set(CPACK_DEBIAN_PACKAGE_SECTION "base")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "standard")
set(CPACK_PACKAGE_VENDOR "fibocom")
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Fibocom")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA 
    "${PROJECT_BINARY_DIR}/../script/preinst;${PROJECT_BINARY_DIR}/../script/prerm;${PROJECT_BINARY_DIR}/../script/postinst;${PROJECT_BINARY_DIR}/../script/postrm")
include(CPack)


configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
  @ONLY
)

add_custom_target(uninstall COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
