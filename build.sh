#! /bin/bash

BUILD_DIR=`pwd`
APP_DIR="${BUILD_DIR}/build/application"
CONFIG_SERVICE_APP_DIR="${APP_DIR}/fibo_config_service"
CONFIG_SERVICE_APP_PATH="${APP_DIR}/fibo_config_service/fibo_config*"
FLASH_SERVICE_APP_PATH="${APP_DIR}/fibo_flash_service/fibo_flash*"
FLASH_SERVICE_APP_DIR="${APP_DIR}/fibo_flash_service"
HELPER_SERVICE_APP_PATH="${APP_DIR}/fibo_helper_service/fibo_helper*"
#MA_SERVICE_PATH_APP_PATH="${APP_DIR}/fibo_ma_service/fibo_ma*"
FW_PKG_FILE_PATH="${BUILD_DIR}/fw_pkg/linux_fw_package"
LIB_SORCE_PATH="${APP_DIR}/fibo_helper_service/code/*.so"


DEB_SOFT_DIR="${BUILD_DIR}/release/dpkg/opt/fibocom"
DEB_CONFIG_SERVICE_DIR="${DEB_SOFT_DIR}/fibo_config_service"
DEB_FLASH_SERVICE_DIR="${DEB_SOFT_DIR}/fibo_flash_service"
DEB_HELPER_SERVICE_DIR="${DEB_SOFT_DIR}/fibo_helper_service"
DEB_LIB_PATH="${BUILD_DIR}/release/dpkg/usr/lib/"
#DEB_MA_SERVICE_DIR="${DEB_SOFT_DIR}/fibo_ma_service"


BUILD_LIST=(
    build_all
    build_service
    make_deb_file
    clean_project
)

function operation_menu_select()
{
    echo -e "\033[32m=================================================== \033[0m"
    echo -e "\033[35m operation select:\033[0m"
    for list in ${BUILD_LIST[@]}; do
        echo -e "\033[32m    --------------------------------- \033[0m"
        COUNT=$(($COUNT+1)); echo -e "\033[35m    $COUNT.$list \033[0m"
    done
}

function code_build()
{
   if [ -d "build" ];then
       rm -r build
   fi
    mkdir build
    cd build
    cmake ..
    cmake --build .
}



function build_service()
{
    code_build
}

function copy_file_to_deb_directory()
{
    # copy configservice file
    if [ "$(ls -A $DEB_CONFIG_SERVICE_DIR)" ]; then
        rm -r ${DEB_CONFIG_SERVICE_DIR}/*
    fi
    cp -raf ${CONFIG_SERVICE_APP_DIR}/fbwwanConfig.ini ${DEB_CONFIG_SERVICE_DIR}
    cp -raf ${CONFIG_SERVICE_APP_PATH} ${DEB_CONFIG_SERVICE_DIR}
    

    # copy flashservice file
    if [ "$(ls -A $DEB_FLASH_SERVICE_DIR)" ]; then
        rm -r ${DEB_FLASH_SERVICE_DIR}/*
    fi
    cp -raf ${FLASH_SERVICE_APP_PATH} ${DEB_FLASH_SERVICE_DIR}
    cp -raf ${FLASH_SERVICE_APP_DIR}/*.ini ${DEB_FLASH_SERVICE_DIR}

    # copy helperservice
    if [ "$(ls -A $DEB_HELPER_SERVICE_DIR)" ]; then
        path=`pwd`
        cd $DEB_HELPER_SERVICE_DIR
        ls | grep -v  fibo_helper_tools  | awk  '{system("rm -rf "$1)}'
        cd $path
    fi
    cp -raf ${HELPER_SERVICE_APP_PATH} ${DEB_HELPER_SERVICE_DIR}

    if [ "$(ls -A $DEB_LIB_PATH)" ]; then
        path=`pwd`
        cd $DEB_LIB_PATH
        ls | grep -v  x86_64-linux-gnu  | awk  '{system("rm -rf "$1)}'
        cd $path
    fi
    cp -raf ${LIB_SORCE_PATH} ${DEB_LIB_PATH}
    # copy maservice
    #if [ "$(ls -A $DEB_MA_SERVICE_DIR)" ]; then
    #    rm -r ${DEB_MA_SERVICE_DIR}/*
    #fi
    #cp -raf ${MA_SERVICE_PATH_APP_PATH} ${DEB_MA_SERVICE_DIR}

}

deb_ver=""
function get_deb_version()
{
    flag=0
    file=${BUILD_DIR}/release/dpkg/DEBIAN/control
    for line in `cat $file`
    do
        if [ 1 -eq $flag ] ; then
            deb_ver=$line
            break;
        fi
        if [ $line == "Version:" ] ; then
            flag=1
        fi
    done
}

function make_deb_file()
{
    copy_file_to_deb_directory
    get_deb_version
    if [ -f "${BUILD_DIR}/release/dpkg/*.deb" ]; then
        rm ${BUILD_DIR}/release/dpkg/*.deb
    fi

    chmod 0755  ${BUILD_DIR}/release/dpkg/DEBIAN/*
    dpkg -b ${BUILD_DIR}/release/dpkg ${BUILD_DIR}/release/dpkg/fibo-apps-${deb_ver}.deb
}


function clean_project()
{
    rm -rf ${BUILD_DIR}/build
    rm -rf ${BUILD_DIR}/fw_pkg
}
function build_all()
{
    build_service
    make_deb_file
    # rm -rf ${BUILD_DIR}/fw_pkg
}



# code_build
# exit -1;
#********************************<main start>********************************************#

OPERATOR_SELECT=$1
if [ "$OPERATOR_SELECT" == "" ] ; then
    COUNT=0; operation_menu_select
    echo -e "\033[32m=================================================== \033[0m"
    echo -en "\033[35m Please input a number in (1-$COUNT):\033[0m"
    read OPERATOR_SELECT
    echo -e "\033[32m=================================================== \033[0m"
fi


echo -e "\033[35m project: operator: $OPERATOR_SELECT \033[0m";
echo -e "\033[32m=================================================== \033[0m"

case $OPERATOR_SELECT in
    1) build_all ;;
    2) build_service ;;
    3) make_deb_file;;
    4) clean_project ;;
    *) COUNT=0; menu_select
       echo -e "\033[32m=================================================== \033[0m"
       echo -e "\033[31m ERROR: You must input a number in (1-$COUNT). \033[0m"
       echo -e "\033[32m=================================================== \033[0m"
       exit -1 ;;
esac


