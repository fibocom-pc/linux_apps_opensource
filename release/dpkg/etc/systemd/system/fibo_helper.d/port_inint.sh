#!/bin/bash
servicename="[fibo_helper_service:pre]"
filename="/sys/bus/usb-serial/drivers/option1/new_id"
modprobe usbserial
modprobe option
echo "load [usbserial] [option] drivers......"
sleep 2
echo "load driver ok......"
pidlist=(8209 8211 8213 8215)
command=`lsusb |grep Fibocom |  cut -d " " -f 6| sed -e 's/:/ /g'`
echo "$servicename>>>>>>>>>>Init port start......<<<<<<<<<<"
echo "$servicename find port result is : -|$command|-"
if [[ -f $filename  ]];then
    echo "$servicename File exit, creat at port"
    for s in ${pidlist[@]}
    do
        echo "413c $s" > $filename
        if [  $? = 0 ];then
            command=`ls -l  /dev/ttyUSB* | cut -d " " -f 11`
            echo "$servicename creat port successed: port is: $command"
        else
            echo "$servicename Error of creat port"
        fi
    done
else
    echo "$servicename File Not exit!"
fi
echo "$servicename >>>>>>>>>>Init port End<<<<<<<<<<"
