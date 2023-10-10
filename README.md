# Fibocom Linux apps
This is a Fibocom linux apps set project for wwan devices.<br>
  **Flash service:** firmware update, switch, recovery.<br>
  **Ma service:** fccunlock(It is not open source. Contact the OEM to provide it).<br>
  **Config service:** OEM configuration function.<br>
  **Helper service:** provider dbus API for Flash/Ma/Config service.<br>

# License
The fibo_flash fibo_config  fibo_helper binaries are both GPLv2+.<br>

# Notice
  Service must be used with fw_package. Before installing service, ensure that fw_package has been installed. Obtain the fw package from the corresponding OEM .<br>
  fw_switch using fastboot so you can install fastboot with command `sudo apt-get install fastboot`<br>

# Building on Ubuntu

## 1. Install

- sudo apt install cmake<br>
- sudo apt install build-essential<br>
- sudo apt install -y pkg-config<br>
- sudo apt install libglib2.0-dev<br>
- sudo apt install libxml2-dev<br>
- sudo apt install libudev-dev<br>
- sudo apt install libmbim-glib-dev<br>
- sudo apt install libdbus-1-dev<br>
- sudo apt install libmm-glib-dev<br>

## 2. Build
./build.sh [operator]<br>
operator:<br>
  1. build_all (build service code and create release folder,config file )<br>
  2. clean_project (clean project remove build and release folder)<br>


examples:./build.sh 1  (build service code and create release folder,config file)<br>


## 3. If using systemd, use
- start service<br>
	sudo systemctl start fibo_xxx.service<br>
- Get status<br>
	sudo systemctl status fibo_xxx.service<br>
- Stop service<br>
	sudo systemctl stop fibo_xxx.service<br>

# release history
- version:1.0.0<br>
  first version, add  flash firmware,recovery  service.<br>


