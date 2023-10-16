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
1.cmake -S . -B build<br>
2.cmake --build build<br>
3.cd build<br>
4.sudo make install<br>

## 3. If using systemd, use
- load config file<br>
  sudo systemctl daemon-reload
- enable service<br>
  sudo systemctl enable fibo_xxx.service<br>
- start service<br>
	sudo systemctl start fibo_xxx.service<br>
- Get status<br>
	sudo systemctl status fibo_xxx.service<br>
- Stop service<br>
	sudo systemctl stop fibo_xxx.service<br>

# release history
- version:1.0.0<br>
  first version, add  flash firmware,recovery  service.<br>
- version:1.0.2<br>
  1. modify project build script<br>
  2. optimize helper and flash service source code<br>
- version:1.0.3<br>
  modify project build script<br>

