# Fibocom Linux apps
This is a Fibocom linux apps set project for wwan devices.<br>
  **Flash service:** firmware update, switch, recovery.<br>
  **Ma service:** fccunlock(It is not open source).<br>
  **Config service:** OEM configuration function.<br>
  **Helper service:** provider dbus API for Flash/Ma/Config service.<br>

# License
The fibo_flash fibo_config  fibo_helper binaries are both GPLv2+.<br>

# Notice
  - Service must be used with fw_package. Before installing service, ensure that fw_package has been installed. Obtain the fw package from the corresponding OEM .<br>
  - fw_switch using fastboot so you can install fastboot with command `sudo apt-get install fastboot`<br>
  - MA service default not enable if you want to used you should copy `/opt/fibocom/fibo_ma_service/fcc-unlock.d` to `/usr/lib/x86_64-linux-gnu/ModemManager/` command :
    1. `cp -raf  /opt/fibocom/fibo_ma_service/fcc-unlock.d  /usr/lib/x86_64-linux-gnu/ModemManager/`
    2. `rm -rf /opt/fibocom/fibo_ma_service/fcc-unlock.d`
    3. `chown -R root:root  /usr/lib/x86_64-linux-gnu/ModemManager/fcc-unlock.d`
    4. `chmod 755 -R /usr/lib/x86_64-linux-gnu/ModemManager/fcc-unlock.d`

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
1. cmake -S . -B build<br>
  if you want to install custom path you can send cmd:<br>
    `cmake -S . -B build --install-prefix <custm path>` <br>
2. cmake --build build<br>
3. sudo cmake --install build<br>
  if you install custom path in home path you can send cmd:<br>
    `cmake --install`<br>

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
- version:1.0.4<br>
  fw switch:<br>
  1. FWSwitch can not be triggered after hotplug switch verizon to CUCC sim card. (mccmnc 6 bit switch to 5 bit) <br>

  recovery: <br>
  1. The oem is damaged. After the module is powered on, recovery is triggered to burn the oem.<br>
  2. Stop the timer when the fastboot port appears.<br>

  Ma Service:<br>
  1. If an exception is returned, modify the judgment string<br>
  2. Add the SKU ID<br>

  helper:<br>
  1. Support MBIM message indication and revert previous MM indication support.<br>
  2. Re-add timeout recovery mechanism if helperm is no response.<br>
  3. When the helper returns a command to the caller, the code logic is incorrect.<br>
- version:1.0.5<br>
  config_service:<br>
  1. support sim card slot switch slot 1.<br>
  
  helper:<br>
  1. The SIM card status and MCCMNC on the network side can be queried using mbim messages.<br>
  2. recovery You can select the version number to flash.<br>

  fw switch:<br>
  1. Support low-battery upgrade in AC mode.<br>
  2. If the obtained SubSysid is empty, no upgrade is performed.<br>

- version:1.0.6<br>
  Fix spelling errors in source code<br>
  
  helper:<br>
  1. The optimization progress bar is displayed<br>
  2. Optimize recovery download logic<br>
  3. modify helperm abnormal stuck status<br>
 
  fw switch:<br>
  1. Can't do FW switch after recovery when port state is abnormal on first boot.<br>
  2. Support monitoring of new package installation.<br>
  
