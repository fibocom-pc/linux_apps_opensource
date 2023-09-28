Fibocom Linux apps.
This is a Fibocom linux apps set project for wwan devices.
  Flash service: firmware update, switch, recovery.
  Ma service: fccunlock(It is not open source. Contact the OEM to provide it).
  Config service: OEM configuration function.
  Helper service: provider dbus API for Flash/Ma/Config service.

License.
The fibo_flash fibo_config  fibo_helper binaries are both GPLv2+.

notice:
  Service must be used with fw_package. Before installing service, ensure that fw_package has been installed. Obtain the fw package from the corresponding OEM .
  fw_switch using fastboot so you can install fastboot with command `sudo apt-get install fastboot`

Building on Ubuntu

1. Install
  sudo apt install camke
  sudo apt install build-essential
  sudo apt install -y pkg-config
  sudo apt install libglib2.0-dev  
  sudo apt install libxml2-dev
  sudo apt install libudev-dev
  sudo apt install libmbim-glib-dev
  sudo apt install libdbus-1-dev
  sudo apt install libmm-glib-dev


2. Build
  ./build.sh [operator]
  operator: 1)build_all (build service code and make deb file )
            2)build_service (build service code include fibo_helper,fibo_flash,fibo_config)
            3)make_deb_file (build debian file)
            4)clean_project (clean project)

  examples:./build.sh 1  (build_service and make debian file.)

3. install apps
 cd ./release/dpkg
 sudo dpkg -i fiboapps-x.x.x.deb

4.
If using systemd, use
- start service
	sudo systemctl start fibo_xxx.service
- Get status
	sudo systemctl status fibo_xxx.service
- Stop service
	sudo systemctl stop fibo_xxx.service

5. uninstall apps
 sudo dpkg -r linux-apps

version:1.0.0
  first version, add  flash firmware,recovery  service.


