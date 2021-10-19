#!/bin/bash

#
# usage ./buildBox 
#

uName=$( whoami )
origDir = $( pwd )

myDir=/home/$uName/Pentesting
myToolDir=/home/$uName/Tools
tempVIMRC=/home/$uName/Downloads
homeDir =/home/$uName

mkdir -p $myDir
cd $myDir

sudo apt update
sudo apt install -y gedit vim-gtk xterm i3 nautilus compton nitrogen


#install ODAT
#mkdir -p $myToolDir/odat
#cd $myToolDir/odat
#wget https://github.com/quentinhardy/odat/releases/download/4.3/odat-linux-libc2.12-x86_64.tar.gz
#tar --extract -f odat-linux-libc2.12-x86_64.tar.gz .

# clone various tools
cd $myToolDir
git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite.git
git clone https://github.com/sullo/nikto.git
git clone https://github.com/Ganapati/RsaCtfTool.git
git clone https://github.com/gchq/CyberChef.git

# install cyberchef
sudo apt install -y npm
npm install -g grunt-cli
cd CyberChef
sudo npm install
grunt dev & disown;
cd ..

# install evilwinrm
sudo gem install evil-winrm

# install bloodhound
sudo apt install -y bloodhound neo4j 

# install some web tools
sudo apt install -y cadaver
sudo apt install -y gobuster
sudo apt install -y hydra-gtk

# install impacket
mkdir -p $myToolDir/impacket
git clone https://github.com/SecureAuthCorp/impacket.git $myToolDir/impacket
sudo pip3 install -r $myToolDir/impacket/requirements.txt
cd $myToolDir/impacket/
sudo pip3 install .
sudo python3 setup.py install
cd $origDir

# get kerbrute
mkdir -p $myToolDir/kerbrute
cd $myToolDir/kerbrute
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
chmod +x kerbrute_linux_amd64

cd $myDir

sudo apt -y autoremove


sudo pip install pyip pycrypto pyopenssl

sudo apt install -y snmp strongswan powercat

#
# copy local tools
#
cd $origDir
cp -r tools/ $myToolDir/


#
# fix configs
#
cd $origDir
sed -i "s/kali/$uName/g" bg-saved.cfg
sed -i "s/kali/$uName/g" nitrogen.cfg

sudo cp compton.conf /etc/xdg/compton.conf
sudo cp vimrc /etc/vimrc
sudo cp bg-saved.cfg $homeDir/.config/nitrogen/bg-saved.cfg
sudo cp nitrogen.cfg $homeDir/.config/nitrogen/nitrogen.cfg
cp i3config $homeDir/i3/config

cd ~
echo "exec --no-startup-id nitrogen --restore" >> $homeDir/.config/i3/config
echo "exec --no-startup-id compton" >> $homeDir/.config/i3/config

# update timezone
sudo timedatectl set-timezone America/New_York

# restart services
nitrogen restart
pkill compton && compton



sudo updatedb
