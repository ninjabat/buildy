#!/bin/bash

myDir=/home/kali/Pentesting
myToolDir=/home/kali/Tools
tempVIMRC=/home/kali/Downloads
homeDir =/home/kali

mkdir -p $myDir
cd $myDir

# fix the repo
#wget "https://deb.parrot.sh/parrot/pool/main/p/parrot-archive-keyring/parrot-archive-keyring_2020.8%2Bparrot3_all.deb" && sudo dpkg -i parrot-archive-keyring*.deb && rm parrot-archive-keyring*.deb

sudo apt update
sudo apt install -y gedit vim-gtk xterm i3 nautilus compton nitrogen


#sudo cp $tempVIMRC/myVimRC /etc/vim/vimrc

#install ODAT
mkdir -p $myToolDir/odat
cd $myToolDir/odat
wget https://github.com/quentinhardy/odat/releases/download/4.3/odat-linux-libc2.12-x86_64.tar.gz
tar --extract -f odat-linux-libc2.12-x86_64.tar.gz .

# clone various tools
cd $myToolDir
git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite.git
git clone https://github.com/sullo/nikto.git
git clone https://github.com/Ganapati/RsaCtfTool.git

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

# get kerbrute
mkdir -p $myToolDir/kerbrute
cd $myToolDir/kerbrute
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
chmod +x kerbrute_linux_amd64

cd $myDir

sudo apt -y autoremove


sudo pip install pyip pycrypto pyopenssl

sudo apt install -y snmp strongswan


#
# fix configs
#
sudo cp compton.conf /etc/xdg/compton.conf
sudo cp vimrc /etc/

cd ~
echo "exec --no-startup-id nitrogen --restore" >> $homeDir/.config/i3/config
echo "exec --no-startup-id compton" >> $homeDir/.config/i3/config

# update timezone
sudo timedatectl set-timezone America/New_York

sudo updatedb
