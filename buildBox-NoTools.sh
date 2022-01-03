#!/bin/bash

#
# usage ./buildBox 
#

uName=$( whoami )
origDir=$( pwd )

myDir=/home/$uName/Pentesting
myToolDir=/home/$uName/Tools
tempVIMRC=/home/$uName/Downloads
homeDir=/home/$uName

mkdir -p $myDir
cd $myDir

sudo apt update
sudo apt install -y gedit vim-gtk xterm i3 nautilus compton nitrogen expect locate


#
# Copy local tools & backgrounds
#
cd $origDir
cp backgrounds/* $homeDir/Pictures

#
# fix configs
#
cd $origDir
sed -i "s/kali/$uName/g" bg-saved.cfg
sed -i "s/kali/$uName/g" nitrogen.cfg
mkdir -p $homeDir/.config/nitrogen/ $homeDir/.config/i3/
echo "exec --no-startup-id nitrogen --restore" >>/etc/i3/config
echo "exec --no-startup-id compton" >> /etc/i3/config



sudo cp compton.conf /etc/xdg/compton.conf
sudo cp vimrc /etc/vimrc
sudo cp bg-saved.cfg $homeDir/.config/nitrogen/bg-saved.cfg
sudo cp nitrogen.cfg $homeDir/.config/nitrogen/nitrogen.cfg
cp i3config $homeDir/.config/i3/config


# update timezone
sudo timedatectl set-timezone America/New_York

# restart services
nitrogen restart
pkill compton && compton

# cleanup 
sudo apt -y autoremove

sudo updatedb
