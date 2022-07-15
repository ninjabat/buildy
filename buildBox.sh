#!/bin/bash -x

#
# usage ./buildBox 
#

uName=$( users | cut -d' ' -f 1 )
origDir=$( pwd )

myDir=/home/$uName/Pentesting
myToolDir=/home/$uName/Tools
tempVIMRC=/home/$uName/Downloads
homeDir=/home/$uName

mkdir -p $myToolDir
cd $myToolDir

sudo apt update
sudo apt upgrade -y
sudo apt install -y gedit vim-gtk3 xterm i3 nautilus compton nitrogen expect locate build-essential


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
git clone https://github.com/stealthcopter/deepce.git
git clone https://github.com/mandiant/flare-floss.git
git clone https://github.com/apogiatzis/gdb-peda-pwndbg-gef.git
#git clone https://github.com/gchq/CyberChef.git
#git clone https://github.com/NebulousAnchor/Aboleth
# install cyberchef
#sudo apt install -y npm
#sudo npm install -g grunt-cli
#cd CyberChef
#sudo npm install
#grunt dev & disown;
#cd ..

# install evilwinrm
sudo gem install evil-winrm

# install bloodhound
sudo apt install -y bloodhound neo4j 

# install some web tools
sudo apt install -y cadaver
sudo apt install -y gobuster
sudo apt install -y hydra-gtk

# install reversing / exploit dev
#sudo apt install gdb-peda 
#echo "source /usr/share/gdb-peda/peda.py" >> /.gdbinit
sudo apt install gdb -y
cd $myToolDir/gdb-peda-pwndbg-gef
sudo -i $uName ./install.sh
sudo -i $uName ./update.sh
pip install psutil pyelftools capstone
sudo apt install -y gdbserver
cd $origDir

# ghidra & fix UI scaling
sudo apt install -y ghidra
sudo updatedb
sed -i 's/VMARGS_LINUX=-Dsun.java2d.uiScale=1/VMARGS_LINUX=-Dsun.java2d.uiScale=2/g' $(locate support/launch.properties)

#pwn tools
sudo apt install -y python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools
echo "export PATH=$PATH:~/.local/bin" >> $homeDir/.zshrc

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

cd $myToolDir
python -m pip install --upgrade pip
sudo pip install pyip pycrypto pyopenssl

sudo apt install -y snmp strongswan powercat 

#
# Copy local tools & backgrounds
#
cd $origDir
cp -r tools/ $myToolDir/
mkdir -p $homeDir/Pictures
cp backgrounds/* $homeDir/Pictures
chown -R $uName:$uName $homeDir/Pictures

#
# fix configs
#
cd $origDir
sed -i "s/kali/$uName/g" bg-saved.cfg
sed -i "s/kali/$uName/g" nitrogen.cfg
mkdir -p $homeDir/.config/nitrogen/ $homeDir/.config/i3/
echo "exec --no-startup-id nitrogen --restore" >>/etc/i3/config
echo "exec --no-startup-id compton" >> /etc/i3/config
chown -R $uName:$uName $homeDir/.config/i3/

# high DPI for i3
cat Xresources >> $homeDir/.Xresources
echo "xrdb -merge ~/.Xresources" >> $homeDir/.xinitrc
chown $uName:$uName $homeDir/.xinitrc

#
# vim plugin manager, requires pathogen setting in vimrc
#
mkdir -p $homeDir/.vim/autoload $homeDir/.vim/bundle && \
curl -LSso $homeDir/.vim/autoload/pathogen.vim https://tpo.pe/pathogen.vim
chown -R $uName:$uName $homeDir/.vim/

# vim code completer
git clone --recursive https://github.com/davidhalter/jedi-vim.git $homeDir/.vim/bundle/jedi-vim
chown -R $uName:$uName $homeDir/.vim/

# copy config files
sudo cp compton.conf /etc/xdg/compton.conf
sudo cp vimrc /etc/vim/vimrc
cp .vimrc $homeDir/.vimrc
sudo cp bg-saved.cfg $homeDir/.config/nitrogen/bg-saved.cfg
sudo cp nitrogen.cfg $homeDir/.config/nitrogen/nitrogen.cfg
cp i3config $homeDir/.config/i3/config
chown -R $uName:$uName $homeDir/.config/

# update timezone
sudo timedatectl set-timezone America/New_York

# restart services
nitrogen --restore
pkill compton && compton

# cleanup 
sudo apt -y autoremove

sudo updatedb
