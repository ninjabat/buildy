#!/bin/bash
#
# install basics, mostly GUI, vim

sudo apt install -y gedit vim-gtk3 xterm i3 nautilus compton nitrogen expect locate build-essential


sudo apt install -y gedit vim-gtk3 xterm i3 nautilus compton nitrogen expect locate build-essential

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
sed -i "s/kali/$uName/g" configs/bg-saved.cfg
sed -i "s/kali/$uName/g" configs/nitrogen.cfg
mkdir -p $homeDir/.config/nitrogen/ $homeDir/.config/i3/
echo "exec --no-startup-id nitrogen --restore" >>/etc/i3/config
echo "exec --no-startup-id compton" >> /etc/i3/config
chown -R $uName:$uName $homeDir/.config/i3/

# high DPI for i3
cat configs/Xresources >> $homeDir/.Xresources
echo "xrdb -merge ~/.Xresources" >> $homeDir/.xinitrc
chown $uName:$uName $homeDir/.xinitrc

#
# vim plugin manager, requires pathogen setting in vimrc
#
mkdir -p $homeDir/.vim/autoload $homeDir/.vim/bundle
sudo -u $uName wget https://tpo.pe/pathogen.vim -O $homeDir/.vim/autoload/pathogen.vim
chown -R $uName:$uName $homeDir/.vim/

# vim code completer
git clone --recursive https://github.com/davidhalter/jedi-vim.git $homeDir/.vim/bundle/jedi-vim
chown -R $uName:$uName $homeDir/.vim/

# copy config files
sudo cp configs/compton.conf /etc/xdg/compton.conf
sudo cp configs/vimrc /etc/vim/vimrc
cp configs/.vimrc $homeDir/.vimrc
sudo cp configs/bg-saved.cfg $homeDir/.config/nitrogen/bg-saved.cfg
sudo cp configs/nitrogen.cfg $homeDir/.config/nitrogen/nitrogen.cfg
cp configs/i3config $homeDir/.config/i3/config
chown -R $uName:$uName $homeDir/.config/

# update timezone
sudo timedatectl set-timezone America/New_York

# restart services
nitrogen --restore
pkill compton && compton



