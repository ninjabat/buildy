#!/bin/bash
#
# install basics, mostly GUI, vim

# define a function to take in a file name and line, check if that line exists, then add it if it doesn't exit in a file
# pass arguments in double quotes:
# idempotentSED "$fileName" "$line_to_add"
idempotentSED(){
    fileName=$1
    line_to_add=$2
    if grep -q "$line_to_add" "$fileName"; then
        echo "Buildy change already made in $fileName."
    else
    # Line doesn't exist, append it to the file
    echo "$line_to_add" >> "$fileName"
    fi
}


sudo apt install -y gedit vim-gtk3 xterm i3 nautilus compton nitrogen expect locate build-essential


sudo apt install -y gedit vim-gtk3 xterm i3 nautilus compton nitrogen expect locate build-essential

#
# Copy local tools & backgrounds
#
cd $origDir
sudo -u $uName cp -r tools/ $myToolDir/
mkdir -p $homeDir/Pictures
sudo -u $uName cp backgrounds/* $homeDir/Pictures
chown -R $uName:$uName $homeDir/Pictures

#
# fix configs
#
cd $origDir
sed -i "s/kali/$uName/g" configs/bg-saved.cfg
sed -i "s/kali/$uName/g" configs/nitrogen.cfg
mkdir -p $homeDir/.config/nitrogen/ $homeDir/.config/i3/

# Check if the line exists in the file
fileName=/etc/i3/config
line_to_add='exec --no-startup-id nitrogen --restore'
idempotentSED "$fileName" "$line_to_add"

line_to_add='exec --no-startup-id compton'
idempotentSED "$fileName" "$line_to_add"

chown -R $uName:$uName $homeDir/.config/i3/

# high DPI for i3
cp configs/Xresources $homeDir/.Xresources

fileName=$homeDir/.xinitrc
line_to_add='xrdb -merge ~/.Xresources'
idempotentSED "$fileName" "$line_to_add"
chown $uName:$uName $homeDir/.xinitrc

#
# vim plugin manager, requires pathogen setting in vimrc
#
sudo -u $uName mkdir -p $homeDir/.vim/autoload $homeDir/.vim/bundle
sudo -u $uName wget 'https://tpo.pe/pathogen.vim' -O $homeDir/.vim/autoload/pathogen.vim
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



