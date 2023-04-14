#!/bin/bash
#
# Web Tools
#

# clone various tools
cd $myToolDir
git clone https://github.com/sullo/nikto.git

# install some web tools
sudo apt install -y cadaver
sudo apt install -y gobuster
sudo apt install -y hydra-gtk


