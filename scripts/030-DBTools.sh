#!/bin/bash
#
# install database tools

#install ODAT
mkdir -p $myToolDir/odat
cd $myToolDir/odat
wget https://github.com/quentinhardy/odat/releases/download/4.3/odat-linux-libc2.12-x86_64.tar.gz
tar --extract -f odat-linux-libc2.12-x86_64.tar.gz .

sudo apt install -y sqlmap
