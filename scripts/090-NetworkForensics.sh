#!/bin/bash
#
#
#
#
#


# netflow tools
sudo apt install nfdump

# passive DNS for parsing pcap into DNS logs
sudo apt install git-core binutils-dev libldns-dev libpcap-dev autoreconf

# libdate-simple-perl is also needed for pdns2db.pl
git clone https://github.com/gamelinux/passivedns.git
cd passivedns/
autoreconf --install
./configure
make

# create a log file for passivedns
sudo touch /var/log/passivedns.log
sudo chown kali:kali /var/log/passivedns.log 
cp src/passivedns ../../passivedns_bin # copy binary out of the src dir
cd ..
sudo rm -r passivedns/
