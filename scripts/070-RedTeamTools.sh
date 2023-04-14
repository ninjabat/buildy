#!/bin/bash
#
# Install Red Team type tools


# install evilwinrm
sudo gem install evil-winrm

# install bloodhound
sudo apt install -y bloodhound neo4j

# install seclists
sudo apt install -y seclists

# install impacket
mkdir -p $myToolDir/impacket
git clone https://github.com/SecureAuthCorp/impacket.git $myToolDir/impacket
sudo -u $uName pip3 install -r $myToolDir/impacket/requirements.txt
cd $myToolDir/impacket/
sudo -u $uName pip3 install .
sudo -u $uName python3 setup.py install
cd $origDir

# get kerbrute
mkdir -p $myToolDir/kerbrute
cd $myToolDir/kerbrute
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
chmod +x kerbrute_linux_amd64

sudo apt install -y snmp strongswan powercat

# winpeas / linpeas
sudo apt install -y peass

# ngrok for c2
curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo \
tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null &&
\echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | \
sudo tee /etc/apt/sources.list.d/ngrok.list && \
sudo apt update && sudo apt install ngrok
