#!/bin/bash
#
# Install crypto tools
#
#
# clone various tools
cd $myToolDir
git clone https://github.com/Ganapati/RsaCtfTool.git
git clone https://github.com/mandiant/flare-floss.git

# install cyberchef as docker container
sudo apt install -y docker.io
sudo docker pull mpepping/cyberchef
sudo docker run -d -p 8000:8000 mpepping/cyberchef
echo "access cyberchef by going to http://localhost:8000"


