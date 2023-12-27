#!/bin/bash

# make it so services restart automatically when updates (will allow automatic updating)

filename=/etc/needrestart/needrestart.conf
# Edit the needrestart file if it exists
if [[ -f "$filename" ]]; then
    sudo sed -i "s/#\$nrconf{restart} = 'i';/\$nrconf{restart} = 'a';/g" /etc/needrestart/needrestart.conf
fi

echo "updating operating system..."
sudo apt update
sudo apt upgrade -y
