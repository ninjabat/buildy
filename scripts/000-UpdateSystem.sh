#!/bin/bash

# make it so services restart automatically when updates (will allow automatic updating)
sudo sed -i "s/#\$nrconf{restart} = 'i';/\$nrconf{restart} = 'a';/g" /etc/needrestart/needrestart.conf

echo "updating operating system..."
sudo apt update
sudo apt upgrade -y
