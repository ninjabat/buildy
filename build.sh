#!/bin/bash

# Define Environmental Variables
export uName=$( users | cut -d' ' -f 1 )
export origDir=$( pwd )

# feel free to modify as appropriate
export myDir=/home/$uName/Pentesting
export myToolDir=/home/$uName/Tools
export tempVIMRC=/home/$uName/Downloads
export homeDir=/home/$uName

mkdir -p $myToolDir

echo "Installing tools, this may take a while!"

# Loop through all .sh files in the scripts directory
for script in $origDir/scripts/*.sh
do
# Check if the file is executable
  if [ -x "$script" ]
  then
    # Run the executable script with the environmental variables set
    . "$script"
  else
    echo "$script is not executable, skipping..."
  fi 
done

