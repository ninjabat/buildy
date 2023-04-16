#!/bin/bash -x

aslrPATH=/proc/sys/kernel/randomize_va_space
ASLR=$( cat $aslrPATH )

if [ $ASLR = 0 ]; then
    sudo echo 2 > $aslrPATH 
    cat $aslrPATH
else
    echo "ALSR is already enabled!"
fi
