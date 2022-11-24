#!/bin/bash -x

aslrPATH=/proc/sys/kernel/randomize_va_space
ASLR=$( cat $aslrPATH )

if [ $ASLR = 2 ]; then
    sudo echo 0 > $aslrPATH 
    cat $aslrPATH
else
    echo "ALSR is already disabled!"
fi
