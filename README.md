# buildy

This project is for automatically building attack boxes - whether it's a Parrot Linux pwnbox in Hack the Box or a fresh Kali VM, the goal here is to provide a consistent set of tools and configurations... just like I like them.

This project includes setting up obscure features like i3, vim, and nitrogen for the best window managing & text editing you can get (probably not).

## Installation
  ```git clone https://github.com/ninjabat/buildy.git 
  cd buildy
  chmod +x buildBox.sh
  sudo ./buildBox.sh
  ```
  
## Tools 
This project also includes precompiled static tools that might be useful; these are not updated (almost ever), but are bread & butter tools like netcat and nmap.  

This project incudes windows binaries like netcat & plink, but also a few common privesc exploits compiled from source by me.

Finally, I'm stashing my buffer overflow templates here for safe keeping.  Dependencies like pwntools & pwndbg should be satisfied via the build script.
