# buildy

This project is for automatically building attack boxes - whether it's a Parrot Linux pwnbox in Hack the Box or a fresh Kali VM, the goal here is to provide a consistent set of tools and configurations... just like I like them.

This project includes setting up obscure features like i3, vim, and nitrogen for the best window managing & text editing you can get (probably not).

## Installation
```
  git clone https://github.com/ninjabat/buildy.git 
  cd buildy
  sudo ./build.sh
```
You can remove tools that you don't want to install by simply making specific scripts in the scripts/ directory non executable:
```
cd scripts
chmod -x 020*
```

## Tools 
This project also includes precompiled static tools that might be useful; these are not updated (almost ever), but are bread & butter tools like netcat and nmap.  

This project incudes windows binaries like netcat & plink, but also a few common privesc exploits compiled from source by me.

Finally, some binary exploitation tools & templates that are useful.
