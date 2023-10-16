Instructions for ps5-kstuff porting_tool

0. Make sure PS5 is jailbroken and elf loader is running...
1. Use Linux.. real Linux?
2. Create Symbols.json and first line should be... `{"allproc": #####}`  ...where ### is your firmwares ALLPROC offset converted from hex to dec. Specters exploit GitHub has these numbers at PS5-IPV6-Kernel-Exploit/document/en/ps5/offsets/x.xx.js just scroll to bottom and you'll see your hex ALLPROC offset, convert it and replace ### with that. 
3. clone sleirsgovey repo
`git clone https://github.com/sleirsgoevy/ps4jb-payloads.git --recursive --recurse-submodules`
cd into ps4jb-payloads
`git fetch`
`git branch -v -a`
`git switch bd-jb`
5. Put symbols.json you created into ps5-kstuff/porting_tool folder.
6. Open terminal in this folder and run each of the following commands...
7. `pip install gdb-tools` press ENTER
8. `sudo apt install yasm` press ENTER
9. `python3 main.py symbols.json your.ps5.ip.address 9020 kernel-data.bin` press ENTER - WAIT
10. Once complete you should have kernel-data.bin dumped into porting_tool folder.
11. Symbols.json will have also been updated to include needed information.

NOTE: This tool isn't complete. This doesn't grab all the data necessary to port "ps5-kstuff" to other firmeares. It's a WIP.