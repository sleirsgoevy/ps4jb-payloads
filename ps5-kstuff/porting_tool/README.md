# Instructions for porting_tool

1. Load Specter host and keep PS5 on ELF loading screen ...  
  
2. Use Oracle VM VirtualBox Or Other Linux (WSL doesnt appear to work)  
-   May need to bridge connection with Oracle VM VirtualBox  

3. Clone this repository locally:  
-    `git clone https://github.com/sleirsgoevy/ps4jb-payloads.git --recursive --recurse-submodules -b bd-jb`  
-    Enter directroy `cd ps4jb-payloads/ps5-kstuff/porting_tool`  

4. Create symbols.json and first line should be... `{"allproc": <Firmware dec #>}`
-    Ex. `{"allproc": 41344088}`

Firmware dec #
-    1.xx = 40705048
-    2.xx = 40901672
-    3.xx = 41344088
-    4.xx = 41868472
-    5.xx = 43048192
   
5. Put symbols.json you created into ps5-kstuff/porting_tool folder.  

6. Open terminal in this Porting_tool folder and run each of the following commands...  
-   `pip install gdb-tools` or `sudo apt-get install gdb` press ENTER  
-   `sudo apt install yasm` press ENTER  
   
7. Run `python3 main.py symbols.json <ps5_ip> <elf_loader_port> <Kernel_Filename>`  press ENTER - WAIT  
-    Ex. `python3 main.py symbols.json 10.0.0.150 9020 kernel-data.bin`  
  
One complete you should have kernel-data.bin and the symbols.json will have have all the offsets in dec format.  

# Supported PS5 Firmares  
3.00, 3.10, 3.20, 3.21, 4.00, 4.02, 4.03, 4.50, 4.51

## Known issue  
It may fail just load PS5 back to specter host and the script will continue.  

NOTE: This tool isn't complete. This doesn't grab all the data necessary to port "ps5-kstuff" to other firmwares. It's a WIP.
