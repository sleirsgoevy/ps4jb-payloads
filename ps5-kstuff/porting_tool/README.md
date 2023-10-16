Instructions for ps5-kstuff porting_tool (original by NotSoTypicalGamer and EchoStretch)

0. Make sure PS5 is jailbroken and running your exploit of choice with the ELF loader active
1. Use Linux, this README is focused on Ubuntu specifically (WSL2 doesnt appear to work)
2. Clone this repository locally:
   1. `git clone https://github.com/sleirsgoevy/ps4jb-payloads.git --recursive --recurse-submodules -b bd-jb`
   2. move into the right folder `cd ps4jb-payloads/ps5-kstuff/porting_tool`
3. Create `symbols.json` in thesame folder and the contents should be: `{"allproc": <ALLPROC_OFFSET>}`  
   1. to find the `ALLPROC_OFFSET` for your firmware, search on [Specter's GitHub](https://github.com/Cryptogenic/PS5-IPV6-Kernel-Exploit)
   2. the offsets are located here `document/en/ps5/offsets`, find the right `.js` file for your firmware and search for `OFFSET_KERNEL_DATA_BASE_ALLPROC`. The HEX value you will find needs to be converted to DEC (just use a website online)
   3. you can finally substitute `<ALLPROC_OFFSET>` with the DEC value you got and save the file
4. Make sure `python3` is installed
5. Install gbd-tools either with `pip install gdb-tools` or `sudo apt-get install gdb` if the other command doesn't work.
6. Install yasm with `sudo apt install yasm`
7. Try and run the script with `python3 main.py symbols.json <your.ps5.ip.address> <elf.loader.port> kernel-data.bin`
8. Once complete you should have `kernel-data.bin` dumped into porting_tool folder.
9. `symbols.json` will have also been updated to include needed information.

NOTE: This tool isn't complete. This doesn't grab all the data necessary to port "ps5-kstuff" to other firmwares. It's a WIP.
