# LoaderInjector

### Details: 
- syscall unhooking using FreshCopy
- payload encryption using xor - loaded as an argument
- process injection - targeting 'WerFault.exe'

### Usage:
- make a raw shellcode and encrypt it using [xor](https://github.com/MaorSabag/LoaderInjector/blob/main/xor.py)
- Compile the LoaderInjector an execute it giving the shellcode as an arguemnt

### POC:
![poc](https://github.com/MaorSabag/LoaderInjector/blob/main/meter_werfault.png)

### AntiScan 01-11-2022:
![antiscan](https://github.com/MaorSabag/LoaderInjector/blob/main/antiscan_werfault.png)
