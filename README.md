# GoScan
![Author](https://img.shields.io/badge/Author-Mher-blueviole) ![build](https://img.shields.io/badge/build-passing-green.svg) ![](https://img.shields.io/badge/language-golang-blue.svg)
```
  ________        _________                     
 /  _____/  ____ /   _____/ ____ _____    ____  
/   \  ___ /  _ \\_____  \_/ ___\\__  \  /    \ 
\    \_\  (  <_> /        \  \___ / __ \|   |  \
 \______  /\____/_______  /\___  (____  |___|  /
        \/              \/     \/     \/     \/ 
```
**Golang** network scanner and service detection tool.

## Details 
- Multiplatform support (Windows, Linux, Mac)
- Support only TCP scans
- Service and application version detection function, the built-in fingerprint probe adopts: [ nmap-service-probes ] (https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes)
- Custom modules functionality (you can do whatever you want with the scan results)

## Why Golang? 
Generally because my goal was to get some knowledge of **Golang** programming. Honestly, I think it's not the right language for this kind of project, but I still happy that I used Golang.

## Usage 
```shell
Usage of ./scanner:
  -all
        scan for all mathces
  -csv
        Output as CSV
        [BOOL] default false
  -e string
        Exclude the following field from the output.
        CSV mode only
         -e Banner,RawBanner,Hostname 
  -h string
        Host to be scanned, supports four formats:
        192.168.1.1
        192.168.1.1-10
        192.168.1.*
        192.168.1.0/24.
  -i string
        Include only the following field from the output.
        CSV mode only
        Overrides exclude filer
         -i IP,Name,Port 
  -o string
        Output the scanning information to file.
        CSV mode only
  -p string
        Customize port list, separate with ',' example: 21,22,80-99,8000-8080 ... (default "80-99,7000-9000,9001-9999,4430,1433,1521,3306,5000,5432,6379,21,22,100-500,873,4440,6082,3389,5560,5900-5909,1080,1900,10809,50030,50050,50070")
  -t int
        Setting scaner connection timeouts,Maxtime 30 Second. (default 2)
```

## Nmap Probes
The scanner uses **nmap probes** to scan the targets - So there are a lot of services that can be recognized by this tool.

## Modules
The most interesting part of this project is the **Modules** option. 

I wanted to provide a functionality of modules so every user can add his own code to work with the scan result. (Take a look on the [Modules](https://github.com/meirtolpin11/GoScan/tree/main/modules) folder and package)

As an example, SMB module is provided. 

The **Module** should implement just one function, with the following signature

``` func module(result *(Types.Result)) {} ```

Then it should **register** itself into the modules list. For example - 

``` data.PortModules[<port>] = append(data.PortModules[<port>], <module function>) ```

You can always refer to the demo SMB module. You can find there all you need to know.

##  💖Thanks
This project is based on [ServerScan](https://github.com/Adminisme/ServerScan). I fixed a lot of bugs, documented the code and added some more functionality.

* [iprange](https://github.com/malfunkt/iprange) - IPv4 address parser for the nmap format
* [ServerScan](https://github.com/Adminisme/ServerScan) - Network Scanner in go, **this project is based on ServerScan**. 
* [vscan-go](https://github.com/RickGray/vscan-go) - Golang version for nmap service and application version detection
