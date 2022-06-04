package main

import (
	"MyCode/core/ProbeParser"
	"MyCode/core/portscan"
	"fmt"
)


func main() {

	target := "192.168.1.129"	
	port := 80
	var targets []string;
	var ports []int;


	targets = append(targets, target)

	ports = append(ports, port)
	ports = append(ports, 445)
	ports = append(ports, 135)
	ports = append(ports, 3389)

	fmt.Println("scanning - " + target)

	// initializing probes var
	fmt.Println("Loading probes")
	vscan := ProbeParser.VScan{}
	vscan.ParseServiceProbes()
	fmt.Println("Finished loading probes")

	// next step is to figure out all the open ports of the target
	//func TCPportScan(hostslist []string,ports string,model string,timeout int)  ([]string,[]string){

	// scanning open ports 
	// returns <hosts, addresses>, hosts are not relevant for the next steps. just addresses
	_, addresses := portscan.TCPportScan(targets, ports, "tcp", 10)
	fmt.Println(addresses)


	results := vscan.ScanTarget(target, ports)
	
	
	for _, results := range results {
		for _, result := range results {
			fmt.Printf("%s:%d %s %s %s\n", result.Target.IP, result.Target.Port, result.Service.Name, result.Service.Extras.Version, result.Service.Extras.Hostname)
		}
		
	}

	// here we should run probes checks on all the opened ports 


}
