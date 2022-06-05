package main

import (
	"MyCode/core/ProbeParser"
	"MyCode/core/portscan"
	"fmt"
	"encoding/json"
	"os"
)


func main() {

	target := os.Args[1]
	port := 1433
	var targets []string;
	var ports []int;


	targets = append(targets, target)

	ports = append(ports, port)

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


	/*
		It's important to mention, that sorting rarity from low to high will give more speed
		while sorting from high to low will give more accuracy
	*/
	results := vscan.ScanTarget(target, ports)
	
	
	for _, results := range results {
		for _, result := range results { 
			s, _ := json.MarshalIndent(result, "", "\t")
			fmt.Println(string(s))
		}
		
	}

	// here we should run probes checks on all the opened ports 


}
