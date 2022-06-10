package main

import (
	"MyCode/core/ProbeParser"
	"MyCode/core/portscan"
	"encoding/json"
	"flag"
	"github.com/malfunkt/iprange"
	"strings"
	"strconv"
	"log"
	"fmt"
	"os"
	"bufio"
)


var hostsInput = ""
var portsInput = ""
var outFileInput = ""
var outputWriter *bufio.Writer
var printCSV = false
var timeoutInput int
var ports []int
var hostLists []string

func init()  {
	// Tools arguments 

	flag.StringVar(&hostsInput, "h", "", "Host to be scanned, supports four formats:\n192.168.1.1\n192.168.1.1-10\n192.168.1.*\n192.168.1.0/24.")

	flag.StringVar(&portsInput, "p", "80-99,7000-9000,9001-9999,4430,1433,1521,3306,5000,5432,6379,21,22,100-500,873,4440,6082,3389,5560,5900-5909,1080,1900,10809,50030,50050,50070", "Customize port list, separate with ',' example: 21,22,80-99,8000-8080 ...")

	flag.IntVar(&timeoutInput, "t", 2, "Setting scaner connection timeouts,Maxtime 30 Second.")

	flag.StringVar(&outFileInput, "o", "", "Output the scanning information to file.")

	flag.BoolVar(&printCSV, "csv", false, "Output as CSV\n[BOOL] default false")

	flag.Parse()


	if outFileInput != "" {
		f, _ := os.Create(outFileInput)
		defer f.Close()

		outputWriter = bufio.NewWriter(f)
	}

	// parsing hosts input 
	hostlist, err := iprange.ParseList(hostsInput)
	if err == nil {
		hostsList := hostlist.Expand()
		for _, host := range hostsList {
			host := host.String()
			hostLists = append(hostLists, host)
		}

	} else {
		flag.Usage()
		os.Exit(1)
	}

	
	for _, port := range strings.Split(portsInput, ",") {
		inVar, _ := strconv.Atoi(port)
		ports = append(ports, inVar)	
	}
}

func print(data string) {

	if outFileInput == "" {
		fmt.Println(data)
	} else {
		fmt.Fprintf(outputWriter, data + "\n")
		outputWriter.Flush()
	}
}

func main() {

	headerPrinted := false

	log.Printf("Found %d Hosts. \n", len(hostLists))


	log.Printf("Scanning %d ports \n", len(ports))
	
	// loading nmap probes from the file 
	vscan := ProbeParser.VScan{}
	vscan.ParseServiceProbes()

	// scanning open ports 
	// returns <hosts, addresses>, hosts are not relevant for the next steps. just addresses
	_, addresses := portscan.TCPportScan(hostLists, ports, "tcp", 10)

	for host, open_ports := range addresses {
		
		results := vscan.ScanTarget(host, open_ports)

		for _, results := range results {
			for _, result := range results { 

				if printCSV {

					if !headerPrinted {
						print(strings.Join(ProbeParser.GetHeaders(&result), ","))
						headerPrinted = true
					}
					print(strings.Join(ProbeParser.GetValues(&result), ","))

				} else {
					s, _ := json.MarshalIndent(result, "", "\t")
					log.Println(string(s))	
				}
				
				
				

			}
			
		}
	}



}
