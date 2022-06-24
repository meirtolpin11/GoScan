package main

import (
	"GoScan/core/ProbeParser"
	"GoScan/core/ProbeParser/Types"
	"GoScan/core/portscan"
	"GoScan/core/helpers"
	"encoding/json"
	"flag"
	"github.com/malfunkt/iprange"
	"strings"
	"strconv"
	"log"
	"fmt"
	"os"
	"bufio"
	"sort"
)


var hostsInput = ""
var portsInput = ""
var outFileInput = ""
var excludeFields = ""
var includeFields = ""
var excludeFieldsList []string
var includeFieldsList []string
var outFileHanle *os.File
var outputWriter *bufio.Writer
var printCSV = false
var allMatches = false
var timeoutInput int
var ports []int
var hostLists []string

// initializing the scanner. parsing the command arguments and created output file if required 
func init()  {

	flag.StringVar(&hostsInput, "h", "", "Host to be scanned, supports four formats:\n192.168.1.1\n192.168.1.1-10\n192.168.1.*\n192.168.1.0/24.")

	flag.StringVar(&portsInput, "p", "80-99,7000-9000,9001-9999,4430,1433,1521,3306,5000,5432,6379,21,22,100-500,873,4440,6082,3389,5560,5900-5909,1080,1900,10809,50030,50050,50070", "Customize port list, separate with ',' example: 21,22,80-99,8000-8080 ...")

	flag.IntVar(&timeoutInput, "t", 2, "Setting scaner connection timeouts,Maxtime 30 Second.")

	flag.StringVar(&outFileInput, "w", "", "Output the scanning information to file.\n[CSV mode only]")

	flag.StringVar(&excludeFields, "ex", "", "Exclude the following field from the output.\n[CSV mode only]\n-e Banner,RawBanner,Hostname ")
	
	flag.StringVar(&includeFields, "inc", "", "Include only the following field from the output.\n[CSV mode only]\nOverrides exclude filer\n-i IP,Name,Port ")

	flag.BoolVar(&printCSV, "csv", false, "Output as CSV\n[BOOL] default false")
	
	flag.BoolVar(&allMatches, "all", false, "scan for all mathces")


	flag.Parse()

	// creating output file if so required 
	if outFileInput != "" {
		outFileHanle, err := os.Create(outFileInput)
		helpers.Check(err)
		outputWriter = bufio.NewWriter(outFileHanle)
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

	// parsing the imported ports 	
	ports = parsePort(portsInput)

	// parsing exclude list
	excludeFieldsList = strings.Split(excludeFields, ",")
	includeFieldsList = strings.Split(includeFields, ",")
}

func print(data string) {

	if outFileInput == "" {
		fmt.Println(data)
	} else {
		_, err := fmt.Fprintf(outputWriter, data + "\n")
		helpers.Check(err)
		outputWriter.Flush()
	}
}

func parsePort(ports string) []int {
	var scanPorts []int
	slices := strings.Split(ports, ",")
	for _, port := range slices {
		port = strings.Trim(port, " ")
		upper := port
		if strings.Contains(port, "-") {
			ranges := strings.Split(port, "-")
			if len(ranges) < 2 {
				continue
			}
			sort.Strings(ranges)
			port = ranges[0]
			upper = ranges[1]
		}
		start, _ := strconv.Atoi(port)
		end, _ := strconv.Atoi(upper)
		for i := start; i <= end; i++ {
			scanPorts = append(scanPorts, i)
		}
	}
	return scanPorts
}

func main() {

	headerPrinted := false

	log.Printf("Found %d Hosts. \n", len(hostLists))


	log.Printf("Scanning %d ports \n", len(ports))
	
	// loading nmap probes from the file 
	vscan := Types.VScan{}
	vscan.ParseServiceProbes()

	// scanning open ports 
	// returns <hosts, addresses>, hosts are not relevant for the next steps. just addresses
	addresses := portscan.TCPportScan(hostLists, ports, "tcp", timeoutInput)

	for host, open_ports := range addresses {
		
		results := ProbeParser.ScanTarget(&vscan, host, open_ports, allMatches)

		for _, results := range results {
			for _, result := range results { 

				if printCSV {
					if !headerPrinted {
						print(strings.Join(Types.GetHeaders(&result, includeFieldsList, excludeFieldsList), ","))
						headerPrinted = true
					}

					print(strings.Join(Types.GetValues(&result, includeFieldsList, excludeFieldsList), ","))

				} else {
					s, _ := json.MarshalIndent(result, "", "\t")
					log.Println(string(s))	
				}
			}
			
		}
	}

	outFileHanle.Close()
}
