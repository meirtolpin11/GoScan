// copied from - https://github.com/Adminisme/ServerScan
package portscan

import (
	"fmt"
	"net"
	"sync"
	"time"
)


// checking open ports per host
// getting a ports channel as input, reading from until there are values in the channel
// then stops and insert True to "done" channel so the parent function know that the thread is finished 
func ProbeHosts(host string, ports <-chan int, respondingHosts chan<- int, done chan<- bool, model string, adjustedTimeout int) {
	Timeout := time.Duration(adjustedTimeout) * time.Second
	for port := range ports{
		start := time.Now()
		con, err := net.DialTimeout("tcp4", fmt.Sprintf("%s:%d", host, port), time.Duration(adjustedTimeout) * time.Second)
		duration := time.Now().Sub(start)
		if err == nil {
			defer con.Close()
			address := port
			respondingHosts <- address
		}
		if duration < Timeout {
			difference := Timeout - duration
			Timeout = Timeout - (difference / 2)
		}
	}
	done <- true
}


/**	scans required ports for one host.
*	input:
	*	address - the ip address to scan
	*	probePorts - a list of ports to scan
	*	threads - number of threads to use for scanning (determinated by the number of ports to scan)
	*	timeout - channel timeout, if there is no new information from the channels after this time, the scan terminates
	*	model - protocol to scan, now only TCP is supported
	*	adjustedTimepit - connection timeout (default is 2 sec, can be changed as command argument)
* 	output:
	*	returning list of open ports on the host
*/
func ScanAllPorts(address string, probePorts []int, threads int, timeout time.Duration, model string, adjustedTimeout int) ([]int, error) {
	// ports to scan 
	ports := make(chan int, 20)

	// scan results (open ports)
	results := make(chan int, 10)

	// done threads counter
	done := make(chan bool, threads)

	for worker := 0; worker < threads; worker++ {
		// creating scanning threads 
		go ProbeHosts(address, ports, results, done, model, adjustedTimeout)
	}

	for _,port := range probePorts{
		ports <- port
	}
	close(ports)

	var responses = []int{}
	for {
		select {
			// wait for scan output
			case found := <-results:
				responses = append(responses, found)

			// if there is a thread that finished scanning
			case <-done:
				threads--
				if threads == 0 {
					return responses, nil
				}

			// if there is no new information from any thread
			case <-time.After(timeout):
				return responses, nil
		}
	}
}


/** "Parent" function of "ScanAllPorts". It receives a list of hosts and a list of ports and then scans every host
 * input:
 	* 	hostslist - list of hosts (ip address or even domain) to be scanned 
 	*   probePorts - list of ports to be scanned 
 	* 	model - scan protocol, now just TCP is supported 
 	* 	timeout - socket.connect() timeout for the scan
 * 	output:
 	* 	map of <host>:<list of open ports>
 * 
*/
func TCPportScan(hostslist []string, probePorts []int, model string, timeout int)  (map[string][]int){
	portsByHost := make(map[string][]int)
	

	// create a limit for parallel scans based on number of hosts to scan
	maxParallelScan := 20

	if ( len(hostslist) > 5 && len(hostslist) <= 50 ) {
		maxParallelScan = 40
	} else if (len(hostslist) > 50 && len(hostslist) <= 100 ){
		maxParallelScan = 50
	} else if (len(hostslist) > 100 && len(hostslist) <= 150 ){
		maxParallelScan = 60
	} else if (len(hostslist) > 150 && len(hostslist) <= 200 ){
		maxParallelScan = 70
	} else if (len(hostslist) > 200){
		maxParallelScan = 75
	}

	// limit number of threads to be used based on number of ports to scan 
	thread := 5
	if (len(probePorts) > 500 && len(probePorts) <= 4000 ) {
		thread = len(probePorts)/100
	} else if (len(probePorts) > 4000 && len(probePorts) <= 6000 ) {
		thread = len(probePorts)/200
	} else if (len(probePorts) > 6000 && len(probePorts) <= 10000 ) {
		thread = len(probePorts)/350
	} else if (len(probePorts) > 10000 && len(probePorts) < 50000 ){
		thread = len(probePorts)/400
	} else if (len(probePorts) >= 50000 && len(probePorts) <= 65535 ){
		thread = len(probePorts)/500
	}

	var wg sync.WaitGroup
	mutex := &sync.Mutex{}

	// creating a channel to create a "limiter" for the host scan calls
	// a channel of fixed size 
	limiter := make(chan struct{}, maxParallelScan)
	
	for _,host :=range hostslist{
		wg.Add(1)

		// adding some value into the "limiter" channel, if the channel is full - it will wait 
		limiter <- struct{}{}

		go func(host string) {
			defer wg.Done()

			openPorts, err := ScanAllPorts(host, probePorts,thread, 5*time.Second,model,timeout)
			if err == nil && len(openPorts) > 0{
				mutex.Lock()
			
				portsByHost[host] = openPorts

				mutex.Unlock()
			}

			// after completing the scan - pop a value from the channel so a new scan could be started 
			<-limiter
		}(host)
	}
	wg.Wait()

	return portsByHost
}