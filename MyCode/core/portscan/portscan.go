// copied from - https://github.com/Adminisme/ServerScan
package portscan

import (
	"fmt"
	"net"
	"sync"
	"time"
)

func ProbeHosts(host string, ports <-chan int, respondingHosts chan<- int, done chan<- bool, model string, adjustedTimeout int) {
	Timeout := time.Duration(adjustedTimeout) * time.Second
	for port := range ports{
		start := time.Now()
		con, err := net.DialTimeout("tcp4", fmt.Sprintf("%s:%d", host, port), time.Duration(adjustedTimeout) * time.Second)
		duration := time.Now().Sub(start)
		if err == nil {
			defer con.Close()
			address := port

			// unrelevant print
			/*if model == "tcp" {
				fmt.Printf("(TCP) Target %s is open\n",address)
			}else {
				fmt.Println(address)
			}*/


			respondingHosts <- address
		}
		if duration < Timeout {
			difference := Timeout - duration
			Timeout = Timeout - (difference / 2)
		}
	}
	done <- true
}

func ScanAllports(address string, probePorts []int, threads int, timeout time.Duration, model string, adjustedTimeout int) ([]int, error) {
	ports := make(chan int, 20)
	results := make(chan int, 10)
	done := make(chan bool, threads)

	for worker := 0; worker < threads; worker++ {
		go ProbeHosts(address, ports, results, done, model, adjustedTimeout)
	}

	for _,port := range probePorts{
		ports <- port
	}
	close(ports)

	var responses = []int{}
	for {
		select {
		case found := <-results:
			responses = append(responses, found)
		case <-done:
			threads--
			if threads == 0 {
				return responses, nil
			}
		case <-time.After(timeout):
			return responses, nil
		}
	}
}

func TCPportScan(hostslist []string,probePorts []int,model string,timeout int)  ([]string,map[string][]int){
	var aliveHosts []string
	portsByHost := make(map[string][]int)
	
	lm := 20
	if (len(hostslist)>5 && len(hostslist)<=50) {
		lm = 40
	}else if(len(hostslist)>50 && len(hostslist)<=100){
		lm = 50
	}else if(len(hostslist)>100 && len(hostslist)<=150){
		lm = 60
	}else if(len(hostslist)>150 && len(hostslist)<=200){
		lm = 70
	}else if(len(hostslist)>200){
		lm = 75
	}

	thread := 5
	if (len(probePorts)>500 && len(probePorts)<=4000) {
		thread = len(probePorts)/100
	}else if (len(probePorts)>4000 && len(probePorts)<=6000) {
		thread = len(probePorts)/200
	}else if (len(probePorts)>6000 && len(probePorts)<=10000) {
		thread = len(probePorts)/350
	}else if (len(probePorts)>10000 && len(probePorts)<50000){
		thread = len(probePorts)/400
	}else if (len(probePorts)>=50000 && len(probePorts)<=65535){
		thread = len(probePorts)/500
	}

	var wg sync.WaitGroup
	mutex := &sync.Mutex{}
	limiter := make(chan struct{}, lm)
	aliveHost := make(chan string, lm/2)
	go func() {
		for s := range aliveHost {
			fmt.Println(s)
		}
	}()
	for _,host :=range hostslist{
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			defer wg.Done()

			openPorts, err := ScanAllports(host, probePorts,thread, 5*time.Second,model,timeout)
			if err == nil && len(openPorts)>0{
				mutex.Lock()
				
				aliveHosts = append(aliveHosts,host)
				portsByHost[host] = openPorts

				mutex.Unlock()
			}
			<-limiter
		}(host)
	}
	wg.Wait()
	close(aliveHost)
	return aliveHosts,portsByHost
}