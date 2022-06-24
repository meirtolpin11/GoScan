package ProbeParser

import (
	"regexp"
	"strings"
	"net"
	"time"
	"GoScan/modules"
	"GoScan/core/ProbeParser/Types"
)

func checkMatchForResponse(response []byte, match Types.Match, lastMatch *Types.Match, result *Types.Result) (bool) {
	// if found the right probe 
	matchFound := false	
	var tempService Types.Service

	matched := match.MatchPattern(response)

	// if not matched to the probe - continue to the next probe 
	if !matched { return matchFound }

	// if this match is "less" accurate than the already found match.
	// if the pattern is longer - the match is more accurate.
	if len(match.Pattern) < len((*lastMatch).Pattern) { return matchFound }

	// if there is already service that found
	if len((*result).Service.Name) > 0 {
		matchFound = true

		tempService.Name = match.Service
		tempService.Extras = match.ParseVersionInfo(response)

		(*result).AdditionalServices = append((*result).AdditionalServices, tempService)

		return matchFound
	}


	matchFound = true
	*lastMatch = match

	(*result).Service.Name = match.Service
	
	(*result).Banner = trimBanner(response)

	(*result).Service.Extras = match.ParseVersionInfo(response)


	return matchFound
}

/*
	Here I will use the vscan database to scan particular ip:ports and try to figure out what is the
	service running in the backgroud.

	the algorithm is very simple -
	* first of all just sorting the probes from rare to less rare
	* then run all the probes agains every port that should be scanned.
	* if service is recognized (for example SMB, HTTP and more) - finish the probe checks.
	* I will not try to get http headers and titles, as it's will be part of the modules section.
*/

func scanWithProbes(v *Types.VScan, target Types.Target, probes *[]Types.Probe, allMatches bool) (Types.Result, error) {
	var result = Types.Result{Target: target}

	// just appending port to ip address
	addr := target.GetAddress()

	// if found the right probe 
	var lastMatch Types.Match

	// returning if found "hard" match, else will continue to next matches.
	for _, probe := range *probes {
		var response []byte;

		// decoding the probe regex pattern 
		probeData, _ := Types.DecodeData(probe.Data)


		// sending the probe and waiting for info
		response, _ = grabResponse(addr, probeData)

		// if no response is recieved - continue to the next probe 
		if len(response) == 0 { continue }

		result.RawBanner = response

		// try to match the probes -
		for _, match := range *probe.Matchs {	

			matchFound := checkMatchForResponse(response, match, &lastMatch, &result)

			if matchFound && !allMatches {
				return result, nil
			}

						
		}	

		fallback := probe.Fallback
		fbProbe, status := v.ProbesMapKName[fallback]
		if status {
			for _, match := range *fbProbe.Matchs {
				
				matchFound := checkMatchForResponse(response, match, &lastMatch, &result)

				if matchFound && !allMatches {
					return result, nil
				}

			}
		}

		if result.Banner == "" {
			result.Banner = trimBanner(response)
		}

		return result, nil
	}

	
	return result, nil
}

func trimBanner(buf []byte) string {
	bufStr := string(buf)

	var src string
	for _,ch:=range bufStr{
		if (32 < int(ch)) && (int(ch)< 125) {
			src = src + string(ch)
		}else {
			src = src +" "
		}
	}

	re, _ := regexp.Compile("\\s{2,}")
	src = re.ReplaceAllString(src, ".")
	return strings.TrimSpace(src)
}

func grabResponse(addr string, data []byte) ([]byte, error) {

	var response []byte

	dialer := net.Dialer{}

	conn, errConn := dialer.Dial("tcp", addr)
	if errConn != nil {
		return response, errConn
	}
	defer conn.Close()

	if len(data) > 0 {
		conn.SetWriteDeadline(time.Now().Add(time.Second*2))	
		_, errWrite := conn.Write(data)
		if errWrite != nil {
			return response, errWrite
		}
	}

	conn.SetReadDeadline(time.Now().Add(time.Second*2))
	for true {
		buff := make([]byte, 1024)
		n, errRead := conn.Read(buff)
		if errRead != nil {
			if len(response) > 0 {
				break
			} else {
				return response, errRead
			}
		}
		if n > 0 {
			response = append(response, buff[:n]...)
		}
	}
	return response, nil
}

/**
 * Scans the target with nmap probes and then scans with the custom modules
 * input:
 * 		v - nmap probes object
 * 		host - the hostname to scan
 * 		ports - list of ports to scan
 * 		allMatches - continue probing after a successful match to find all the possible matches 
 * output:
 * 		map of <host>:<results>
 */ 
func ScanTarget(v *Types.VScan, host string, ports []int, allMatches bool) (map[string][]Types.Result) {
	var target Types.Target

	// creating the output map
	results := make(map[string][]Types.Result)

	target.IP = host
	target.Protocol = "tcp"

	var probesUsed []Types.Probe

	// filter out all the UDP probes (now only TCP is supported)
	for _, probe := range v.Probes {
		if strings.ToLower(probe.Protocol) == strings.ToLower(target.Protocol) {
			probesUsed = append(probesUsed, probe)
		}
	}

	// use also the NULL probe because why not ?
	probesUsed = append(probesUsed, v.ProbesMapKName["NULL"])

	// sort probes by Rarity, from less rare to rare
	probesUsed = Types.SortProbesByRarity(probesUsed)

	// scan port by port 
	for _, port := range ports {
		target.Port = port
		portResult, _ := scanWithProbes(v, target, &probesUsed, allMatches)			

		// special scan model is here  
		if val, ok := modules.PortModules[port]; ok {

			for _, f := range val {
				// calling all the modules which are "binding" on this port
				f(&portResult)	
			}
			
		}
		

		results[host] = append(results[host], portResult)
	}	

	return results
}
