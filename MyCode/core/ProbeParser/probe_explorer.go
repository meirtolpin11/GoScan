package ProbeParser

import (
	"sort"
	"fmt"
	"regexp"
	"strings"
	"net"
	"time"
)

/*
	Here I will use the vscan database to scan particular ip:ports and try to figure out what is the
	service running in the backgroud.

	the algorithm is very simple -
	* first of all just sorting the probes from rare to less rare
	* then run all the probes agains every port that should be scanned.
	* if service is recognized (for example SMB, HTTP and more) - finish the probe checks.
	* I will not try to get http headers and titles, as it's will be part of the modules section.
*/

func (v *VScan) scanWithProbes(target Target, probes *[]Probe) (Result, error) {
	var result = Result{Target: target}

	// just appending port to ip address
	addr := target.GetAddress()

	// if found the right probe 
	matchFound := false
	softFound := false
	var softMatch Match


	// returning if found "hard" match, else will continue to next matches.
	for _, probe := range *probes {
		var response []byte;

		probeData, _ := DecodePattern(probe.Data)
		response, _ = grabResponse(addr, probeData)

		// continue to the next probe 
		if len(response) == 0 { continue }

		// try to match the probes -
		for _, match := range *probe.Matchs {

			matched := match.MatchPattern(response)

			// if not matched to the probe - continue to the next probe 
			if !matched { continue }

			if match.IsSoft {
				matchFound = true
				softFound = true
				softMatch = match
			} else {
				extras := match.ParseVersionInfo(response)
				result.Service.Name = match.Service

				result.Banner = trimBanner(response)
				result.Service.Extras = extras

				return result, nil
			}
		}	

		fallback := probe.Fallback
		fbProbe, status := v.ProbesMapKName[fallback]
		if status {
			for _, match := range *fbProbe.Matchs {
				matched := match.MatchPattern(response)

				// if not matched to the probe - continue to the next probe 
				if !matched { continue }

				if match.IsSoft {
					matchFound = true
					softFound = true
					softMatch = match 

				} else {
					extras := match.ParseVersionInfo(response)
					result.Service.Name = match.Service

					result.Banner = trimBanner(response)
					result.Service.Extras = extras

					return result, nil
				}

			}
		}


		if !matchFound {

			// if got response - but no match were found - return the recieved banner
			result.Banner = trimBanner(response)

			if softFound {
				extras := softMatch.ParseVersionInfo(response)	
				result.Service.Extras = extras
				result.Service.Name = softMatch.Service

			}

			return result, nil
		}
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

func (v *VScan) ScanTarget(host string, ports []int) (map[string][]Result) {
	var target Target
	results := make(map[string][]Result)

	target.IP = host
	target.Protocol = "tcp"

	var probesUsed []Probe

	for _, probe := range v.Probes {
		if strings.ToLower(probe.Protocol) == strings.ToLower(target.Protocol) {
			probesUsed = append(probesUsed, probe)
		}
	}

	probesUsed = append(probesUsed, v.ProbesMapKName["NULL"])

	probesUsed = sortProbesByRarity(probesUsed)

	for _, port := range ports {
		target.Port = port
		portResult, _ := v.scanWithProbes(target, &probesUsed)			

		// special scan model is here 

		results[host] = append(results[host], portResult)
	}	

	return results
}

func sortProbesByRarity(probes []Probe) (probesSorted []Probe) {
	probesToSort := ProbesRarity(probes)
	sort.Stable(probesToSort)
	probesSorted = []Probe(probesToSort)
	return probesSorted
}

func (ps ProbesRarity) Len() int {
	return len(ps)
}

func (ps ProbesRarity) Swap(i, j int) {
	ps[i], ps[j] = ps[j], ps[i]
}

func (ps ProbesRarity) Less(i, j int) bool {
	return ps[i].Rarity < ps[j].Rarity
}
