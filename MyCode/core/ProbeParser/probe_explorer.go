package ProbeParser

/*
	Here I will use the vscan database to scan particular ip:ports and try to figure out what is the
	service running in the backgroud.

	the algorithm is very simple -
	* first of all just sorting the probes from rare to less rare
	* then run all the probes agains every port that should be scanned.
	* if service is recognized (for example SMB, HTTP and more) - finish the probe checks.
	* I will not try to get http headers and titles, as it's will be part of the modules section.
*/


func (v *VScan) ScanTarget(host string, ports int[]) (Result, error) {
	var target Target
	
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
		result, err := v.scanWithProbes(target, &probesUsed)	
	}
	

	return result, err
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
