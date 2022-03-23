package ProbeParser

import (
	"regexp"
)

// Documentation about the structure of the nmap-service-probes file is here
// https://nmap.org/book/vscan-fileformat.html

// parsed probe struct from the nmap-service-probes file
type Probe struct {
	Name     string
	Data     string
	Protocol string

	Ports    string
	SSLPorts string

	TotalWaitMS  int
	TCPWrappedMS int

	// rarity is important as in my code I will ignore the probe ports and run
	// the probe explore on every port. so I will go from high to low rarity
	Rarity int

	Fallback string

	Matchs *[]Match
}

// nmap-service-probes probe match info
type Match struct {
	IsSoft bool

	Service     string
	Pattern     string
	VersionInfo string

	PatternCompiled *regexp.Regexp
}

// nmap directive struct.
type Directive struct {
	DirectiveName string
	Flag          string
	Delimiter     string
	DirectiveStr  string
}

type VScan struct {
	Exclude string

	Probes []Probe

	ProbesMapKName map[string]Probe
}
