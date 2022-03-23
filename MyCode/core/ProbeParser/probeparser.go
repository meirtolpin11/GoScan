package ProbeParser

import (
	_ "embed"
	"regexp"
	"strconv"
	"strings"
)

// based on https://github.com/RickGray/vscan-go

//go:embed nmap-service-probes
var nmap_service_probes string

func (v *VScan) ParseServiceProbes() {

	var excludePorts string
	var probes []Probe

	// first of all let's ignore all the comment lines
	var lines []string

	tmpLines := strings.Split(nmap_service_probes, "\n")
	for _, line := range tmpLines {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			// ignore blank or comment lines
			continue
		}

		lines = append(lines, line)
	}

	if len(lines) == 0 {
		panic("Failed loading nmap service probes, 0 lines found")
	}

	firstLine := lines[0]

	if strings.HasPrefix(firstLine, "Exclude ") {
		excludePorts = firstLine[len("Exclude ")+1:]

		// removing the first line from the probes list
		lines = lines[1:]
	}

	cleanData := "\n" + strings.Join(lines, "\n")

	probesStr := strings.Split(cleanData, "\nProbe")

	// the first line is empty
	probesStr = probesStr[1:]

	v.Exclude = excludePorts
	for _, probeText := range probesStr {
		probe := Probe{}
		err := probe.ParseProbe(probeText)
		if err != nil {
			continue
		}

		probes = append(probes, probe)
	}
	v.Probes = probes
}

func (v *VScan) parseProbesToMapKName(probes []Probe) {
	var probesMap = map[string]Probe{}
	for _, probe := range v.Probes {
		probesMap[probe.Name] = probe
	}
	v.ProbesMapKName = probesMap
}

func (p *Probe) parseProbeInfo(probeStr string) {
	proto := probeStr[:4]
	other := probeStr[4:]

	if !(proto == "TCP " || proto == "UDP ") {
		panic("Probe <protocol>must be either TCP or UDP.")
	}
	if len(other) == 0 {
		panic("nmap-service-probes - bad probe name")
	}

	directive := p.getDirectiveSyntax(other)

	p.Name = directive.DirectiveName
	p.Data = strings.Split(directive.DirectiveStr, directive.Delimiter)[0]
	p.Protocol = strings.ToLower(strings.TrimSpace(proto))
}

func (p *Probe) getDirectiveSyntax(data string) (directive Directive) {
	directive = Directive{}

	blankIndex := strings.Index(data, " ")
	directiveName := data[:blankIndex]
	Flag := data[blankIndex+1 : blankIndex+2]
	delimiter := data[blankIndex+2 : blankIndex+3]
	directiveStr := data[blankIndex+3:]

	directive.DirectiveName = directiveName
	directive.Flag = Flag
	directive.Delimiter = delimiter
	directive.DirectiveStr = directiveStr

	return directive
}

func (p *Probe) ParseProbe(probeText string) error {

	var err error
	probeText = strings.TrimSpace(probeText)
	lines := strings.Split(probeText, "\n")

	probeStr := lines[0]

	p.parseProbeInfo(probeStr)

	var matchs []Match
	for _, line := range lines {
		if strings.HasPrefix(line, "match ") {
			match, err := p.getMatch(line)
			if err != nil {
				continue
			}
			matchs = append(matchs, match)
		} else if strings.HasPrefix(line, "softmatch ") {
			softMatch, err := p.getSoftMatch(line)
			if err != nil {
				continue
			}
			matchs = append(matchs, softMatch)
		} else if strings.HasPrefix(line, "ports ") {
			p.parsePorts(line)
		} else if strings.HasPrefix(line, "sslports ") {
			p.parseSSLPorts(line)
		} else if strings.HasPrefix(line, "totalwaitms ") {
			p.parseTotalWaitMS(line)
		} else if strings.HasPrefix(line, "totalwaitms ") {
			p.parseTotalWaitMS(line)
		} else if strings.HasPrefix(line, "tcpwrappedms ") {
			p.parseTCPWrappedMS(line)
		} else if strings.HasPrefix(line, "rarity ") {
			p.parseRarity(line)
		} else if strings.HasPrefix(line, "fallback ") {
			p.parseFallback(line)
		}
	}
	p.Matchs = &matchs
	return err
}

func (p *Probe) getMatch(data string) (match Match, err error) {
	match = Match{}

	matchText := data[len("match")+1:]
	directive := p.getDirectiveSyntax(matchText)

	textSplited := strings.Split(directive.DirectiveStr, directive.Delimiter)

	pattern, versionInfo := textSplited[0], strings.Join(textSplited[1:], "")

	patternUnescaped, _ := DecodePattern(pattern)
	patternUnescapedStr := string([]rune(string(patternUnescaped)))
	patternCompiled, ok := regexp.Compile(patternUnescapedStr)
	if ok != nil {
		return match, ok
	}

	match.Service = directive.DirectiveName
	match.Pattern = pattern
	match.PatternCompiled = patternCompiled
	match.VersionInfo = versionInfo

	return match, nil
}

func (p *Probe) getSoftMatch(data string) (softMatch Match, err error) {
	softMatch = Match{IsSoft: true}

	matchText := data[len("softmatch")+1:]
	directive := p.getDirectiveSyntax(matchText)

	textSplited := strings.Split(directive.DirectiveStr, directive.Delimiter)

	pattern, versionInfo := textSplited[0], strings.Join(textSplited[1:], "")
	patternUnescaped, _ := DecodePattern(pattern)
	patternUnescapedStr := string([]rune(string(patternUnescaped)))
	patternCompiled, ok := regexp.Compile(patternUnescapedStr)
	if ok != nil {
		return softMatch, ok
	}

	softMatch.Service = directive.DirectiveName
	softMatch.Pattern = pattern
	softMatch.PatternCompiled = patternCompiled
	softMatch.VersionInfo = versionInfo

	return softMatch, nil
}

func (p *Probe) parsePorts(data string) {
	p.Ports = data[len("ports")+1:]
}

func (p *Probe) parseSSLPorts(data string) {
	p.SSLPorts = data[len("sslports")+1:]
}

func (p *Probe) parseTotalWaitMS(data string) {
	p.TotalWaitMS, _ = strconv.Atoi(string(data[len("totalwaitms")+1:]))
}

func (p *Probe) parseTCPWrappedMS(data string) {
	p.TCPWrappedMS, _ = strconv.Atoi(string(data[len("tcpwrappedms")+1:]))
}

func (p *Probe) parseRarity(data string) {
	p.Rarity, _ = strconv.Atoi(string(data[len("rarity")+1:]))
}

func (p *Probe) parseFallback(data string) {
	p.Fallback = data[len("fallback")+1:]
}
