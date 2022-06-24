package Types

import (
	"sort"
	"reflect"
	"fmt"
	"unicode"
	"regexp"
	"strings"
	"strconv"
	"golang.org/x/exp/slices"
	"encoding/json"
)


func isHexCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	return matchRe.Match(b)
}

func isOctalCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[0-7]{1,3}`)
	return matchRe.Match(b)
}

func isStructCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[aftnrv]`)
	return matchRe.Match(b)
}

func isReChar(n int64) bool {
	reChars := `.*?+{}()^$|\`
	for _, char := range reChars {
		if n == int64(char) {
			return true
		}
	}
	return false
}

func isOtherEscapeCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[^\\]`)
	return matchRe.Match(b)
}

func DecodeData(s string) ([]byte, error) {
	sByteOrigin := []byte(s)
	matchRe := regexp.MustCompile(`\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|[aftnrv])`)
	sByteDec := matchRe.ReplaceAllFunc(sByteOrigin, func(match []byte) (v []byte) {
		var replace []byte
		if isHexCode(match) {
			hexNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(hexNum), 16, 32)
			replace = []byte{uint8(byteNum)}
		}
		if isStructCode(match) {
			structCodeMap := map[int][]byte{
				97:  []byte{0x07}, // \a
				102: []byte{0x0c}, // \f
				116: []byte{0x09}, // \t
				110: []byte{0x0a}, // \n
				114: []byte{0x0d}, // \r
				118: []byte{0x0b}, // \v
			}
			replace = structCodeMap[int(match[1])]
		}
		if isOctalCode(match) {
			octalNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(octalNum), 8, 32)
			replace = []byte{uint8(byteNum)}
		}
		return replace
	})

	matchRe2 := regexp.MustCompile(`\\([^\\])`)
	sByteDec2 := matchRe2.ReplaceAllFunc(sByteDec, func(match []byte) (v []byte) {
		var replace []byte
		if isOtherEscapeCode(match) {
			replace = match
		} else {
			replace = match
		}
		return replace
	})
	return sByteDec2, nil
}


func DecodePattern(s string) ([]byte, error) {
	sByteOrigin := []byte(s)
	matchRe := regexp.MustCompile(`\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|[aftnrv])`)
	sByteDec := matchRe.ReplaceAllFunc(sByteOrigin, func(match []byte) (v []byte) {
		var replace []byte
		if isHexCode(match) {
			hexNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(hexNum), 16, 32)
			if isReChar(byteNum) {
				replace = []byte{'\\', uint8(byteNum)}
			} else {
				replace = []byte{uint8(byteNum)}
			}
		}
		if isStructCode(match) {
			structCodeMap := map[int][]byte{
				97:  []byte{0x07}, // \a
				102: []byte{0x0c}, // \f
				116: []byte{0x09}, // \t
				110: []byte{0x0a}, // \n
				114: []byte{0x0d}, // \r
				118: []byte{0x0b}, // \v
			}
			replace = structCodeMap[int(match[1])]
		}
		if isOctalCode(match) {
			octalNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(octalNum), 8, 32)
			replace = []byte{uint8(byteNum)}
		}
		return replace
	})

	matchRe2 := regexp.MustCompile(`\\([^\\])`)
	sByteDec2 := matchRe2.ReplaceAllFunc(sByteDec, func(match []byte) (v []byte) {
		var replace []byte
		if isOtherEscapeCode(match) {
			replace = match
		} else {
			replace = match
		}
		return replace
	})
	return sByteDec2, nil
}

func (t *Target) GetAddress() string {
	return t.IP + ":" + strconv.Itoa(t.Port)
}

func (m *Match) MatchPattern(response []byte) (matched bool) {
	responseStr := string([]rune(string(response)))
	foundItems := m.PatternCompiled.FindStringSubmatch(responseStr)
	if len(foundItems) > 0 {
		matched = true
		return
	}
	return false
}

func (m *Match) ParseVersionInfo(response []byte) Extras {
	var extras = Extras{}

	responseStr := string([]rune(string(response)))

	foundItems := m.PatternCompiled.FindStringSubmatch(responseStr)

	versionInfo := m.VersionInfo
	foundItems = foundItems[1:]
	for index, value := range foundItems {
		dollarName := "$" + strconv.Itoa(index+1)
		versionInfo = strings.Replace(versionInfo, dollarName, value, -1)
	}

	// do the same for P() function of nmap-probs
	for index, value := range foundItems {

		value = strings.TrimFunc(value, func(r rune) bool {
        	return !unicode.IsGraphic(r)
    	})

		dollarName := "$P(" + strconv.Itoa(index+1) + ")"
		versionInfo = strings.Replace(versionInfo, dollarName, value, -1)
	}


	v := versionInfo
	if strings.Contains(v, " p/") {
		regex := regexp.MustCompile(`p/([^/]*)/`)
		vendorProductName := regex.FindStringSubmatch(v)
		extras.VendorProduct = vendorProductName[1]
	}
	if strings.Contains(v, " p|") {
		regex := regexp.MustCompile(`p|([^|]*)|`)
		vendorProductName := regex.FindStringSubmatch(v)
		extras.VendorProduct = vendorProductName[1]
	}
	if strings.Contains(v, " v/") {
		regex := regexp.MustCompile(`v/([^/]*)/`)
		version := regex.FindStringSubmatch(v)
		extras.Version = version[1]
	}
	if strings.Contains(v, " v|") {
		regex := regexp.MustCompile(`v|([^|]*)|`)
		version := regex.FindStringSubmatch(v)
		extras.Version = version[1]
	}
	if strings.Contains(v, " i/") {
		regex := regexp.MustCompile(`i/([^/]*)/`)
		info := regex.FindStringSubmatch(v)
		extras.Info = info[1]
	}
	if strings.Contains(v, " i|") {
		regex := regexp.MustCompile(`i|([^|]*)|`)
		info := regex.FindStringSubmatch(v)
		extras.Info = info[1]
	}
	if strings.Contains(v, " h/") {
		regex := regexp.MustCompile(`h/([^/]*)/`)
		hostname := regex.FindStringSubmatch(v)
		extras.Hostname = hostname[1]
	}
	if strings.Contains(v, " h|") {
		regex := regexp.MustCompile(`h|([^|]*)|`)
		hostname := regex.FindStringSubmatch(v)
		extras.Hostname = hostname[1]
	}
	if strings.Contains(v, " o/") {
		regex := regexp.MustCompile(`o/([^/]*)/`)
		operatingSystem := regex.FindStringSubmatch(v)
		extras.OperatingSystem = operatingSystem[1]
	}
	if strings.Contains(v, " o|") {
		regex := regexp.MustCompile(`o|([^|]*)|`)
		operatingSystem := regex.FindStringSubmatch(v)
		extras.OperatingSystem = operatingSystem[1]
	}
	if strings.Contains(v, " d/") {
		regex := regexp.MustCompile(`d/([^/]*)/`)
		deviceType := regex.FindStringSubmatch(v)
		extras.DeviceType = deviceType[1]
	}
	if strings.Contains(v, " d|") {
		regex := regexp.MustCompile(`d|([^|]*)|`)
		deviceType := regex.FindStringSubmatch(v)
		extras.DeviceType = deviceType[1]
	}
	if strings.Contains(v, " cpe:/") {
		regex := regexp.MustCompile(`cpe:/([^/]*)/`)
		cpeName := regex.FindStringSubmatch(v)
		if len(cpeName) > 1 {
			extras.CPE = cpeName[1]
		} else {
			extras.CPE = cpeName[0]
		}
	}
	if strings.Contains(v, " cpe:|") {
		regex := regexp.MustCompile(`cpe:|([^|]*)|`)
		cpeName := regex.FindStringSubmatch(v)
		if len(cpeName) > 1 {
			extras.CPE = cpeName[1]
		} else {
			extras.CPE = cpeName[0]
		}
	}
	return extras
}

func SortProbesByRarity(probes []Probe) (probesSorted []Probe) {
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

func (s Service) String() string {
	output, _ := json.MarshalIndent(s, "", "\t")
	return string(output)
}

// converts a struct (passed as interface) to list of string values 
func GetValues(s interface{}, includeFields []string, excludeFields []string, params ...[]string) []string {
	
	var values []string
	if len(params) != 0 {
		values = params[0]
	}

	// get the type of the interface 
    reflectType := reflect.TypeOf(s).Elem()

    // get the object of the interface
    reflectValue := reflect.ValueOf(s).Elem()

    for i := 0; i < reflectType.NumField(); i++ {
    	typeName := reflectType.Field(i).Name
        value := reflectValue.Field(i).Interface()

        if reflectValue.Field(i).Kind() == reflect.Struct {
            values = GetValues(reflectValue.Field(i).Addr().Interface(), includeFields, excludeFields, values)
        } else {
        	
	        // check if includeField contains just one string - "" empty string because of "split" in main
	        if len(includeFields) == 1 {
	        	if slices.Contains(excludeFields, typeName) {
		    		continue
		    	}	
	        } else {
	        	if !slices.Contains(includeFields, typeName) {
	        		continue
	        	}
	        }
	        
        	values = append(values, fmt.Sprintf("\"%v\"", strings.Replace(fmt.Sprintf("%v", value), "\"", "\"\"", -1)))
        }
    }

   	return values
}

// converts struct's (passed as interface) key name to list of strings
func GetHeaders(s interface{}, includeFields []string, excludeFields []string, params ...[]string) []string {
	var headers []string
	if len(params) != 0 {
		headers = params[0]
	}

	// get the type of the interface 
    reflectType := reflect.TypeOf(s).Elem()

    // get the object of the interface
    reflectValue := reflect.ValueOf(s).Elem()

    for i := 0; i < reflectType.NumField(); i++ {
        typeName := reflectType.Field(i).Name

        if reflectValue.Field(i).Kind() == reflect.Struct {
            headers = GetHeaders(reflectValue.Field(i).Addr().Interface(), includeFields, excludeFields, headers)
        } else {

	        // check if includeField contains just one string - "" empty string because of "split" in main
	        if len(includeFields) == 1 {
	        	if slices.Contains(excludeFields, typeName) {
		    		continue
		    	}	
	        } else {
	        	if !slices.Contains(includeFields, typeName) {
	        		continue
	        	}
	        }
	        
        	headers = append(headers, typeName)	
        }
        
    }

   	return headers
}

