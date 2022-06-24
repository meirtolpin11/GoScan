package data

import (
	"GoScan/core/ProbeParser/Types"
)

var PortModules map[int][]func(*Types.Result) = make(map[int][]func(*Types.Result))
