package modules

import (
	"GoScan/modules/data"
	"GoScan/modules/smb"
	"GoScan/core/ProbeParser/Types"
)

var PortModules map[int][]func(*Types.Result) = data.PortModules

func init() {
	smb.Load()	
}