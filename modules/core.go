package modules

import (
	"GoScan/modules/data"
	"GoScan/modules/smb"
	"GoScan/core/ProbeParser/Types"
)

var PortModules map[int][]func(*Types.Result) = data.PortModules

func init() {

	// it's nessesary because else the code will not compile. so when creating a module you should 
	// manually add it here :(
	smb.Load()	
}