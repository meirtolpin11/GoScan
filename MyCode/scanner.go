package main

import (
	"MyCode/core/ProbeParser"
)

func main() {
	vscan := ProbeParser.VScan{}
	vscan.ParseServiceProbes()

}
