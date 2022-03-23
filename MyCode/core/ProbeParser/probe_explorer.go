/*
	Here I will use the vscan database to scan particular ip:ports and try to figure out what is the
	service running in the backgroud.

	the algorithm is very simple -
	* first of all just sorting the probes from rare to less rare
	* then run all the probes agains every port that should be scanned.
	* if service is recognized (for example SMB, HTTP and more) - finish the probe checks.
	* I will not try to get http headers and titles, as it's will be part of the modules section.
*/