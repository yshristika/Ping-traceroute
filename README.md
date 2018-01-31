# Repos
This ping and traceroute work like real ones. That is, the ICMP packets from the ping and traceroute are acceptable by actual routers. This has been done by using raw sockets.
## Ping

	•	-c count Stop after sending (and receiving) count ECHO_RESPONSE packets. If this option is not specified, ping will operate until interrupted. 
	•	-i wait Wait wait seconds between sending each packet. The default is to wait for one second between each packet. 
	•	-s packetsize Specify the number of data bytes to be sent. The default is 56, which translates into 64 ICMP data bytes when combined with the 8 bytes of ICMP header data. 
	•	-t timeout Specify a timeout, in seconds, before ping exits regardless of how many packets have been received. 
## Traceroute
	•	-n Print hop addresses numerically rather than symbolically and numerically. 
	•	-q nqueries Set the number of probes per ``ttl'' to nqueries. 
	•	-S Print a summary of how many probes were not answered for each hop.
