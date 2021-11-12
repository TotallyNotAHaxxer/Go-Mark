package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/kelvin-mai/go-port-scanner/port"
)

var (
	flagTarget = flag.String("t", "", `Target host(s). Provide a single IP: "1.2.3.4", a CIDR block "1.2.3.0/24", an IP range: "1.2.3-7.4-12", an IP with a wildcard: "1.2.3.*", or a list with any combination: "1.2.3.4, 1.2.3.0/24, ..."`)
	flagPort   = flag.Int("sp", 1, `Target Start port | Provide a port to start from EX -> 1`)
	flagPortn  = flag.Int("ep", 8090, `Target End Port   | Provide a port to stop ascanning at ex -> 8090`)
)

func main() {
	flag.Parse()
	t := time.Now()
	port.GetOpenPorts(*flagTarget, port.PortRange{Start: *flagPort, End: *flagPortn})
	fmt.Println("\033[31m\n[*] Script ended at -> ", time.Since(t))
}
