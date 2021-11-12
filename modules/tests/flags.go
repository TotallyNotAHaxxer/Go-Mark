// sample code from arp fox //never knew how to parse flags so easily and now i do thanks XD

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
)

var (
	flagInterface      = flag.String("i", defaultInterface(), `Network interface.`)
	flagTarget         = flag.String("t", "", `Target host(s). Provide a single IP: "1.2.3.4", a CIDR block "1.2.3.0/24", an IP range: "1.2.3-7.4-12", an IP with a wildcard: "1.2.3.*", or a list with any combination: "1.2.3.4, 1.2.3.0/24, ..."`)
	flagListInterfaces = flag.Bool("l", false, `List available interfaces and exit.`)
	flagWaitInterval   = flag.Float64("w", 2, `Wait <w> seconds between every broadcast, <w> must be a value greater than 0.1.`)
	flagHelp           = flag.Bool("h", false, `Print usage instructions and exit.`)
	flagVersion        = flag.Bool("v", false, `Print software version and exit.`)
)

func main() {
	flag.Parse()

	if *flagVersion {
		fmt.Printf("%v\n", version)
		os.Exit(0)
	}

	if *flagHelp {
		fmt.Println("arpfox sends specially crafted ARP packets to a given host on a LAN in order")
		fmt.Println("to poison its ARP cache table.")
		fmt.Println("")
		fmt.Println("Kernel IP forwarding must be turned on ahead of time.")
		fmt.Println("")
		fmt.Println("Usage: ")
		fmt.Println("arpfox [-i interface] -t target host")
		fmt.Println("")
		flag.PrintDefaults()
		os.Exit(0)
	}

	if *flagListInterfaces {
		ifaces, err := net.Interfaces()
		if err != nil {
			log.Fatal("Failed to retrieve interfaces: ", err)
		}
		for _, iface := range ifaces {
			if iface.HardwareAddr == nil {
				continue
			}
			fmt.Printf("%s \"%s\"\n", iface.HardwareAddr, iface.Name)
		}
		os.Exit(0)
	}

	if *flagWaitInterval < 0.1 {
		*flagWaitInterval = 0.1
	}

	if *flagTarget == "" {
		log.Fatal("Missing target (-t 192.168.1.7).")
	}

	iface, err := net.InterfaceByName(*flagInterface)
	if err != nil {
		log.Fatalf("Could not use interface %s: %v", *flagInterface, err)
	}
}
