package main

import (
	"fmt"
	"net"
	"os"
	"strings"
)

func checkErr(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
}

func main() {
	addrs, err := net.InterfaceAddrs()
	checkErr(err)
	var currentIP, currentNetworkHardwareName string
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				fmt.Println("Using Current IP -> ", ipnet.IP.String())
				currentIP = ipnet.IP.String()
			}
		}
	}
	interfaces, _ := net.Interfaces()
	for _, interf := range interfaces {
		if addrs, err := interf.Addrs(); err == nil {
			for index, addr := range addrs {
				fmt.Println("[", index, "]", interf.Name, ">", addr)
				if strings.Contains(addr.String(), currentIP) {
					fmt.Println("[?] Used Name ->  ", interf.Name)
					currentNetworkHardwareName = interf.Name
				}
			}
		}
	}
	netInterface, err := net.InterfaceByName(currentNetworkHardwareName)
	if err != nil {
		fmt.Println(err)
	}
	netname := netInterface.Name
	madd := netInterface.HardwareAddr
	fmt.Println("[?] Hardware name   ->  ", netname)
	fmt.Println("[?] MAC address     ->  ", madd)
	hwAddr, err := net.ParseMAC(madd.String())
	checkErr(err)
	fmt.Printf("[?] Hardware Address ->  %s \n", hwAddr.String())

}
