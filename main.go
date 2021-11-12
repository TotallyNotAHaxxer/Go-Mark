// arp relay with the google documentation LOL

// trick discovered
// to start a new package just do shift + p and hit enter this will start the package as main, and write the function as a main to start with

package main // putting it all into one main file as adding onto easy make and call

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"image/color"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/briandowns/spinner" //go get github.com/go-ping/ping
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	. "github.com/logrusorgru/aurora"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
)

var (
	flagHelp    = flag.Bool("h", false, `Print usage instructions`)
	flagVersion = flag.Bool("v", false, `Print version`)
	flagTarget  = flag.String("t", "", `Target host(s). Provide a single IP: "1.2.3.4", a CIDR block "1.2.3.0/24", an IP range: "1.2.3-7.4-12", an IP with a wildcard: "1.2.3.*", or a list with any combination: "1.2.3.4, 1.2.3.0/24, ..."`)
	flagPort    = flag.Int("sp", 1, `Target Start port | Provide a port to start from EX -> 1`)
	flagPortn   = flag.Int("ep", 65535, `Target End Port   | Provide a port to stop ascanning at ex -> 8090`)
)

const (
	v = "1.0 BETA"
)

type info struct {
	Hostname string `bson:hostname`
}

//go code

type QRCode struct {
	Content         string
	VersionNumber   int
	ForegroundColor color.Color
	BackgroundColor color.Color
	DisableBorder   bool
}

//// stats

type SysInfo struct {
	Hostname string `bson:hostname`
	Platform string `bson:platform`
	CPU      string `bson:cpu`
	RAM      uint64 `bson:ram`
	Disk     uint64 `bson:disk`
}

func statsall() {
	fmt.Println("\033[34m[\033[35m*\033[34m] Gathering")
	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
	s.Start()
	time.Sleep(1 * time.Second)
	s.Stop()
	isRoot()
	checker2()
	fmt.Println("\033[34m[\033[35m*\033[34m]\tGathering network details")
	s.Stop()
	netcheck()
	localaddr()
	netip()
	fmt.Println("\033[34m[\033[35m*\033[34m]\tExtra information")
	fmt.Println("\n\n\033[34m[\033[35m*\033[34m] ----------------------------------- ")
	addrs, err := net.InterfaceAddrs()
	checkErr(err)
	var currentIP, currentNetworkHardwareName string
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				fmt.Println("\tUsing Current IP -> ", ipnet.IP.String())
				currentIP = ipnet.IP.String()
			}
		}
	}
	interfaces, _ := net.Interfaces()
	for _, interf := range interfaces {
		if addrs, err := interf.Addrs(); err == nil {
			for index, addr := range addrs {
				fmt.Println("\t[", index, "]", interf.Name, ">", addr)
				if strings.Contains(addr.String(), currentIP) {
					fmt.Println("\033[34m[\033[35m*\033[34m] Used Name ->  ", interf.Name)
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
	fmt.Println("\t\033[34m[\033[35m*\033[34m] Hardware name   ->  ", netname)
	fmt.Println("\t\033[34m[\033[35m*\033[34m] MAC address     ->  ", madd)
	hwAddr, err := net.ParseMAC(madd.String())
	checkErr(err)
	fmt.Printf("\t\033[34m[\033[35m*\033[34m] Hardware Address ->  %s \n", hwAddr.String())
	hostStat, _ := host.Info()
	cpuStat, _ := cpu.Info()
	vmStat, _ := mem.VirtualMemory()
	if runtime.GOOS == "windows" {
		diskStat, _ := disk.Usage("\\")
		info := new(SysInfo)
		info.Hostname = hostStat.Hostname
		info.Platform = hostStat.Platform
		info.CPU = cpuStat[0].ModelName
		info.RAM = vmStat.Total / 1024 / 1024
		info.Disk = diskStat.Total / 1024 / 1024
		fmt.Println("\t----------- CPU, HOST, PLAT, RAM, AND DISK -------------00000")
		fmt.Printf("\t\033[34m<\033[35mCPU\033[34m>\t%+v\n", info.CPU)
		fmt.Printf("\t\033[34m<\033[35mHOST\033[34m>\t%+v\n", info.Hostname)
		fmt.Printf("\t\033[34m<\033[35mPLAT\033[34m>\t%+v\n", info.Platform)
		fmt.Printf("\t\033[34m<\033[35mRAM\033[34m>\t%+v\n", info.RAM)
		fmt.Printf("\t\033[34m<\033[35mDISK\033[34m>\t%+v\n", info.Disk)
	} else {
		diskStat, _ := disk.Usage("/")
		info := new(SysInfo)
		info.Hostname = hostStat.Hostname
		info.Platform = hostStat.Platform
		info.CPU = cpuStat[0].ModelName
		info.RAM = vmStat.Total / 1024 / 1024
		info.Disk = diskStat.Total / 1024 / 1024
		fmt.Println("\t----------- CPU, HOST, PLAT, RAM, AND DISK -------------00000")
		fmt.Printf("\t\033[34m<\033[35mCPU\033[34m>\t%+v\n", info.CPU)
		fmt.Printf("\t\033[34m<\033[35mHOST\033[34m>\t%+v\n", info.Hostname)
		fmt.Printf("\t\033[34m<\033[35mPLAT\033[34m>\t%+v\n", info.Platform)
		fmt.Printf("\t\033[34m<\033[35mRAM\033[34m>\t%+v\n", info.RAM)
		fmt.Printf("\t\033[34m<\033[35mDISK\033[34m>\t%+v\n", info.Disk)
	} // If you're in Unix change this "\\" for "/"

}

/////////////////////////////////////////////////////// ROOT CHECKER AND USERNAME GREPPERS /////////////////////////////////

func isRoot() bool {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("[RootCheck] Unable to fetch user: %s", err)
	}
	return currentUser.Username == "root"
}

func checker1() {
	if getProcessOwner() == "root" {
		fmt.Println("\033[34m[\033[35m*\033[34m] Root detected...")
	} else {
		fmt.Println("\033[31m[*] Please try running this script as root, or in a root shell")
		os.Exit(1)
	}
}

func checker2() {
	cmd := exec.Command("id", "-u")
	output, err := cmd.Output()
	checkErr(err)
	i, err := strconv.Atoi(string(output[:len(output)-1]))
	checkErr(err)
	if i == 0 {
		log.Println("\033[34m[\033[35m*\033[34m] Root detected")
	} else {
		log.Fatal("This program must be run as root! (sudo)")
	}
}

func getProcessOwner() string {
	stdout, err := exec.Command("ps", "-o", "user=", "-p", strconv.Itoa(os.Getpid())).Output()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return string(stdout)
}

//////////////////////////////////////////////////////////////////////////////////

// flags
func flagedcheck() {
	flag.Parse()
	if *flagVersion {
		fmt.Printf("Current Version <?> %v\n", v)
		os.Exit(0)
	}
	if *flagHelp {
		fmt.Println(" Snoofer -> Options | ")
		fmt.Println(" Flags ARE FOR PORT SCANNING ONLY ")
		fmt.Println(">>>>>>>>> USAGE PORT >>>>>>>>>>")
		fmt.Println("-t <target> 		   | -t www.google.com ")
		fmt.Println("-sp <starting port> EX| -sp 1 ")
		fmt.Println("-ep <Ending Port    EX| -ep 6990")
		fmt.Println("------------------- FILE EXAMPLE ------------- ")
		fmt.Println("sudo go run main.go -t www.example.com -sp 100 -ep 900")
		flag.PrintDefaults()
		os.Exit(0)
	}
	if *flagTarget == "" {
		fmt.Println("\033[36m[-] Missing Target, Port scanning module closed and useless")
	}
}

///////////////////////////

//defualt interfaces based on OS

func defaultInterface() string {
	switch runtime.GOOS {
	case "freebsd", "linux":
		return "wlan0"
	case "windows":
		return "Ethernet"
	case "darwin":
		return "en0"
	}
	return "eth0"
}

func cl() {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("cls").Output()
		if err != nil {
			log.Fatal(err)
		}
		output := string(out[:])
		fmt.Println(output)
	} else {
		out, err := exec.Command("clear").Output()
		if err != nil {
			log.Fatal(err)
		}
		output := string(out[:])
		fmt.Println(output)
	}
}

func banner() {
	prg := "cat"
	prg1 := "txt/banner.txt"
	command := exec.Command(prg, prg1)
	out, err := command.Output()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Print(Magenta(string(out)))
}

/// generate QR code

//////////////////////// ERROR HANDELING, CON TESTS, AND SAFE RUNNING //////////////////////
func checkErr(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
}

func handel(c chan os.Signal) {
	signal.Notify(c, os.Interrupt)
	for s := <-c; ; s = <-c {
		switch s {
		case os.Interrupt:
			fmt.Println("\nDetected Interupt.....")
			os.Exit(1)
		case os.Kill:
			fmt.Println("\n\n\tKILL received")
			os.Exit(1)
		}
	}
}

func handelreturncon(c chan os.Signal) {
	signal.Notify(c, os.Interrupt)
	for s := <-c; ; s = <-c {
		switch s {
		case os.Interrupt:
			fmt.Println("\nDetected Interupt.....")
			os.Exit(1)
			consol()
		case os.Kill:
			fmt.Println("\n\n\tKILL received")
			os.Exit(1)
			consol()
		}
	}
}

func netcheck() bool {
	_, err := http.Get("https://www.google.com")
	if err != nil {
		fmt.Println("[!] Interface may be offline")
		os.Exit(1)
	} else {
		return false
	}
	return false
}

////////////////////////////////////////////////////////////////////////////////////////
// port scanner TCP WEBSITE OR HOST
func scanner() {
	flag.Parse()
	err := os.Chdir(filepath.Join("modules")) // adding cd command would bug out
	checkErr(err)
	prg := "go"
	prg2 := "run"
	prg1 := "main.go"
	prg4 := "-t"
	prg3 := *flagTarget
	prg5 := "-sp"
	prg6 := "1"
	prg7 := "-ep"
	prg8 := "65535"
	command := exec.Command(prg, prg2, prg1, prg4, prg3, prg5, prg6, prg7, prg8)
	out, err := command.Output()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Print(Magenta(string(out)))
	exit()
}

// gather of interfaces

func localaddr() {
	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
	s.Start()
	time.Sleep(2 * time.Second)
	s.Stop()
	ifaces, err := net.Interfaces()
	checkErr(err)
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		checkErr(err)
		for _, a := range addrs {
			log.Printf("\033[35m[\033[34mINTERFACE\033[35m] ->  %v %v\n", i.Name, a)
		}
	}
}

////////////

func scan(iface *net.Interface) error {
	go handelreturncon(make(chan os.Signal, 1))
	var addr *net.IPNet
	if addrs, err := iface.Addrs(); err != nil {
		return err
	} else {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					addr = &net.IPNet{
						IP:   ip4,
						Mask: ipnet.Mask[len(ipnet.Mask)-4:],
					}
					break
				}
			}
		}
	}
	if addr == nil {
		return errors.New("\033[34m[\033[35m?\033[34m] Unstable Network on card") // check networks interface
	} else if addr.IP[0] == 127 {
		return errors.New("\033[34m[\033[35m*\033[34m] Skipping LO...") //skip local host
	} else if addr.Mask[0] != 0xff || addr.Mask[1] != 0xff {
		return errors.New("\033[34m[\033[35m?\033[34m] Mask is to large....")
	}
	log.Printf("\033[34m[\033[35m*\033[34m] USING CURRENT NET RANGE -> %v FOR INTERFACES -> %v", addr, iface.Name)
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	checkErr(err)
	defer handle.Close()

	stop := make(chan struct{})
	go ARPR(handle, iface, stop)
	defer close(stop)
	for {

		if err := ARPW(handle, iface, addr); err != nil {
			log.Printf("[DATA]->[ERROR] An error has occured during the following write of packets-> %v: %v", iface.Name, err)
			return err
		}
		s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
		s.Start()
		time.Sleep(2 * time.Second)
		s.Stop()
	}
}

func ARPR(handle *pcap.Handle, iface *net.Interface, stop chan struct{}) {
	go handelreturncon(make(chan os.Signal, 1))
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply || bytes.Equal([]byte(iface.HardwareAddr), arp.SourceHwAddress) {

				continue
			}

			log.Printf("\033[34m[\033[35m+\033[34m] Address [%v] Has MAC ~> [%v]", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
		}
	}
}

func ARPW(handle *pcap.Handle, iface *net.Interface, addr *net.IPNet) error {
	go handelreturncon(make(chan os.Signal, 1))
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(addr.IP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	for _, ip := range ips(addr) {
		arp.DstProtAddress = []byte(ip)
		gopacket.SerializeLayers(buf, opts, &eth, &arp)
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

func ips(n *net.IPNet) (out []net.IP) {
	num := binary.BigEndian.Uint32([]byte(n.IP))
	mask := binary.BigEndian.Uint32([]byte(n.Mask))
	network := num & mask
	broadcast := network | ^mask
	for network++; network < broadcast; network++ {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], network)
		out = append(out, net.IP(buf[:]))
	}
	return
}

func arpmain() {
	fmt.Println("\033[34m[\033[35m+\033[34m] Module ARP Relay Loaded....")
	fmt.Println("\033[34m[\033[35m+\033[34m] Gathering Interfaces.....")
	localaddr()
	go handelreturncon(make(chan os.Signal, 1))
	var err error
	netcheck()
	ifaces, err := net.Interfaces()
	checkErr(err)
	var wg sync.WaitGroup
	for _, iface := range ifaces {
		wg.Add(1)
		go func(iface net.Interface) {
			defer wg.Done()
			if err := scan(&iface); err != nil {
				log.Printf("interface %v: %v", iface.Name, err)
			}
		}(iface)
		go handelreturncon(make(chan os.Signal, 1))
	}
	go handelreturncon(make(chan os.Signal, 1))
	wg.Wait()
}

func netip() {
	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
	s.Start()
	time.Sleep(2 * time.Second)
	s.Stop()
	hostStat, _ := host.Info()
	info := new(info)
	info.Hostname = hostStat.Hostname
	uli := "https://api.ipify.org?format=text"
	fmt.Print("\033[32m\n\t\tFetching Public IPA for -> ", info.Hostname, " ...\n")
	response, err := http.Get(uli)
	checkErr(err)
	defer response.Body.Close()
	ip, err := ioutil.ReadAll(response.Body)
	checkErr(err)
	fmt.Printf("\033[32m\t\t[PUBLIC]->[IPA-ADDR]      | %s\n", ip)
	addrs, err := net.InterfaceAddrs()
	checkErr(err)
	for i, addr := range addrs {
		fmt.Printf("\033[32m\t\t[PRIVATE]->[INTERFACE] #%d | %v\n", i, addr)
	}
	fmt.Println("[+] Getting Ranges......")
	ifaces, err := net.Interfaces()
	// handle function usage
	checkErr(err)
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		checkErr(err)
		for _, addr := range addrs {
			//var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				fmt.Println("\t\t", ip)
			case *net.IPAddr:
				ip = v.IP
				fmt.Println("\t\t", ip)
			}
		}
	}
}

// mind map
// if length is equal to 3 but is not equal to 2 1 or 4 then load arp module
// if length is equal to 2 but is not equal ro 1, 4, or 3 then load interface module

func exit() {
	os.Exit(0)
}

func consol() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\n\033[49m\033[34m[\033[35m*\033[34m]\033[31m Snoofer> ")
	//if text >= "LOADARP" {
	//	arpmain()
	//}
	for {
		text, _ := reader.ReadString('\n')
		// convert CRLF to LF
		text = strings.Replace(text, "\n", "", -1)
		if strings.Compare("STATS", text) == 0 {
			statsall()
		}
		if strings.Compare("NETIP", text) == 0 {
			netip()
			consol()
		}
		if strings.Compare("MODPORT", text) == 0 {
			scanner()
			consol()
		}
		if strings.Compare("MODARP", text) == 0 {
			arpmain()
			consol()
		}
		if strings.Compare("IFLO", text) == 0 {
			localaddr()
			consol()
		}
		if strings.Compare("MODULES", text) == 0 {
			file := "help.txt"
			filepath := "txt/help.txt"
			f, err := os.Open("txt/help.txt")
			if err != nil {
				log.Fatal(err)
				fmt.Println("Hm? An error has occured when opening -> ", file, "In path -> ", filepath)
			}
			defer f.Close()
			format := bufio.NewScanner(f)
			for format.Scan() {
				fmt.Println(Magenta(format.Text()))

			}
			if err := format.Err(); err != nil {
				log.Fatal(err)
				fmt.Println("[!] An error has occured when scanning file 0> ", file, "In path 0> ", filepath)
			}
			consol()
		}
		if strings.Compare("HELP", text) == 0 {
			file := "help.txt"
			filepath := "txt/help.txt"
			f, err := os.Open("txt/help.txt")
			if err != nil {
				log.Fatal(err)
				fmt.Println("Hm? An error has occured when opening -> ", file, "In path -> ", filepath)
			}
			defer f.Close()
			format := bufio.NewScanner(f)
			for format.Scan() {
				fmt.Println(Magenta(format.Text()))

			}
			if err := format.Err(); err != nil {
				log.Fatal(err)
				fmt.Println("[!] An error has occured when scanning file 0> ", file, "In path 0> ", filepath)
			}
			consol()
		}
		if strings.Compare("CLEAR", text) == 0 {
			cl()
			main()
		}
		if strings.Compare("CLS", text) == 0 {
			cl()
			main()
		}
		if strings.Compare("EXIT", text) == 0 {
			os.Exit(1)
		}
		if strings.Compare("COMMAND", text) == 0 {
			file := "help.txt"
			filepath := "txt/help.txt"
			f, err := os.Open("txt/help.txt")
			if err != nil {
				log.Fatal(err)
				fmt.Println("\n\t\033[31m[!] Hm? An error has occured when opening -> ", file, "In path -> ", filepath)
			}
			defer f.Close()
			format := bufio.NewScanner(f)
			for format.Scan() {
				fmt.Println(Magenta(format.Text()))

			}
			if err := format.Err(); err != nil {
				log.Fatal(err)
				fmt.Println("\n\t\033[31m[!] An error has occured when scanning file 0> ", file, "In path 0> ", filepath)
			}
			consol()
		}
		if strings.Compare("COMMANDS", text) == 0 {
			file := "help.txt"
			filepath := "txt/help.txt"
			f, err := os.Open("txt/help.txt")
			if err != nil {
				log.Fatal(err)
				fmt.Println("\n\t\033[31m[!] Hm? An error has occured when opening -> ", file, "In path -> ", filepath)
			}
			defer f.Close()
			format := bufio.NewScanner(f)
			for format.Scan() {
				fmt.Println(Magenta(format.Text()))

			}
			if err := format.Err(); err != nil {
				log.Fatal(err)
				fmt.Println("\n\t[!] An error has occured when scanning file 0> ", file, "In path 0> ", filepath)
			}
			consol()
		}
		if strings.Compare("WHOAMI", text) == 0 {
			name, err := os.Hostname()
			checkErr(err)
			fmt.Println("You are -> ", name)
		}
		if strings.Compare("COREUSE", text) == 0 {
			err := os.Chdir(filepath.Join("modules/core"))
			checkErr(err)
			prg := "./core"
			command := exec.Command(prg)
			out, err := command.Output()
			if err != nil {
				fmt.Println(err.Error())
				return
			}
			fmt.Print(Cyan(string(out)))
			exit()
		}
		if strings.Compare("VERSION", text) == 0 {
			fmt.Println("\n[*] Current Version -> ", v)
			consol()
		} else {
			fmt.Println("\033[31m")
			consol()
		}

	}
}

func main() {
	hex := "\x1b[H\x1b[2J\x1b[3J"
	fmt.Println(hex)
	banner()
	t := time.Now()
	checker2()
	fmt.Println("\n\033[41m\033[35mSnoofer started at ", t)
	fmt.Printf("\n\033[49m\033[34m[\033[35m?\033[34m]\033[31m Is user root -> %v", isRoot())
	flagedcheck()
	consol()
}
