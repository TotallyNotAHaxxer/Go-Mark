# Go-Mark
```
 _______ __   _  _____   _____  _______ _______  ______
 |______ | \  | |     | |     | |______ |______ |_____/
 ______| |  \_| |_____| |_____| |       |______ |    \_
              
2021/11/11 18:11:06 [*] Root detected

```

Features
- Port scanner 
- root check 
- ARP scanner 
- Gather core 
- WHOAMI
- system stats 
- interfaces 
- grab your public and private IP

# commands 

```
╭──────────────────────────────────────────────────────────────────╮
│ HELP          | Will load this menu                              │
│ MODARP        | Will load the Address Resolution Module          │
│ IFLO          | Will get you're Interfaces and Addresses         │
│ NETIP         | Will Get you're private and Public IPA           │
│ CLEAR/CLS     | Clear the screen                                 │
│ EXIT          | will exit the program                            │
│ MODPORT       | will scan the given host specified with -t       │
│ COREUSE       | see the current CPU the tool or script is using  │
│ WHOAMI        | see who you are                                  │
│ STATS         | will gather ALL system stats within a few seconds│
╰──────────────────────────────────────────────────────────────────╯
```

# how to run port scanning modules 

sudo go run main.go -t 192.168.180.90 # replace the IP with your priavte ex 10.0.0.0.|10.0.0.1|

# libs 

```
	"github.com/briandowns/spinner" //go get github.com/go-ping/ping
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	. "github.com/logrusorgru/aurora"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
```

# install 


```
git clone https://github.com/ArkAngeL43/Go-Mark.git ; cd Go-Mark ; chmod +x ./insta.sh ; ./install.sh ; clear
```

