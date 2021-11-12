go get github.com/briandowns/spinner
go get github.com/google/gopacket
go get github.com/google/gopacket/layers
go get github.com/google/gopacket/pcap
go get github.com/logrusorgru/aurora
go get github.com/shirou/gopsutil/cpu
go get github.com/shirou/gopsutil/disk
go get github.com/shirou/gopsutil/host 
go get github.com/shirou/gopsutil/mem
cd modules ; cd core ; nasm -f elf32 -o core.o core.asm ; ld -m elf_i386 -o core core.o ; ./core
