package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	// The same default as tcpdump.
	defaultSnapLen = 262144

	NULL = iota
	SYN
)

var (
	tcpHandshakes  = make(map[string]int)
	goodHandshakes = make(map[string]int)
	badHandshakes  = make(map[string]int)
)

func main() {
	displayGood := flag.Bool("g", false, "display good tcp handshakes")
	list := flag.Bool("list", false, "list capture devices")
	pcapFile := flag.String("pcap", "", "pcap file to analyze")
	pcapIface := flag.String("iface", "", "interface to listen on")
	pcapPort := flag.String("port", "", "port to use in capture filter")
	flag.Parse()

	if *list {
		// Find all devices
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}
		// Print device information
		fmt.Println("Devices found:")
		for _, device := range devices {
			fmt.Println("\nName: ", device.Name)
			fmt.Println("Description: ", device.Description)
			fmt.Println("Devices addresses: ", device.Description)
			for _, address := range device.Addresses {
				fmt.Println("- IP address: ", address.IP)
				fmt.Println("- Subnet mask: ", address.Netmask)
			}
		}
		return
	}

	//var handle *pcap.Handle
	var packets chan gopacket.Packet

	if *pcapFile != "" {
		if !checkFileExists(*pcapFile) {
			fmt.Println("no such file")
			os.Exit(1)
		}
		handle, err := pcap.OpenOffline(*pcapFile)
		if err != nil {
			panic(err)
		}
		defer handle.Close()
		packets = gopacket.NewPacketSource(
			handle,
			handle.LinkType()).Packets()
	} else {
		if *pcapIface == "" {
			fmt.Println("specify a pcap file or interface")
			os.Exit(1)
		}
		handle, err := pcap.OpenLive(
			*pcapIface,
			defaultSnapLen,
			true,
			pcap.BlockForever)
		if err != nil {
			panic(err)
		}
		defer handle.Close()

		if *pcapPort != "" {
			if err := handle.SetBPFFilter("port " + *pcapPort); err != nil {
				panic(err)
			}
		}
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGUSR1)

		go func() {
			for {
				<-sigs
				printSummary(*displayGood)
			}
		}()

		packets = gopacket.NewPacketSource(
			handle,
			layers.LinkTypeEthernet).Packets()
	}

	for pkt := range packets {
		analyzePacket(pkt)
	}

	printSummary(*displayGood)

}

func analyzePacket(pkt gopacket.Packet) {

	// log.Println("analyze", pkt)

	networkLayer := pkt.NetworkLayer()
	if networkLayer == nil {
		return
	}
	transportLayer := pkt.TransportLayer()
	if transportLayer == nil {
		return
	}
	srcHost := networkLayer.NetworkFlow().Src().String()
	srcPort := transportLayer.TransportFlow().Src().String()
	ipAndPort := net.JoinHostPort(srcHost, srcPort)

	// fmt.Println("from: ", srcHost, srcPort)

	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.SYN && !tcp.ACK {
			tcpHandshakes[ipAndPort] = SYN
			return
		}
		if tcp.ACK && tcpHandshakes[ipAndPort] == SYN {
			if tcp.FIN {
				tcpHandshakes[ipAndPort] = NULL
				badHandshakes[srcHost] += 1
			} else {
				tcpHandshakes[ipAndPort] = NULL
				goodHandshakes[srcHost] += 1
			}
		}
	}
}

func printSummary(displayGood bool) {
	var hosts []string
	for host, _ := range badHandshakes {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	fmt.Println("# bad")
	for _, host := range hosts {
		fmt.Printf("%v\t%v\n", host, badHandshakes[host])
	}
	if displayGood {
		fmt.Println()
		fmt.Println("# good")
		for host, count := range goodHandshakes {
			fmt.Printf("%v\t%v\n", host, count)
		}
	}
}

func checkFileExists(filePath string) bool {
	_, error := os.Stat(filePath)
	return !errors.Is(error, os.ErrNotExist)
}
