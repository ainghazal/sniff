package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
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
	pcapFile := flag.String("pcap", "", "pcap file to analyze")
	flag.Parse()

	if !checkFileExists(*pcapFile) {
		fmt.Println("no such file")
		os.Exit(1)
	}

	handle, err := pcap.OpenOffline(*pcapFile)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	packets := gopacket.NewPacketSource(
		handle, handle.LinkType()).Packets()
	for pkt := range packets {
		analyzePacket(pkt)
	}
	printSummary(*displayGood)
}

func analyzePacket(pkt gopacket.Packet) {
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
