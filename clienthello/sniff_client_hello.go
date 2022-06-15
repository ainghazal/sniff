package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	magic        = []byte{0x16, 0x03, 0x01}
	offsetMin    = 14
	offsetMax    = 17
	clientHellos int
)

// The same default as tcpdump.
const defaultSnapLen = 262144

func main() {
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
				printSummary()
			}
		}()

		packets = gopacket.NewPacketSource(
			handle,
			layers.LinkTypeEthernet).Packets()
	}

	for packet := range packets {
		analyzePacket(packet)
	}

	printSummary()

}

func analyzePacket(packet gopacket.Packet) {

	if app := packet.ApplicationLayer(); app != nil {
		payload := app.Payload()
		if len(payload) < offsetMax {
			return
		}

		if bytes.Equal(payload[offsetMin:offsetMax], magic) {
			fmt.Println(hex.Dump(payload[offsetMin:]))
			clientHellos += 1
		}
	}
}

func printSummary() {
	fmt.Printf("captured %d clientHellos\n", clientHellos)
}

func checkFileExists(filePath string) bool {
	_, error := os.Stat(filePath)
	return !errors.Is(error, os.ErrNotExist)
}
