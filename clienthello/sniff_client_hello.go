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
	"strconv"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	dissector "github.com/ainghazal/tls-dissector"
)

var (
	magic        = []byte{0x16, 0x03, 0x01}
	clientHellos int
	doText       bool
)

// The same default as tcpdump.
const defaultSnapLen = 262144

func main() {
	list := flag.Bool("list", false, "list capture devices")
	pcapFile := flag.String("pcap", "", "pcap file to analyze")
	pcapIface := flag.String("iface", "", "interface to listen on")
	pcapPort := flag.String("port", "", "port to use in capture filter")
	text := flag.Bool("text", false, "text output for the TLS record")
	flag.Parse()

	doText = *text

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

		if bytes.Contains(payload, magic) {
			for i, _ := range payload {
				if bytes.Equal(magic, payload[i:i+3]) {
					// can verify that at a fixed offset (-20?)
					// should find a ~0x20 byte (opcode[P_CONTROL_V1]/keyid=0)
					// -- this is likely to be true for all the first connections.
					rawHello := payload[i:]
					fmt.Println(hex.Dump(rawHello))
					fmt.Printf("\nraw:\n\n%s\n\n", hex.EncodeToString(rawHello))
					if doText {
						parseTLSRecord(rawHello)
					}
					clientHellos += 1
					return
				}
			}
		}
	}
}

func parseTLSRecord(b []byte) {
	ch := &dissector.ClientHelloMsg{}
	err := ch.Decode(b[5:])
	if err != nil {
		log.Println("error:", err)
	}
	fmt.Println("Client Hello")
	fmt.Println("  Version:      ", parseVersion(ch.Version))
	fmt.Println("  Random:       ", parseRandom(ch.Random))
	fmt.Println("  SessionID:    ", parseSessionID(ch.SessionID))
	fmt.Println("  Cipher Suites: ", parseCiphersuites(ch.CipherSuites))
	for _, cs := range ch.CipherSuites {
		fmt.Printf("\t\t\t%s (%x)\n", getCiphersuiteName(cs), cs)
	}
	fmt.Println("  Compression:  ", parseCompression(ch.CompressionMethods))
	fmt.Println("  Extensions:")
	for _, ext := range ch.Extensions {
		fmt.Printf("\t\t\t%v\n", ext)
	}
}

func parseVersion(value dissector.Version) string {
	switch value {
	case 0x303:
		return "TLS 1.2"
	case 0x304:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}

func parseRandom(value dissector.Random) string {
	time := strconv.Itoa(int(value.Time))
	random := hex.EncodeToString(value.Opaque[:])
	return fmt.Sprintf("%s:%s", time, random)
}

func parseSessionID(value []byte) string {
	return hex.EncodeToString(value)
}

func parseCiphersuites(value []uint16) string {
	return fmt.Sprintf("(%d suites)", len(value))
}

func parseCompression(value []uint8) string {
	if len(value) == 1 && value[0] == 0 {
		return "null"
	}
	// is there really someone out there setting compression nowadays??
	m := ""
	for _, cm := range value {
		m = m + strconv.Itoa(int(cm)) + ","
	}
	return m
}

func getCiphersuiteName(cs uint16) string {
	name := dissector.Suites[cs]
	if name == "" {
		name = "???"
	}
	return name
}

func printSummary() {
	fmt.Printf("captured %d clientHellos\n", clientHellos)
}

func checkFileExists(filePath string) bool {
	_, error := os.Stat(filePath)
	return !errors.Is(error, os.ErrNotExist)
}
