package main

import (
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	udpConn *net.UDPConn
	handle  *pcap.Handle
	done    chan bool
)

func init() {
	log.Println("Executing...")
}

func main() {
	done = make(chan bool) // exist for supporting runing in background

	//open eth interface and get the handle
	var err error
	handle, err = pcap.OpenLive(GConfig.InterfaceName, 1024, false, -1*time.Second)
	defer handle.Close()
	if err != nil {
		log.Println(err)
		os.Exit(0)
	}
	if handle == nil {
		log.Println("null handle")
		os.Exit(1)
	}

	//set filter
	var filter string = "ether proto 0x888e || udp port 61440"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	startRequest()

	packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	go sniff(packetSrc)

	// keep alive
	serverIPStr := string(GConfig.ServerIP[:])
	udpServerAddr, err := net.ResolveUDPAddr("udp4", serverIPStr+":61440")
	if err != nil {
		log.Println(err)
	}
	udpConn, err = net.DialUDP("udp4", nil, udpServerAddr)
	if err != nil {
		log.Println(err)
	}
	defer udpConn.Close()
	go recvPing()

	<-done // Block forever
}
