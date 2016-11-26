package main

import (
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	udpConn *net.UDPConn
	handle  *pcap.Handle
	done    chan bool
)

func init() {
	log.Println(AppName, ": go version DrCom client by artificerpi")
	log.Println("Project url:", Copyright)
	log.Println("Executing...")
}

// sniff EAP packets and send response packets
func sniff(packetSrc *gopacket.PacketSource) {
	var ethLayer layers.Ethernet // structures can be reused
	var eapLayer layers.EAP
	var eapolLayer layers.EAPOL
	var ipLayer layers.IPv4
	var udpLayer layers.UDP
	for packet := range packetSrc.Packets() {
		parser := gopacket.NewDecodingLayerParser( // just parse needed layer
			layers.LayerTypeEthernet,
			&ethLayer,   // essential
			&eapLayer,   // eap packet needed
			&eapolLayer, // eap packet needed
			&ipLayer,    // udp packet needed
			&udpLayer,   // udp packet needed
		)
		foundLayerTypes := []gopacket.LayerType{}

		// ignore error of decoding drcom packet (payload bytes of udp)
		_ = parser.DecodeLayers(packet.Data(), &foundLayerTypes)

		for _, layerType := range foundLayerTypes {
			switch layerType {
			case layers.LayerTypeUDP:
				sniffDRCOM(udpLayer.Payload) // this line of code used more often
			case layers.LayerTypeEAP:
				sniffEAP(eapLayer)
			}
		}
	}

	done <- true
}

func main() {
	done = make(chan bool) // exist for supporting runing in background

	//open eth interface and get the handle
	var err error
	handle, err = pcap.OpenLive(GConfig.InterfaceName, 1024, false, -1*time.Second)
	//	handle, err = pcap.OpenOffline("fsnet1.pcapng")
	defer handle.Close()
	if err != nil {
		log.Println(err)
		os.Exit(0)
	}
	if handle == nil {
		log.Println("null handle")
		os.Exit(1)
	}

	//set filter, filter 802.1X and incoming drcom message
	var filter string = "ether proto 0x888e || udp src port 61440"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	startRequest()

	packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	go sniff(packetSrc)

	// dial udp connection
	serverIPStr := GConfig.ServerIP.String()
	udpNet := "udp4"
	udpServerAddr, err := net.ResolveUDPAddr(udpNet, serverIPStr+":61440")
	if err != nil {
		log.Println(err)
	}
	udpConn, err = net.DialUDP(udpNet, nil, udpServerAddr)
	if err != nil {
		log.Println(err)
	}
	defer udpConn.Close()

	<-done // Block forever
}
