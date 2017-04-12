package main

// sniff packets and send response packets
import (
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	udpConn   *net.UDPConn
	handle    *pcap.Handle
	packetSrc *gopacket.PacketSource
)

func sniffPacket(packetSrc *gopacket.PacketSource) {
	defer func() {
		log.Println("sniff Packet done!")
	}()
	var ethLayer layers.Ethernet
	var eapLayer layers.EAP
	var eapolLayer layers.EAPOL
	var ipLayer layers.IPv4
	var udpLayer layers.UDP
	for {
		select {
		case packet := <-packetSrc.Packets():
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
		case <-time.After(time.Second * 30):
			log.Println("Timeout for sniffing packet src")
			return
		}
	}
}

// running instance
func run() {
	// dial udp connection
	serverIPStr := GConfig.ServerIP.String()
	udpServerAddr, err := net.ResolveUDPAddr("udp4", serverIPStr+":61440")
	if err != nil {
		log.Println(err)
	}
	udpConn, err = net.DialUDP("udp4", nil, udpServerAddr)
	if err != nil {
		log.Println(err)
	}
	defer udpConn.Close()

	//open dev interface and get the handle
	handle, err = pcap.OpenLive(GConfig.InterfaceName, 1024, false, -1*time.Second)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	//set filter, filter 802.1X and incoming drcom message
	var filter string = "ether proto 0x888e || udp src port 61440"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	relogin(timeInterval)
	packetSrc = gopacket.NewPacketSource(handle, handle.LinkType())
	sniffPacket(packetSrc) // sniff and block
}
