package main

// sniff packets and send response packets
import (
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var (
	udpConn      *net.UDPConn
	handle       *pcap.Handle
	capturedFile *os.File
	quit         chan bool = make(chan bool)
)

// sniff packets and handle them
func sniff() {
	defer func() {
		log.Println("An instance has been closed!")
	}()

	// Open output pcap file and write header
	var w *pcapgo.Writer
	if capturedFile != nil {
		w = pcapgo.NewWriter(capturedFile)
		w.WriteFileHeader(1024, layers.LinkTypeEthernet) //snapshotLen, 1024
	}

	var err error
	//open dev interface and get the handle
	handle, err = pcap.OpenLive(GConfig.InterfaceName, 1024, false, -1*time.Second)
	if err != nil {
		panic(err)
	}
	defer handle.Close()
	//set filter, filter 802.1X and incoming drcom message
	err = handle.SetBPFFilter("ether proto 0x888e || udp src port 61440")
	if err != nil {
		log.Fatal(err)
	}

	go relogin(2) // start login
	// dial UDP connection
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

	//	will reuse these for each packet
	var (
		ethLayer   layers.Ethernet
		ipLayer    layers.IPv4
		eapolLayer layers.EAPOL
		eapLayer   layers.EAP
		udpLayer   layers.UDP
	)
	packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())

	// sniff packets and block the goroutine
	for {
		select {
		case <-quit:
			log.Println("A goroutine has quit.")
			return
		case packet := <-packetSrc.Packets():
			// needed packets: eapol, eap, udp
			parser := gopacket.NewDecodingLayerParser(
				layers.LayerTypeEthernet,
				&ethLayer, // essential
				&ipLayer,  // essential
				&eapolLayer,
				&eapLayer,
				&udpLayer,
			)
			foundLayerTypes := []gopacket.LayerType{}

			// ignore error of decoding layer type Unknown (drcom packet in udp)
			_ = parser.DecodeLayers(packet.Data(), &foundLayerTypes)

			for _, layerType := range foundLayerTypes {
				switch layerType {
				case layers.LayerTypeUDP: // drcom packets are more frequent
					if isOnline {
						sniffDRCOM(udpLayer.Payload)
					}
				case layers.LayerTypeEAP:
					if !isOnline {
						sniffEAP(eapLayer)
					}
				}
			}

			if w != nil {
				w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			}
		case <-time.After(time.Second * 30): // timeout within 30s
			log.Println("Timeout for sniffing packet source")
			setOnline(false)
			startRequest() // restart eap auth
		}
	}
}
