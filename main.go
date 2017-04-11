package main

import (
	"flag"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	udpConn    *net.UDPConn
	handle     *pcap.Handle
	done       chan bool = make(chan bool) // exist for supporting runing in background
	configFile string
	lock       sync.Mutex
)

func init() {
	log.Println(AppName, Version, "-- go version Drcom client by artificerpi")
	log.Println("Project url:", Copyright)
	log.Println("Executing...")
}

func setState(value int) {
	if value > 1 || value < -1 {
		log.Println("improper value")
		return
	}
	lock.Lock()
	defer lock.Unlock()
	state = value
}

func loop() {
	for {
		if state == -1 {
			break
		}
	}
}

// sniff EAP packets and send response packets
func sniff(packetSrc *gopacket.PacketSource) {
	var ethLayer layers.Ethernet 
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
}

func run() {
	setState(0)
	log.Println("restarting..")
	//open dev interface and get the handle
	var err error
	handle, err = pcap.OpenLive(GConfig.InterfaceName, 1024, false, -1*time.Second)
	defer handle.Close()
	if err != nil {
		log.Println(err)
		os.Exit(0)
	}
	if handle == nil {
		panic("null handle")
		os.Exit(1)
	}

	//set filter, filter 802.1X and incoming drcom message
	var filter string = "ether proto 0x888e || udp src port 61440"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	relogin(timeInterval)
	packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	go sniff(packetSrc)

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
	for {
		if state == -1 {
			break
		}
	}
}

func cron() {
	ticker := time.NewTicker(20 * time.Second)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				// do stuff
				log.Println("ticking...")

				if checkNetwork() {
					log.Println("ok")
				} else {
					setState(-1)
					log.Println("detected network offline")
					log.Println("restart....................................................")
					go run()
				}
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()
}

func main() {
	var configFile string
	flag.StringVar(&configFile, "c", "config.ini", "specify config file")
	flag.Parse()
	loadConfig(configFile) // load configuration file

	go run()
	time.Sleep(time.Duration(10) * time.Second)
	go cron()
	select {} // block forever
}
