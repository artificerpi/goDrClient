package main

import (
	"flag"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/kardianos/service"
)

var (
	udpConn    *net.UDPConn
	handle     *pcap.Handle
	packetSrc  *gopacket.PacketSource
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

// sniff packets and send response packets
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

var logger service.Logger

// Program structures.
//  Define Start and Stop methods.
type program struct {
	exit chan struct{}
}

func (p *program) Start(s service.Service) error {
	if service.Interactive() {
		logger.Info("Running in terminal.")
	} else {
		logger.Info("Running under service manager.")
	}
	p.exit = make(chan struct{})

	// Start should not block. Do the actual work async.
	go p.run()
	return nil
}
func (p *program) run() error {
	logger.Infof("I'm running %v.", service.Platform())
	ticker := time.NewTicker(20 * time.Second)
	go run()
	for {
		select {
		case tm := <-ticker.C:
			logger.Infof("Still running at %v...", tm)
			if checkNetwork() {
				log.Println("ok")
			} else {
				setState(-1)
				log.Println("detected network offline")
				log.Println("restart....................................................")
				err := handle.WritePacketData([]byte("abc"))
				if err != nil {
					log.Println(err)
					log.Println("detected error")
					go run()
				} else {
					relogin(5)
				}

			}
		case <-p.exit:
			ticker.Stop()
			return nil
		}
	}
}

func (p *program) Stop(s service.Service) error {
	// Any work in Stop should be quick, usually a few seconds at most.
	logger.Info("I'm Stopping!")
	close(p.exit)
	return nil
}

func main() {
	var configFile string
	flag.StringVar(&configFile, "c", "config.ini", "specify config file")
	svcFlag := flag.String("service", "", "Control the system service.")
	flag.Parse()
	loadConfig(configFile) // load configuration file

	//	go run()
	//	time.Sleep(time.Duration(10) * time.Second)
	//	go cron()

	svcConfig := &service.Config{
		Name:        "GoServiceExampleLogging",
		DisplayName: "Go Service Example for Logging",
		Description: "This is an example Go service that outputs log messages.",
	}

	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}
	errs := make(chan error, 5)
	logger, err = s.Logger(errs)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			err := <-errs
			if err != nil {
				log.Print(err)
			}
		}
	}()

	if len(*svcFlag) != 0 {
		err := service.Control(s, *svcFlag)
		if err != nil {
			log.Printf("Valid actions: %q\n", service.ControlAction)
			log.Fatal(err)
		}
		return
	}
	err = s.Run()
	if err != nil {
		logger.Error(err)
	}
}
