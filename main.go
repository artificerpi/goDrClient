package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/larspensjo/config"
)

var (
	clientip [4]byte
	mac      net.HardwareAddr
	dns1     byte
	dns2     byte
	username string
	password string
)

var (
	udpConn *net.UDPConn
)

var err error
var done chan bool
var handle *pcap.Handle
var boardCastAddr net.HardwareAddr
var serverip [4]byte
var serverIpStr string

var (
	challenge []byte
	dev       string
)

func initialize() {
	// load config
	var cfg *config.Config
	_, err = os.Stat(ConfigFileName)
	if err == nil {
		cfg, err = config.ReadDefault(ConfigFileName)
		checkError(err)
	} else {
		cfg = config.NewDefault()
	}

	username, _ = cfg.String("user", "username")
	password, _ = cfg.String("user", "password")
	if username == "" || password == "" {
		fmt.Print("Username: ")
		fmt.Scan(&username)
		cfg.AddOption("user", "username", username)
		fmt.Print("Password: ")
		fmt.Scan(&password)
		cfg.AddOption("user", "password", password)
	}

	// choose the device
	dev = "\\Device\\NPF_{4C8D0B85-40B4-4173-AC40-02A86AA1087D}"
	macConfig, _ := cfg.String("client", "mac")
	if macConfig == "" {
		fmt.Print("Mac Address: ")
		fmt.Scan(&macConfig)
		cfg.AddOption("client", "mac", macConfig)
	}

	mac, _ = net.ParseMAC(macConfig)

	//devSelect:
	//	dev, _ = cfg.String("client", "dev")
	//	if dev == "" {
	//		devs, err := pcap.FindAllDevs()
	//		checkError(err)
	//		switch runtime.GOOS {
	//		case "windows":
	//			for n, d := range devs {
	//				fmt.Printf("[%d] %s\n", n+1, d.Description)
	//			}
	//		default:
	//			for n, d := range devs {
	//				fmt.Printf("[%d] %s\n", n+1, d.Name)
	//			}
	//		}

	//		s := 0
	//		fmt.Scan(&s)
	//		if s >= 1 && s <= len(devs) {
	//			cfg.AddOption("client", "dev", devs[s-1].Name)
	//		}
	//		goto devSelect
	//	}

	// set Server ip
	serverIpStr, _ = cfg.String("server", "ip")
	if serverIpStr == "" {
		fmt.Print("Server IP: ")
		fmt.Scan(&serverIpStr)
		cfg.AddOption("server", "ip", serverIpStr)
	}
	cfg.WriteFile(ConfigFileName, os.FileMode(os.O_WRONLY), AppName+" "+Version+" Configuration")

	// set mac
	//	var tmpInterface *net.Interface
	//	switch runtime.GOOS {
	//	case "windows":
	//		tmpInterface, err = net.InterfaceByName(dev[12:])
	//	default:
	//		tmpInterface, err = net.InterfaceByName(dev)
	//	}
	//	checkError(err)
	//mac = tmpInterface.HardwareAddr

	//		ipStr, _ := tmpInterface.Addrs()
	//	fmt.Sscanf(ipStr[0].String(), "%d.%d.%d.%d", &clientip[0], &clientip[1], &clientip[2], &clientip[3])
	fmt.Sscanf(serverIpStr, "%d.%d.%d.%d", &serverip[0], &serverip[1], &serverip[2], &serverip[3])
	boardCastAddr = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
}

func main() {
	done = make(chan bool) // exist for supporting runing in background

	initialize()

	//open eth interface and get the handle
	handle, err = pcap.OpenLive(dev, 1024, false, -1*time.Second)
	defer handle.Close()
	checkError(err)

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
	udpServerAddr, err := net.ResolveUDPAddr("udp4", serverIpStr+":61440")
	checkError(err)
	udpConn, err = net.DialUDP("udp4", nil, udpServerAddr)
	checkError(err)
	defer udpConn.Close()
	go recvPing()

	<-done // Block forever
}
