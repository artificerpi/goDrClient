package main

import (
	"fmt"
	"net"
	"os"
	"runtime"
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

var (
	challenge []byte
)

func main() {
	done = make(chan bool) // exist for supporting runing in background
	var cfg *config.Config

	_, err = os.Stat("config.ini")

	if err == nil {
		cfg, err = config.ReadDefault("config.ini")
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

devSelect:
	dev, _ := cfg.String("client", "dev")
	if dev == "" {
		devs, err := pcap.FindAllDevs()
		checkError(err)
		switch runtime.GOOS {
		case "windows":
			for n, d := range devs {
				fmt.Printf("[%d] %s\n", n+1, d.Description)
			}
		default:
			for n, d := range devs {
				fmt.Printf("[%d] %s\n", n+1, d.Name)
			}
		}

		s := 0
		fmt.Scan(&s)
		if s >= 1 && s <= len(devs) {
			cfg.AddOption("client", "dev", devs[s-1].Name)
		}
		goto devSelect
	}
	serverIpStr, _ := cfg.String("server", "ip")
	if serverIpStr == "" {
		serverIpStr = "192.168.127.129"
		cfg.AddOption("server", "ip", serverIpStr)
	}
	cfg.WriteFile("config.ini", os.FileMode(os.O_WRONLY), "goDrClient Config File")
	var tmpInterface *net.Interface
	switch runtime.GOOS {
	case "windows":
		tmpInterface, err = net.InterfaceByName(dev[12:])
	default:
		tmpInterface, err = net.InterfaceByName(dev)
	}

	checkError(err)
	mac = tmpInterface.HardwareAddr
	ipStr, _ := tmpInterface.Addrs()
	fmt.Sscanf(ipStr[0].String(), "%d.%d.%d.%d/%d", &clientip[0], &clientip[1], &clientip[2], &clientip[3])
	fmt.Sscanf(serverIpStr, "%d.%d.%d.%d", &serverip[0], &serverip[1], &serverip[2], &serverip[3])
	boardCastAddr = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	handle, err = pcap.OpenLive(dev, 1024, false, 0*time.Second)
	fmt.Println(dev)
	checkError(err)

	startRequest()

	packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	go readNewPacket(packetSrc)

	udpServerAddr, err := net.ResolveUDPAddr("udp4", serverIpStr+":61440")
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	udpConn, err = net.DialUDP("udp4", nil, udpServerAddr)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	defer udpConn.Close()
	go recvPing()

	<-done // Block forever
}
