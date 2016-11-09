package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"runtime"

	"github.com/larspensjo/config"
)

const (
	AppName        string = "gofsnet"
	Version        string = "0.0.1"
	ConfigFileName string = "config.ini"
)

var (
	GConfig       Config           // gofsnet configuration
	SrcMAC        net.HardwareAddr // mac address of interface
	BoardCastAddr net.HardwareAddr = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

type Config struct {
	// Account information
	Username string
	Password string

	// Network information
	ClientIP net.IP
	Gateway  net.IP
	Netmask  net.IPMask
	DNS1     net.IP
	DNS2     net.IP

	// Device information
	InterfaceName string // or interface struct?

	// Server information
	ServerIP net.IP
}

//TODO what is init for?
func init() {
	// load config
	log.Println("Loading configuration ...")

	// load configuration from file
	var cfg *config.Config
	_, err := os.Stat(ConfigFileName)
	if err == nil {
		cfg, err = config.ReadDefault(ConfigFileName)
		if err != nil {
			log.Println(err)
		}
	} else {
		cfg = config.NewDefault()
	}

	// load account info
	username, _ = cfg.String("account", "username")
	password, _ = cfg.String("account", "password")
	if username == "" || password == "" {
		fmt.Print("Username: ")
		fmt.Scan(&username)
		cfg.AddOption("account", "username", username)
		fmt.Print("Password: ")
		fmt.Scan(&password)
		cfg.AddOption("account", "password", password)
	}

	// load device info
	ifaceName, _ := cfg.String("device", "interface")
	if ifaceName == "" {
		ifaces, err := listEthDevices()
		if err != nil {
			log.Println(err)
		}
		for i, iface := range ifaces {
			fmt.Printf("[%d] %s\n", i+1, iface.Name)
		}

		option := 0
		fmt.Scan(&option)
		if option >= 1 && option <= len(ifaces) {
			ifaceName = ifaces[option-1].Name
			cfg.AddOption("device", "interface", ifaceName)
		} else {
			log.Println("Bad selection input for interface!")
			os.Exit(0)
		}
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Println(err)
	}
	if iface == nil {
		log.Println("null interface")
		os.Exit(1)
	}
	mac = iface.HardwareAddr
	if mac == nil {
		log.Println("null mac")
		os.Exit(1)
	}
	// set device name
	switch runtime.GOOS {
	case "windows": // dev = adapter device name
		adapterName, _ := getDeviceAdapterName(iface.Index)
		dev = "\\Device\\NPF_" + adapterName
	default:
		dev = ifaceName
	}

	// Network information (optional)
	ipStr, err := iface.Addrs() // get client ip
	if err != nil {
		log.Println(err)
	}
	fmt.Sscanf(ipStr[0].String(), "%d.%d.%d.%d", &clientip[0], &clientip[1], &clientip[2], &clientip[3])

	// Authenticator Server information
	serverIpStr, _ = cfg.String("server", "ip")
	if serverIpStr == "" {
		fmt.Print("Server IP: ")
		fmt.Scan(&serverIpStr)
		cfg.AddOption("server", "ip", serverIpStr)
	}
	fmt.Sscanf(serverIpStr, "%d.%d.%d.%d", &serverip[0], &serverip[1], &serverip[2], &serverip[3])
	boardCastAddr = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	// write back to configuration file
	cfg.WriteFile(ConfigFileName, os.FileMode(os.O_WRONLY), AppName+" "+Version+" Configuration")
}

//TODO add read() write() method for Config
