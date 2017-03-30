package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strings"

	"github.com/robfig/config"
)

const (
	AppName   string = "gofsnet"
	Version   string = "0.7.4"
	Copyright string = "https://github.com/artificerpi/gofsnet"
)

var (
	GConfig       Config           // gofsnet configuration
	InterfaceMAC  net.HardwareAddr // mac address of interface
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
	InterfaceName string // dev name to capture packet

	// Server information
	ServerIP net.IP
}

// load configuration from file
//default setting is for dormitory network of scut
func loadConfig(configFile string) {
	log.Println("Loading configuration ...")

	var cfg *config.Config
	_, err := os.Stat(configFile)
	if err == nil {
		cfg, err = config.ReadDefault(configFile)
		if err != nil {
			log.Println(err)
		}
	} else {
		cfg = config.NewDefault()
		fmt.Println("Configuration file does not exist, create a new one:")
	}

	// load account info(username, password)
	GConfig.Username, _ = cfg.String("account", "username")
	GConfig.Password, _ = cfg.String("account", "password")
	if GConfig.Username == "" || GConfig.Password == "" {
		GConfig.Username, GConfig.Password = credentials()
		cfg.AddOption("account", "username", GConfig.Username)
	}
	var appPrefix = AppName + "-"
	if strings.HasPrefix(GConfig.Password, appPrefix) { // decode from masking
		GConfig.Password = strings.TrimPrefix(GConfig.Password, appPrefix)
		decodedPass, err := base64.StdEncoding.DecodeString(GConfig.Password)
		if err != nil {
			log.Println(err)
		}
		GConfig.Password = string(decodedPass)
	} else {
		encodedPass := base64.StdEncoding.EncodeToString([]byte(GConfig.Password))
		cfg.AddOption("account", "password", appPrefix+encodedPass) // pass masking
	}

	// load device info
	// TODO optimize the following codes and find the lan device automactially
	ifaceName, _ := cfg.String("device", "interface")
	if ifaceName == "" {
		ifaces, err := listEthDevices()
		if err != nil {
			log.Println(err)
		}
		fmt.Println("Choose the network interface by entering your option")
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
			//			os.Exit(0)
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
	InterfaceMAC = iface.HardwareAddr // mac address
	if InterfaceMAC == nil {
		log.Println("null mac")
		os.Exit(1)
	}
	switch runtime.GOOS { // set device name
	case "windows": // dev = adapter device name
		adapterName, _ := getDeviceAdapterName(iface.Index)
		GConfig.InterfaceName = "\\Device\\NPF_" + adapterName
	default:
		GConfig.InterfaceName = ifaceName
	}

	// Network information (optional)
	addrs, err := iface.Addrs() // get client ip
	if err != nil {
		log.Println(err)
	}
	if len(addrs) == 0 {
		log.Fatal("You haven't plugged the network cable yet!")
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				GConfig.ClientIP = ipnet.IP
				break // only get the first one if there exists multiple addrs
			}
		}
	}

	// Authenticator Server information
	serverIpStr, _ := cfg.String("server", "ip") // server ip
	dns1, _ := cfg.String("server", "dns1")      // dns1
	dns2, _ := cfg.String("server", "dns2")      // dns2
	if serverIpStr == "" {
		serverIpStr = "202.38.210.131"
		cfg.AddOption("server", "ip", serverIpStr)
	}
	if dns1 == "" {
		dns1 = "222.201.130.30"
		cfg.AddOption("server", "dns1", dns1)
	}
	if dns2 == "" {
		dns2 = "222.201.130.33"
		cfg.AddOption("server", "dns2", dns2)
	}
	GConfig.ServerIP = net.ParseIP(serverIpStr)
	GConfig.DNS1 = net.ParseIP(dns1)
	GConfig.DNS2 = net.ParseIP(dns2)

	// write back to configuration file
	cfg.WriteFile(configFile, os.FileMode(644), AppName+" "+Version+" Configuration")
}
