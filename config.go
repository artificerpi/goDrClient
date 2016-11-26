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
	Copyright      string = "https://github.com/artificerpi/gofsnet"
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
	InterfaceName string // or interface struct?

	// Server information
	ServerIP   net.IP
	ServerName string
}

//load and check configuration
//default setting is for scut dormitory net
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
	GConfig.Username, _ = cfg.String("account", "username")
	GConfig.Password, _ = cfg.String("account", "password")
	if GConfig.Username == "" || GConfig.Password == "" {
		fmt.Print("Username: ")
		fmt.Scan(&GConfig.Username)
		cfg.AddOption("account", "username", GConfig.Username)
		fmt.Print("Password: ")
		fmt.Scan(&GConfig.Password)
		cfg.AddOption("account", "password", GConfig.Password)
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
	InterfaceMAC = iface.HardwareAddr
	if InterfaceMAC == nil {
		log.Println("null mac")
		os.Exit(1)
	}
	// set device name
	switch runtime.GOOS {
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
		log.Fatal("You haven't plug the ethernet")
		os.Exit(1)
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				GConfig.ClientIP = ipnet.IP
			}
		}
	}
	if err != nil {
		log.Fatal(err)
	}
	if GConfig.ClientIP == nil {
		log.Fatal("Null client ip")
	}

	// Authenticator Server information
	serverIpStr, _ := cfg.String("server", "ip") // server ip
	if serverIpStr == "" {
		fmt.Print("Server IP: ")
		fmt.Scan(&serverIpStr)
		cfg.AddOption("server", "ip", serverIpStr)
	}
	GConfig.ServerIP = net.ParseIP(serverIpStr)
	if GConfig.ServerIP == nil {
		log.Println("Illegal server ip ")
	}
	GConfig.ServerName, _ = cfg.String("server", "name") // server name
	if GConfig.ServerName == "" {
		GConfig.ServerName = "139Yui-miao"
		cfg.AddOption("server", "name", GConfig.ServerName)
	}
	dns1, _ := cfg.String("server", "dns1") // dns1
	if dns1 == "" {
		dns1 = "222.201.130.30"
		cfg.AddOption("server", "dns1", dns1)
	}
	GConfig.DNS1 = net.ParseIP(dns1)
	dns2, _ := cfg.String("server", "dns2") // dns2
	if dns2 == "" {
		dns2 = "222.201.130.33"
		cfg.AddOption("server", "dns2", dns2)
	}
	GConfig.DNS2 = net.ParseIP(dns2)
	BoardCastAddr = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	// write back to configuration file
	cfg.WriteFile(ConfigFileName, os.FileMode(os.O_WRONLY), AppName+" "+Version+" Configuration")
}

//TODO add read() write() method for Config
