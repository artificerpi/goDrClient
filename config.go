package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"

	"github.com/larspensjo/config"
)

const (
	AppName        string = "gofsnet"
	Version        string = "0.7.3-ui"
	ConfigFileName string = "config.ini"
	Copyright      string = "https://github.com/artificerpi/gofsnet"
)

var (
	GConfig       Config           // gofsnet configuration
	InterfaceMAC  net.HardwareAddr // mac address of interface
	BoardCastAddr net.HardwareAddr = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	EnableSysTray   bool
	EnableAutoStart bool
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

//load and check configuration
//default setting is for scut dormitory net
func init() {
	// load config
	log.Println("Loading configuration ...")

	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}
	// load configuration from file
	var cfg *config.Config
	_, err = os.Stat(dir + "\\" + ConfigFileName)
	if err == nil {
		cfg, err = config.ReadDefault(dir + "\\" + ConfigFileName)
		if err != nil {
			log.Println(err)
		}
	} else {
		cfg = config.NewDefault()
	}

	// load account info(username, password)
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
	InterfaceMAC = iface.HardwareAddr // mac address
	if InterfaceMAC == nil {
		log.Println("null mac")
		os.Exit(1)
	}
	switch runtime.GOOS { // set device name
	case "windows": // dev = adapter device name
		adapterName, _ := getDeviceAdapterName(iface.Index)
		GConfig.InterfaceName = "\\Device\\NPF_" + adapterName
		EnableSysTray = true
	default:
		GConfig.InterfaceName = ifaceName
		EnableSysTray = false
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
				break // only get the first one if there exists multiple addrs
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
		serverIpStr = "202.38.210.131"
		cfg.AddOption("server", "ip", serverIpStr)
	}
	GConfig.ServerIP = net.ParseIP(serverIpStr)
	if GConfig.ServerIP == nil {
		log.Println("Illegal server ip ")
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

	autoStart, _ := cfg.String("preference", "autostart")
	if autoStart == "true" { //TODO case not sensitive
		EnableAutoStart = true
		fmt.Println("ok")
	} else {
		EnableAutoStart = false
		cfg.AddOption("preference", "autostart", "false")
	}
	// write back to configuration file
	cfg.WriteFile(dir+"\\"+ConfigFileName, os.FileMode(644), AppName+" "+Version+" Configuration")
}

// TODO setting ip and dns of the network interface
