package main

import (
	"bufio"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

// List ethernet devices
// FindAllDevs is not very good in fact it uses c
// use golang net.interfaces() instead
func listEthDevices() (ifs []net.Interface, err error) {
	// TODO you should filter device not ethernet
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Println(err)
	}
	//TODO if ifaces is null return err
	//	if ifaces == nil{
	//		return nil, err msg
	//	}
	return ifaces, err
}

// credentials get username and hidden pass from terminal input
func credentials() (string, string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter Username: ")
	username, _ := reader.ReadString('\n')

	fmt.Print("Enter Password: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Println("errors while entering pass", err)
	}
	password := string(bytePassword)

	return strings.TrimSpace(username), strings.TrimSpace(password)
}

func checkOnline() {
	//	http://root-servers.org/ good ip for ping test
	addrs := [6]string{"8.8.8.8", "4.2.2.1", "4.2.2.2",
		"208.67.222.123", "208.67.220.123", "198.41.0.4"}
	if ping(addrs[rand.Intn(6)], 1) || ping(GConfig.DNS1.String(), 3) {
		log.Println("Checking network:", "ok.")
	} else if checkNTP() || checkNTP() { // try twice
		log.Println("Checking network:", "ok.")
	} else {
		log.Println("Detected network offline, restarting...")
		setOnline(false)
		if !startRequest() { // try relogin
			quit <- true
			go sniff()
		}
	}
}
