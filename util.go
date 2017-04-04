package main

import (
	"bufio"
	"fmt"
	"log"
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
	if err == nil {
		fmt.Println("\nPassword typed: " + string(bytePassword))
	}
	password := string(bytePassword)

	return strings.TrimSpace(username), strings.TrimSpace(password)
}
