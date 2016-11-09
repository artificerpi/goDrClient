package main

import (
	"log"
	"net"
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
