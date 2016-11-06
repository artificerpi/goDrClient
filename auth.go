package main

import (
	"crypto/md5"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// sends the EAPOL message to Authenticator
func sendEAPOL(Version byte, Type layers.EAPOLType, SrcMAC net.HardwareAddr, DstMAC net.HardwareAddr) {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{EthernetType: layers.EthernetTypeEAPOL, SrcMAC: SrcMAC, DstMAC: DstMAC},
		&MyEAPOL{&layers.EAPOL{Version: 0x01, Type: Type}, 0},
	)
	//var err error
	err := handle.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Println(err)
		os.Exit(0)
	}
}

// sends the EAP message to Authenticator
func sendEAP(Id uint8, Type layers.EAPType, TypeData []byte, Code layers.EAPCode, SrcMAC net.HardwareAddr, DstMAC net.HardwareAddr) {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{EthernetType: layers.EthernetTypeEAPOL, SrcMAC: SrcMAC, DstMAC: DstMAC},
		&MyEAPOL{&layers.EAPOL{Version: 0x01, Type: layers.EAPOLTypeEAP}, uint16(len(TypeData)) + 5},
		&layers.EAP{Id: Id, Type: Type, TypeData: TypeData, Code: Code, Length: uint16(len(TypeData) + 5)},
	)
	// err error
	err := handle.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Println(err)
		os.Exit(0)
	}
}

/* 读取新数据包 */
func readNewPacket(packetSrc *gopacket.PacketSource) {
	for packet := range packetSrc.Packets() {
		eapl := packet.Layer(layers.LayerTypeEAP)
		if eapl != nil {
			switch eapl.(*layers.EAP).Code {
			case 0x03: //Success
				fmt.Println("Success")
				sendPingStart()
			case 0x01: //Request
				switch int8(eapl.(*layers.EAP).Type) {
				case 0x04: //EAP-MD5-CHALLENGE
					//fmt.Println(eapl.(*layers.EAP).TypeData)
					go responseMd5Challenge(eapl.(*layers.EAP).TypeData[1:17])
				case 0x02: //Notification
					fmt.Println("Failed")
					os.Exit(0)
				case 0x01: //Identity
					//fmt.Print("TRUE")
					go responseIndentity(eapl.(*layers.EAP).Id)
				}
			case 0x04: //Failure
				fmt.Println("Failed")
				fmt.Println("Retry...")
				time.Sleep(5 * time.Second)
				startRequest()
			}

		}
	}

	done <- true
}

// start request to the Authenticator
func startRequest() {
	log.Println(mac)
	log.Println("EAP Start...")
	// sending the EAPOL-Start message to a multicast group
	sendEAPOL(0x01, layers.EAPOLTypeStart, mac, boardCastAddr)
}

// sending logoff message
func logoff() {
	//send EAPOL-Logoff message to be disconnected from the network.
	sendEAPOL(0x01, layers.EAPOLTypeLogOff, mac, boardCastAddr)
	log.Println("Logoff...")
}

/* 回应身份(Indentity) */
func responseIndentity(id byte) {
	dataPack := []byte{}
	dataPack = append(dataPack, []byte(username)...)                     //用户名
	dataPack = append(dataPack, []byte{0x00, 0x44, 0x61, 0x00, 0x00}...) //未知
	dataPack = append(dataPack, clientip[:]...)                          //客户端IP
	fmt.Println("Response Identity...")
	sendEAP(id, 0x01, dataPack, 2, mac, boardCastAddr)
}

/* 回应MD5-Challenge */
func responseMd5Challenge(m []byte) {
	mPack := []byte{}
	mPack = append(mPack, 0)
	mPack = append(mPack, []byte(password)...)
	mPack = append(mPack, m...)
	mCal := md5.New()
	mCal.Write(mPack)
	dataPack := []byte{}
	dataPack = append(dataPack, 16)
	dataPack = append(dataPack, mCal.Sum(nil)...)
	dataPack = append(dataPack, []byte(username)...)
	dataPack = append(dataPack, []byte{0x00, 0x44, 0x61, 0x26, 0x00}...)
	dataPack = append(dataPack, []byte(clientip[:])...)
	challenge = mCal.Sum(nil) //用于后面心跳包
	fmt.Println("Response EAP-MD5-Challenge...")
	sendEAP(0, 0x04, dataPack, 2, mac, boardCastAddr)
}
