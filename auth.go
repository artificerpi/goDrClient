package main

import (
	"crypto/md5"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	challenge []byte
)

// sends the EAPOL message to Authenticator
func sendEAPOL(Version byte, Type layers.EAPOLType, SrcMAC net.HardwareAddr, DstMAC net.HardwareAddr) {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	ethernetLayer := &layers.Ethernet{
		EthernetType: layers.EthernetTypeEAPOL,
		SrcMAC:       SrcMAC,
		DstMAC:       DstMAC,
	}
	eapolLayer := &layers.EAPOL{
		Version: Version,
		Type:    Type,
		Length:  0,
	}
	gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		eapolLayer,
	)

	// write packet
	err := handle.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Println(err)
	}
}

// sends the EAP message to Authenticator
func sendEAP(Id uint8, Type layers.EAPType, TypeData []byte, Code layers.EAPCode, SrcMAC net.HardwareAddr, DstMAC net.HardwareAddr) {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	ethernetLayer := &layers.Ethernet{
		EthernetType: layers.EthernetTypeEAPOL,
		SrcMAC:       SrcMAC,
		DstMAC:       DstMAC,
	}
	eapolLayer := &layers.EAPOL{
		Version: 0x01,
		Type:    layers.EAPOLTypeEAP,
		Length:  uint16(len(TypeData) + 5),
	}
	eapLayer := &layers.EAP{
		Id: Id, Type: Type,
		TypeData: TypeData,
		Code:     Code,
		Length:   uint16(len(TypeData) + 5),
	}

	gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		eapolLayer,
		eapLayer,
	)
	// err error
	err := handle.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Println(err)
	}
}

// sniff EAP packets and send response packets
func sniff(packetSrc *gopacket.PacketSource) {
	for packet := range packetSrc.Packets() {
		eapl := packet.Layer(layers.LayerTypeEAP)
		if eapl != nil { // EAP packet
			switch eapl.(*layers.EAP).Code {
			case layers.EAPCodeRequest: //Request
				switch eapl.(*layers.EAP).Type { // request type
				case layers.EAPTypeIdentity: //Identity
					go responseIdentity(eapl.(*layers.EAP).Id)
				case layers.EAPTypeOTP: //EAP-MD5-CHALLENGE
					go responseMd5Challenge(eapl.(*layers.EAP).TypeData[1:17])
				case layers.EAPTypeNotification: //Notification
					log.Println("Failed")
					os.Exit(0)
				}
			case layers.EAPCodeSuccess: //Success
				log.Println("Login success")
				sendPingStart()
			case layers.EAPCodeFailure: //Failure
				log.Println("Failed")
				log.Println("Retry...")
				time.Sleep(5 * time.Second)
				startRequest()
			}

		}
	}

	done <- true
}

// start request to the Authenticator
func startRequest() {
	log.Println("Start request to Authenticator...")
	// sending the EAPOL-Start message to a multicast group
	sendEAPOL(0x01, layers.EAPOLTypeStart, SrcMAC, BoardCastAddr)
}

// sending logoff message
func logoff() {
	//send EAPOL-Logoff message to be disconnected from the network.
	sendEAPOL(0x01, layers.EAPOLTypeLogOff, SrcMAC, BoardCastAddr)
	log.Println("Logoff...")
}

// response Identity
func responseIdentity(id byte) {
	dataPack := []byte{}
	dataPack = append(dataPack, []byte(GConfig.Username)...)             // Username
	dataPack = append(dataPack, []byte{0x00, 0x44, 0x61, 0x00, 0x00}...) // Uknown bytes
	dataPack = append(dataPack, GConfig.ClientIP[:]...)                  // Client IP
	log.Println("Response Identity...")
	sendEAP(id, layers.EAPTypeIdentity, dataPack, layers.EAPCodeResponse, SrcMAC, BoardCastAddr)
}

/* 回应MD5-Challenge */
func responseMd5Challenge(m []byte) {
	mPack := []byte{}
	mPack = append(mPack, 0)
	mPack = append(mPack, []byte(GConfig.Password)...)
	mPack = append(mPack, m...)
	mCal := md5.New()
	mCal.Write(mPack)
	dataPack := []byte{}
	dataPack = append(dataPack, 16)
	dataPack = append(dataPack, mCal.Sum(nil)...)
	dataPack = append(dataPack, []byte(GConfig.Username)...)
	dataPack = append(dataPack, []byte{0x00, 0x44, 0x61, 0x26, 0x00}...)
	dataPack = append(dataPack, []byte(GConfig.ClientIP[:])...)
	challenge = mCal.Sum(nil) //用于后面心跳包
	log.Println("Response EAP-MD5-Challenge...")
	sendEAP(0, layers.EAPTypeOTP, dataPack, layers.EAPCodeResponse, SrcMAC, BoardCastAddr)
}
