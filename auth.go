package main

import (
	"crypto/md5"
	"log"
	"net"
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
		Id:       Id,
		Type:     Type,
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

//// TODO rewrite the sniff of auth part
func sniffEAP(eapLayer layers.EAP) {
	switch eapLayer.Code {
	case layers.EAPCodeRequest: //Request
		switch eapLayer.Type { // request type
		case layers.EAPTypeIdentity: //Identity
			go responseIdentity(eapLayer.Id)
		case layers.EAPTypeOTP: //EAP-MD5-CHALLENGE
			go responseMd5Challenge(eapLayer.TypeData[1:17])
		case layers.EAPTypeNotification: //Notification
			log.Println("Failed")
			startRequest()
		}
	case layers.EAPCodeSuccess: //Success
		log.Println("EAP auth success")
		startUDPRequest() // start keep-alive
	case layers.EAPCodeFailure: //Failure
		log.Println("Failed")
		log.Println("Retry...")
		startRequest()
	}

}

// start request to the Authenticator
func startRequest() {
	logoff()
	log.Println("Start request to Authenticator...")
	time.Sleep(3 * time.Second)
	// sending the EAPOL-Start message to a multicast group
	sendEAPOL(0x01, layers.EAPOLTypeStart, InterfaceMAC, BoardCastAddr)
}

// sending logoff message
func logoff() {
	//send EAPOL-Logoff message to be disconnected from the network.
	sendEAPOL(0x01, layers.EAPOLTypeLogOff, InterfaceMAC, BoardCastAddr)
	log.Println("Logoff...")
}

// response Identity
func responseIdentity(id byte) {
	dataPack := []byte{}
	dataPack = append(dataPack, []byte(GConfig.Username)...)             // Username
	dataPack = append(dataPack, []byte{0x00, 0x44, 0x61, 0x00, 0x00}...) // Fixed Uknown bytes
	dataPack = append(dataPack, []byte(GConfig.ClientIP.To4())...)       // Client IP
	log.Println("Response Identity...")
	sendEAP(id, layers.EAPTypeIdentity, dataPack, layers.EAPCodeResponse, InterfaceMAC, BoardCastAddr)
}

// response MD5-Challenge  md( EAP-MD5 Challange + Password) + Extra data
func responseMd5Challenge(m []byte) {
	mPack := []byte{}
	mPack = append(mPack, 0)
	mPack = append(mPack, []byte(GConfig.Password)...)
	mPack = append(mPack, m...)
	mCal := md5.New() //new hash.Hash
	mCal.Write(mPack)
	challenge = mCal.Sum(nil) //用于后面心跳包
	dataPack := []byte{}
	dataPack = append(dataPack, 16) // EAP-MD5 Value-Size
	dataPack = append(dataPack, mCal.Sum(nil)...)
	dataPack = append(dataPack, []byte(GConfig.Username)...)
	dataPack = append(dataPack, []byte{0x00, 0x44, 0x61, 0x26, 0x00}...)
	dataPack = append(dataPack, []byte(GConfig.ClientIP.To4())...)
	log.Println("Response EAP-MD5-Challenge...")
	sendEAP(0, layers.EAPTypeOTP, dataPack, layers.EAPCodeResponse, InterfaceMAC, BoardCastAddr)
}
