package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"time"
)

// Dr.com protocol is based on udp
// Note that if you want to test in your own drcom environment,
// you may have to rewrite this code for your own situation
// this file is written to test in scut dormitory network.

type DrCode byte

const (
	DrCodeMisc    DrCode = 0x07
	DrCodeMessage DrCode = 0x4d
	DrCodeAlive   DrCode = 0xff
)

var (
	UknCode_1   byte
	UknCode_2   byte
	UknCode_3   byte
	globalCheck [4]byte
	counter     byte

	kpsercnt uint16
	flux     uint32
)

// DRCOM defines the Dr.com 2011 protocol
type DRCOM struct {
	// Data (or payload) is the set of bytes that the packet contains
	Data []byte

	Code DrCode // code for identifying each type of drcom packet

	// common used types for misc type
	Type     byte
	AuthType byte // response for alive auth
	Step     byte // loop alive message (0x01, 0x02, 0x03, 0x04)
}

// DecodeFromBytes decodes the slice into the DRCOM struct.
func (d *DRCOM) DecodeFromBytes(data []byte) error {
	if len(data) < 2 {
		log.Println("data len", len(data))
		return errors.New("DRCOM packet too short")
	}

	d.Data = data[:len(data)]
	d.Code = DrCode(data[0])

	if d.Code == DrCodeMisc {
		d.Type = data[2]
		if d.Type == 0x10 {
			d.AuthType = data[1]
		}
		if d.Type == 0x28 {
			d.Step = data[5]
		}
	}

	return nil
}

// start udp request to the server
func startUDPRequest() {
	var dr DRCOM = DRCOM{}
	dr.Data = make([]byte, 8) // 8 bytes

	dr.Data[0] = byte(DrCodeMisc)
	copy(dr.Data[2:4], []byte{0x08, 0x00}) // Type
	copy(dr.Data[4:], []byte{0x01, 0x00, 0x00, 0x00})

	_, err := udpConn.Write(dr.Data) // write raw bytes
	if err != nil {
		log.Println(err)
	}
	log.Println("start udp request")
}

// sniff and handle drcom packet
func sniffDRCOM(rawBytes []byte) {
	var dr DRCOM // stores drcom packet
	err := dr.DecodeFromBytes(rawBytes)
	if err != nil {
		log.Println(err)
		return
	}

	//	log.Printf("content % x\n", dr.Data)	// for debug

	if dr.Code == DrCodeMisc {
		switch dr.Type {
		case 0x10: // response for alive
			if dr.AuthType == 0x00 { // request for udp auth
				log.Println("requested dr login auth")
				flux = binary.LittleEndian.Uint32(dr.Data[8:12]) // set flux
				sendAuthInfo()                                   // drcom auth
			}
			if dr.AuthType == 0x01 { // has been authenticated
				log.Println("keeping alive")
				sendPacket40(0x01) // send step 1 packet
			}
		case 0x28:
			if dr.Step == 0x02 { //received step 2 packet
				log.Println("received step 2 message")
				flux = binary.LittleEndian.Uint32(dr.Data[16:20]) // update flux
				sendPacket40(0x03)                                // send step 3 packet
			}
			if dr.Step == 0x04 { //received step 4 packet
				log.Println("received step 4 message")
				flux = binary.LittleEndian.Uint32(dr.Data[16:20]) // update flux
				go sendPacket38()
			}
		case 0x30: // packet after auth, logon message or token
			UknCode_1 = dr.Data[24]
			UknCode_2 = dr.Data[25]
			UknCode_3 = dr.Data[31]
			log.Println("received auth bytes")
		}
	} else if dr.Code == DrCodeMessage { // file message
		log.Println("start keep alive")
		sendPacket40(1) // send step 1 message
	}
}

// Step 1 and 3, Drcom Packet type: 0x2800
// 40字节心跳包发送
func sendPacket40(step byte) {
	var buf [40]byte
	buf[0] = byte(DrCodeMisc)
	buf[1] = counter
	buf[2] = 0x28 // Type 0x2800
	buf[4] = 0x0b //fixed byte
	buf[5] = step
	copy(buf[6:8], []byte{0xdc, 0x02}) // fixed bytes, available from response alive message

	binary.LittleEndian.PutUint16(buf[8:10], kpsercnt) // Carry per 1000 step?
	binary.LittleEndian.PutUint32(buf[16:20], flux)    // flux

	if step == 3 { // add IP info for Step 3
		copy(buf[28:32], []byte(GConfig.ClientIP.To4()))
		putCode2(buf[:]) // copy hash bytes
	}
	if counter >= 255 { // byte (uint8)
		counter = 0
	}
	counter = counter + 1
	if kpsercnt >= 65535 { //unint16
		kpsercnt = 0
	}
	if step == 0x03 {
		kpsercnt = kpsercnt + uint16(flux/1000000)
	}
	udpConn.Write(buf[:])
	log.Printf("Step %d message sent", uint8(step))
}

// keep alive message request
// 38字节心跳包发送
func sendPacket38() {
	time.Sleep(20 * time.Second) // TODO  verify: client to server per 20s
	var buf [38]byte
	buf[0] = byte(DrCodeAlive)

	copy(buf[1:5], globalCheck[:]) // MD5A
	copy(buf[5:17], challenge[4:16])

	// [17:20] Zeros

	//Auth Information
	copy(buf[20:24], "Drco")                         // unknown drco
	copy(buf[24:28], []byte(GConfig.ServerIP.To4())) // Server IP
	buf[28] = UknCode_1
	if UknCode_2 >= 128 {
		buf[29] = UknCode_2<<1 | 1
	} else {
		buf[29] = UknCode_2 << 1
	}
	copy(buf[30:34], []byte(GConfig.ClientIP.To4()))
	buf[34] = 0x01
	if UknCode_3%2 == 0 {
		buf[35] = UknCode_3 >> 1
	} else {
		buf[35] = UknCode_3>>1 | 128
	}
	binary.LittleEndian.PutUint16(buf[36:38], uint16(time.Now().Unix()))
	udpConn.Write(buf[:])
	log.Println("38 bytes packet sent")
}

// send auth info to the authenticator
// packet 286 bytes: Misc, Info usesrname, host
func sendAuthInfo() {
	var buf [244]byte // 244 bytes

	// header
	buf[0] = 0x07
	buf[1] = 0x01                      // Count what?
	copy(buf[2:4], []byte{0xf4, 0x00}) // Info username, hostname
	buf[4] = 0x03
	buf[5] = byte(len(GConfig.Username))

	// mac and ip
	copy(buf[6:12], InterfaceMAC)
	copy(buf[12:16], []byte(GConfig.ClientIP.To4()))

	// fixed 4 bytes
	copy(buf[16:20], []byte{0x02, 0x22, 0x00, 0x2a})

	// flux, copy from auth request
	binary.LittleEndian.PutUint32(buf[20:24], flux)

	// crc32, 4 bytes, calculated later
	// zeros

	// Username and hostname
	hostname, err := os.Hostname()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	copy(buf[32:76], []byte(GConfig.Username+hostname))
	copy(buf[76:80], []byte(GConfig.DNS1.To4())) // dns1 4 bytes
	copy(buf[84:88], []byte(GConfig.DNS2.To4())) // dns2 4 bytes

	var otherInfo []byte = make([]byte, 37)
	//0x0060
	otherInfo[7] = 0x94
	otherInfo[11] = 0x06
	otherInfo[15] = 0x02
	otherInfo[19] = 0xf0
	otherInfo[20] = 0x23

	//0x0070
	otherInfo[23] = 0x02
	copy(otherInfo[27:37], []byte{0x44, 0x72,
		0x43, 0x4f, 0x4d, 0x00, 0x96, 0x02, 0x2a, 0x00}) // DrCOM character
	copy(buf[89:], otherInfo)

	// fixed 64 hash bytes
	var hashCode string = "2ec15ad258aee9604b18f2f8114da38db16efd00"
	copy(buf[180:], []byte(hashCode))
	putCode1(buf[:244]) //crc32 bytes

	udpConn.Write(buf[:])
}

// 信息包校验码计算 drcom crc32
func putCode1(buf []byte) {
	v5 := len(buf) >> 2
	var v6 uint32
	var tmp uint32
	var b_tmp *bytes.Buffer
	binary.LittleEndian.PutUint32(buf[24:28], 20000711)
	binary.LittleEndian.PutUint32(buf[28:32], 126)
	for i := 0; i < v5; i++ {
		b_tmp = bytes.NewBuffer(buf[4*i : 4*i+4])
		binary.Read(b_tmp, binary.LittleEndian, &tmp)
		v6 ^= tmp
	}
	binary.LittleEndian.PutUint32(buf[24:28], v6*19680126)
	buf[28] = 0
	//	log.Printf("% x\n", v6*19680126)
	//	log.Printf("% x\n", buf[:])
	binary.LittleEndian.PutUint32(globalCheck[:], v6*19680126)
}

// 40字节心跳包校验码计算
func putCode2(buf []byte) {
	var tmp, v5 uint16
	var b_tmp *bytes.Buffer
	for i := 0; i < 20; i++ {
		b_tmp = bytes.NewBuffer(buf[2*i : 2*i+2])
		binary.Read(b_tmp, binary.LittleEndian, &tmp)
		v5 ^= tmp
	}
	binary.LittleEndian.PutUint32(buf[24:28], uint32(v5)*711)
}
