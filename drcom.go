package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"time"
)

// Dr.com protocol is based on udp

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
	drLayer     DRCOM
)

// DRCOM defines the Dr.com 2011 protocol
type DRCOM struct {
	// Contents is the set of bytes that make up this layer.
	Contents []byte

	Code       DrCode // code for identification
	TypeData   []byte // bytes depends on code
	ExtraBytes []byte // unknow bytes, like payload

	// common used types
	Type byte // for misc type
	Step byte // for loop alive message (0x01, 0x02, 0x03, 0x04)
}

// DecodeFromBytes decodes the slice into the DRCOM struct.
func (d *DRCOM) DecodeFromBytes(data []byte) error {
	if len(data) < 2 {
		return errors.New("DRCOM packet too short")
	}

	d.Contents = data[:len(data)]
	d.Code = DrCode(data[0])
	d.TypeData = data[2:]

	if d.Code == DrCodeMisc {
		d.Type = data[2]
		if d.Type == 0x28 {
			d.Step = data[5]
		}
	}
	return nil
}

// LayerContents returns the information that our layer
// provides. In this case it is a header layer so
// we return the header information
func (d *DRCOM) LayerContents() []byte {
	if len(d.Contents) == 0 && len(d.TypeData) > 0 { // data to be sent
		d.Contents = append(d.Contents, byte(d.Code), 0x00)
		d.Contents = append(d.Contents, d.TypeData...)
		d.Contents = append(d.Contents, d.ExtraBytes...)
	}
	return d.Contents
}

// start udp request to the server
func startUDPRequest() {
	drLayer = DRCOM{}
	drLayer.Code = DrCodeMisc
	drLayer.Type = 0x08
	drLayer.TypeData = []byte{drLayer.Type, 0x00}
	drLayer.ExtraBytes = []byte{0x01, 0x00, 0x00, 0x00}

	rawBytes := drLayer.LayerContents()

	udpConn.Write(rawBytes)
	log.Printf("%x\n", rawBytes)
	log.Println("start udp request")
}

//	TODO sniff drcom
func sniffDRCOM(rawBytes []byte) {
	err := drLayer.DecodeFromBytes(rawBytes)
	if err != nil {
		log.Println(err)
	}
	// for debug
	log.Printf("content %x\n", drLayer.Contents)
	log.Printf("raw byte %x\n", rawBytes)
	if drLayer.Code == DrCodeMisc {
		switch drLayer.Type {
		case 0x10: // response for alive
			if len(rawBytes) == 32 { // request for udp auth
				log.Println("requested dr login auth")
				sendAuthInfo(drLayer.TypeData[7:11]) //Info username, hostname
			}
			if len(rawBytes) == 64 { // request for alive message
				log.Println("requested alive message after step 4")
				sendPing40(1) // send pkt1 step 1
			}
		case 0x28:
			if drLayer.Step == 0x02 { //receive step 2 message
				log.Println("requested step 2 message")
				sendPing40(3) // send Step 3 message
			}
			if drLayer.Step == 0x04 { // receive step 4 message
				log.Println("send 38 bytes ")
				sendPing38()
			}
		case 0x30: // packet after auth
			UknCode_1 = drLayer.TypeData[23]
			UknCode_2 = drLayer.TypeData[24]
			UknCode_3 = drLayer.TypeData[30]
			//			log.Println
		case 0x4d: // file message
			sendPing40(1) // send step 1 message
			log.Println("step1")
		}
	}
}

// Step 1 and 3, Drcom Packet type: 0x2800
// 40字节心跳包发送
func sendPing40(step byte) {
	var buf [40]byte
	buf[0] = byte(DrCodeMisc)
	buf[1] = counter
	buf[2] = 0x28 // Type 0x2800
	buf[4] = 0x0b //fixed byte
	buf[5] = step
	copy(buf[6:10], []byte{0xdc, 0x02, 0x6c, 0x6f})
	if step == 3 { // add IP info for Step 3
		copy(buf[28:32], GConfig.ClientIP[:])
		//		putCode2(buf[:])
	}
	counter = counter + 1
	udpConn.Write(buf[:])
}

// keep alive message request
// 38字节心跳包发送
func sendPing38() {
	var buf [38]byte
	buf[0] = byte(DrCodeAlive)
	copy(buf[1:5], globalCheck[:]) // MD5A
	copy(buf[5:17], challenge[4:16])
	// [17:20] Zeros
	copy(buf[20:24], "Drco")              // unknown drco
	copy(buf[24:28], GConfig.ServerIP[:]) // Server IP
	buf[28] = UknCode_1
	if UknCode_2 >= 128 {
		buf[29] = UknCode_2<<1 | 1
	} else {
		buf[29] = UknCode_2 << 1
	}
	copy(buf[30:34], GConfig.ClientIP[:])
	buf[34] = 0x01
	if UknCode_3%2 == 0 {
		buf[35] = UknCode_3 >> 1
	} else {
		buf[35] = UknCode_3>>1 | 128
	}
	binary.LittleEndian.PutUint16(buf[36:38], uint16(time.Now().Unix()))
	udpConn.Write(buf[:])
}

// send auth info to the authenticator
// packet 286 bytes: Misc, Info usesrname, host
func sendAuthInfo(data []byte) {
	user_name := "201330620" // 长度可变，需要修改

	var dr DRCOM

	dr.Code = DrCodeMisc // code

	var buf []byte
	// append to content
	buf = append(buf, 0x01)          // Count what?
	buf = append([]byte{0xf4, 0x00}) // Info username, hostname
	copy(buf[:], []byte(user_name))
	copy(buf[:], []byte("１３９Yui-miao"))
	// add more
	dr.TypeData = buf
	udpConn.Write(dr.Contents)
}

/* 信息包校验码计算 */
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
	fmt.Println(v6 * 19680126)
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
