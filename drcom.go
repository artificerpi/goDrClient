package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

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
)

var counter byte

// Dr.com 2011
type Drcom struct {
	// Contents is the set of bytes that make up this layer.
	Contents []byte
	Code     DrCode
}

func (dr *Drcom) Bytes() []byte {
	var packet []byte
	packet = append(packet, byte(dr.Code))
	packet = append(dr.Contents)
	return packet
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

/* 40字节心跳包校验码计算 */
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

func sendPingStart() {
	udpConn.Write([]byte{0x07, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00})
}

/* 两种心跳包循环发送 */
func pingCycle() {
	time.Sleep(1 * time.Second)
	for {
		sendPing40(1)
		time.Sleep(10 * time.Second)
		sendPing38()
		time.Sleep(5 * time.Second)
	}
}

// 40字节心跳包发送
func sendPing40(step byte) {
	var buf [40]byte
	buf[0] = byte(DrCodeMisc)
	buf[1] = counter
	buf[2] = 0x28
	buf[4] = 0x0b
	buf[5] = step
	copy(buf[6:10], []byte{0xdc, 0x02, 0x6c, 0x6f})
	if step == 3 {
		copy(buf[28:32], clientip[:])
		putCode2(buf[:])
	}
	counter = counter + 1
	udpConn.Write(buf[:])
}

/* 38字节心跳包发送 */
func sendPing38() {
	var buf [38]byte
	buf[0] = byte(DrCodeAlive)
	copy(buf[1:5], globalCheck[:])
	copy(buf[5:17], challenge[4:16])
	copy(buf[20:24], "Drco")
	copy(buf[24:28], serverip[:])
	buf[28] = UknCode_1
	if UknCode_2 >= 128 {
		buf[29] = UknCode_2<<1 | 1
	} else {
		buf[29] = UknCode_2 << 1
	}
	copy(buf[30:34], clientip[:])
	buf[34] = 0x01
	if UknCode_3%2 == 0 {
		buf[35] = UknCode_3 >> 1
	} else {
		buf[35] = UknCode_3>>1 | 128
	}
	binary.LittleEndian.PutUint16(buf[36:38], uint16(time.Now().Unix()))
	udpConn.Write(buf[:])
}

// send info to the authenticator
// packet 286 bytes: Misc, Info usesrname, host
func sendPingInfo(data []byte) {
	user_name := "201330620" // 长度可变，需要修改

	var dr Drcom

	dr.Code = DrCodeMisc // code

	var buf []byte
	// append to content
	buf = append(buf, 0x01)          // Count what?
	buf = append([]byte{0xf4, 0x00}) // Info username, hostname
	copy(buf[:], []byte(user_name))
	copy(buf[:], []byte("１３９Yui-miao"))
	// add more
	dr.Contents = buf
	udpConn.Write(dr.Bytes())
}

/* 接收服务器的UDP回应 */
func recvPing() {
	data := [4096]byte{}
	for {
		n, _, err := udpConn.ReadFromUDP(data[0:])
		if err != nil {
			fmt.Println(err)
		}
		if n > 0 {
			if data[0] == 0x07 { //应答包
				if data[2] == 0x10 && n == 32 { //第一次应答
					sendPingInfo(data[8:12]) //发送用户信息包
				} else if data[2] == 0x30 { //第二次应答
					UknCode_1 = data[24]
					UknCode_2 = data[25]
					UknCode_3 = data[31]
					go pingCycle() //发送Ping-1
				} else if data[2] == 0x28 { //Ping应答
					if data[5] == 0x02 { //收到Ping-2
						sendPing40(3) //发送Ping-3
					}
				}
			}
		}
	}
}
