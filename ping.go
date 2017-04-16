package main

import (
	"encoding/binary"
	"log"
	"math/rand"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Method1. Invoke system ping tool to check network

var LATENCY_PATTERN *regexp.Regexp = regexp.MustCompile(`=(.*) *ms`)

// This works for both mac and linux output, not sure if for windows too...
func parseResults(cmd *exec.Cmd, address string, pattern *regexp.Regexp) bool {
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("event='ping_cmd_error' addresss='%s' error='%s'\n", address, err)
	}
	if len(output) > 0 {
		for _, line := range strings.Split(string(output), "\n") {
			if matches := pattern.FindStringSubmatch(line); matches != nil && len(matches) >= 2 {
				log.Printf("event='ping_latency'  addresss='%s' latency_ms='%s'\n", address, strings.TrimSpace(matches[1]))
				return true
			}
		}
	}
	// guess we never found a ping latency in our response data
	log.Printf("event='missed_ping_latency' addresss='%s'\n", address)
	return false
}

// Method2. Use ubuntu ntp time service to check network
//  ntpTime provides a simple mechanism for querying the current time from
// a remote NTP server. See RFC 5905. Approach inspired by go-nuts post by
// Michael Hofmann:
//
// https://groups.google.com/forum/?fromgroups#!topic/golang-nuts/FlcdMU5fkLQ
type mode uint8

const (
	reserved mode = 0 + iota
	symmetricActive
	symmetricPassive
	client
	server
	broadcast
	controlMessage
	reservedPrivate
)

const (
	maxStratum = 16
	nanoPerSec = 1000000000
)

var (
	timeout  = 5 * time.Second
	ntpEpoch = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
)

// An ntpTime is a 64-bit fixed-point (Q32.32) representation of the number of
// seconds elapsed since the NTP epoch.
type ntpTime uint64

// Duration interprets the fixed-point ntpTime as a number of elapsed seconds
// and returns the corresponding time.Duration value.
func (t ntpTime) Duration() time.Duration {
	sec := (t >> 32) * nanoPerSec
	frac := (t & 0xffffffff) * nanoPerSec >> 32
	return time.Duration(sec + frac)
}

// Time interprets the fixed-point ntpTime as a an absolute time and returns
// the corresponding time.Time value.
func (t ntpTime) Time() time.Time {
	return ntpEpoch.Add(t.Duration())
}

// toNtpTime converts the time.Time value t into its 64-bit fixed-point
// ntpTime representation.
func toNtpTime(t time.Time) ntpTime {
	nsec := uint64(t.Sub(ntpEpoch))
	sec := nsec / nanoPerSec
	frac := (nsec - sec*nanoPerSec) << 32 / nanoPerSec
	return ntpTime(sec<<32 | frac)
}

// An ntpTimeShort is a 32-bit fixed-point (Q16.16) representation of the
// number of seconds elapsed since the NTP epoch.
type ntpTimeShort uint32

// Duration interprets the fixed-point ntpTimeShort as a number of elapsed
// seconds and returns the corresponding time.Duration value.
func (t ntpTimeShort) Duration() time.Duration {
	sec := (t >> 16) * nanoPerSec
	frac := (t & 0xffff) * nanoPerSec >> 16
	return time.Duration(sec + frac)
}

// msg is an internal representation of an NTP packet.
type msg struct {
	LiVnMode       uint8 // Leap Indicator (2) + Version (3) + Mode (3)
	Stratum        uint8
	Poll           int8
	Precision      int8
	RootDelay      ntpTimeShort
	RootDispersion ntpTimeShort
	ReferenceID    uint32
	ReferenceTime  ntpTime
	OriginTime     ntpTime
	ReceiveTime    ntpTime
	TransmitTime   ntpTime
}

// setVersion sets the NTP protocol version on the message.
func (m *msg) setVersion(v int) {
	m.LiVnMode = (m.LiVnMode & 0xc7) | uint8(v)<<3
}

// setMode sets the NTP protocol mode on the message.
func (m *msg) setMode(md mode) {
	m.LiVnMode = (m.LiVnMode & 0xf8) | uint8(md)
}

// A Response contains time data, some of which is returned by the NTP server
// and some of which is calculated by the client.
type Response struct {
	Time           time.Time     // receive time reported by the server
	RTT            time.Duration // round-trip time between client and server
	ClockOffset    time.Duration // local clock offset relative to server
	Poll           time.Duration // maximum polling interval
	Precision      time.Duration // precision of server's system clock
	Stratum        uint8         // stratum level of NTP server's clock
	ReferenceID    uint32        // server's reference ID
	RootDelay      time.Duration // server's RTT to the reference clock
	RootDispersion time.Duration // server's dispersion to the reference clock
	Leap           uint8         // server's leap second indicator; see RFC 5905
}

// getTime returns the "receive time" from the remote NTP server host.
func getTime(host string, version int) (*msg, error) {
	if version < 2 || version > 4 {
		panic("ntp: invalid version number")
	}

	raddr, err := net.ResolveUDPAddr("udp", host+":123")
	if err != nil {
		return nil, err
	}

	con, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	defer con.Close()
	con.SetDeadline(time.Now().Add(timeout))

	m := new(msg)
	m.setMode(client)
	m.setVersion(version)
	m.TransmitTime = toNtpTime(time.Now())

	err = binary.Write(con, binary.BigEndian, m)
	if err != nil {
		return nil, err
	}

	err = binary.Read(con, binary.BigEndian, m)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// TimeV returns the current time from the remote server host using the
// requested version of the NTP protocol. The version may be 2, 3, or 4;
// although 4 is most typically used.
func TimeV(host string, version int) (time.Time, error) {
	m, err := getTime(host, version)
	if err != nil {
		return time.Now(), err
	}
	return m.ReceiveTime.Time().Local(), nil
}

func checkNTP() bool {
	host := string(rand.Intn(4)) + ".pool.ntp.org"
	tm, err := TimeV(host, 4)
	if err != nil {
		log.Println(err)
		return false
	}
	log.Println("NTP Time", tm)
	return true
}
