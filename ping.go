package main

import (
	"log"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

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

func pingLinux(address string, timeoutSec int, pattern *regexp.Regexp) bool {
	// -c 1 --> send one packet -w <sec> deadline/timeout in seconds before giving up
	cmd := exec.Command("ping", "-c", "1", "-w", strconv.Itoa(timeoutSec), address)
	return parseResults(cmd, address, pattern)
}

func pingMac(address string, timeoutSec int, pattern *regexp.Regexp) bool {
	// -c 1 --> send one packet -t <sec> timeout in sec before ping exits
	// regardless of packets received
	cmd := exec.Command("ping", "-c", "1", "-t", strconv.Itoa(timeoutSec), address)
	return parseResults(cmd, address, pattern)
}

func pingWindows(address string, timeoutSec int, pattern *regexp.Regexp) bool {
	// -n 1 --> send one packet/echo -w <miliseconds> wait up to this many ms for
	// each reply (only one reply in this case...).  Note the * 1000 since we're
	// configured with seconds and this arg takes miliseconds.
	cmd := exec.Command("ping", "-n", "1", "-w", strconv.Itoa(timeoutSec*1000), address)
	return parseResults(cmd, address, pattern)
}

func ping(address string, timeoutSec int, pattern *regexp.Regexp) bool {
	switch os := runtime.GOOS; os {
	case "darwin":
		return pingMac(address, timeoutSec, pattern)
	case "linux":
		return pingLinux(address, timeoutSec, pattern)
	case "windows":
		return pingWindows(address, timeoutSec, pattern)
	default:
		log.Fatalf("Unsupported OS type: %s.  Can't establish ping cmd args.\n", os)
		return false
	}
}
