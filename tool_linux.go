package main

// +build linux,386 darwin,!cgo
import (
	"errors"
	"os/exec"
	"strconv"
)

// get device adapter in windows
func getDeviceAdapterName(Index int) (string, error) {
	err := errors.New("You can not use the method while not on windows")
	return "", err
}

func ping(address string, timeoutSec int) bool {
	// -c 1 --> send one packet -w <sec> deadline/timeout in seconds before giving up
	cmd := exec.Command("ping", "-c", "1", "-w", strconv.Itoa(timeoutSec), address)
	return parseResults(cmd, address, LATENCY_PATTERN)
}
