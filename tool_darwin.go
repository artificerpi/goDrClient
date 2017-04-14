package main

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
	// -c 1 --> send one packet -t <sec> timeout in sec before ping exits
	// regardless of packets received
	cmd := exec.Command("ping", "-c", "1", "-t", strconv.Itoa(timeoutSec), address)
	return parseResults(cmd, address, LATENCY_PATTERN)
}
