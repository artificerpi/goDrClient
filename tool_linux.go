package main

// +build linux,386 darwin,!cgo
import "errors"

// get device adapter in windows
func getDeviceAdapterName(Index int) (string, error) {
	err := errors.New("You can not use the method while not on windows")
	return "", err
}

func showSysTray() {
	// exists only for compile
}
