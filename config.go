package main

import "log"

const (
	AppName        string = "gofsnet"
	Version        string = "0.0.1"
	ConfigFileName string = "config.ini"
)

var (
	Username string
	Password string

	Device   string
	OSTarget string // windows, linux
)

type Config struct {
}

func init() {
	log.Println("Loading configuration ...")
}
