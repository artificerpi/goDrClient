package main

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/kardianos/service"
	"github.com/marcsauter/single"
)

var done chan bool = make(chan bool) // exist for supporting runing in background

func init() {
	log.Println(AppName, Version, "-- golang version DRCOM client by artificerpi")
	log.Println("Project URL: ", "https://github.com/artificerpi/gofsnet")
	log.Println("Program is executing...")
}

// Program structures.
//  Define Start and Stop methods.
type program struct {
	exit chan struct{}
}

func (p *program) Start(s service.Service) error {
	if service.Interactive() {
		log.Println("Running in terminal.")
	} else {
		log.Println("Running under service manager.")
	}
	p.exit = make(chan struct{})

	// Start should not block. Do the actual work async.
	go p.run()
	return nil
}
func (p *program) run() error {
	log.Printf("I'm running at %s.", service.Platform())
	ticker := time.NewTicker(30 * time.Second)
	go sniff()
	for {
		select {
		case <-ticker.C:
			checkOnline()
		case <-p.exit:
			ticker.Stop()
			return nil
		}
	}
}

func (p *program) Stop(s service.Service) error {
	// Any work in Stop should be quick, usually a few seconds at most.
	log.Println("I'm Stopping!")
	close(p.exit)
	return nil
}

func main() {
	// only allow one running program instance
	instance := single.New(AppName)
	instance.Lock()
	defer instance.Unlock()

	var configFile string
	flag.StringVar(&configFile, "c", "config.ini", "specify config file")
	svcFlag := flag.String("service", "", "Control the system service.")
	flag.Parse()

	loadConfig(configFile) // load configuration file
	if GConfig.EnableFileLog {
		f, err := os.OpenFile(AppName+".log", os.O_RDWR|os.O_CREATE|os.O_APPEND|os.O_TRUNC, 0644) //TODO
		if err != nil {
			log.Fatalf("Error while opening file: %v", err)
		}
		defer f.Close()
		log.SetOutput(f)
	}
	// if capture packets enabled
	// create only one pcap file of program's startup for each time
	if GConfig.EnableCapture && capturedFile == nil {
		capturedFile, _ = os.Create(AppName + time.Now().Format(time.RFC3339) + ".pcap")
		defer capturedFile.Close()
	}

	svcConfig := &service.Config{
		Name:        "GofsnetService",
		DisplayName: "gofsnet service program",
		Description: "This is the gofsnet service that works as a drcom client.",
	}

	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}
	if len(*svcFlag) != 0 {
		err := service.Control(s, *svcFlag)
		if err != nil {
			log.Printf("Valid actions: %q\n", service.ControlAction)
			log.Fatal(err)
		}
		return
	}

	err = s.Run()
	if err != nil {
		log.Fatal(err)
	}
}
