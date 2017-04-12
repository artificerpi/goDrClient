package main

import (
	"flag"
	"log"
	"time"

	"github.com/kardianos/service"
)

var done chan bool = make(chan bool) // exist for supporting runing in background

func init() {
	log.Println(AppName, Version, "-- go version Drcom client by artificerpi")
	log.Println("Project url:", Project)
}

var logger service.Logger

// Program structures.
//  Define Start and Stop methods.
type program struct {
	exit chan struct{}
}

func (p *program) Start(s service.Service) error {
	if service.Interactive() {
		logger.Info("Running in terminal.")
	} else {
		logger.Info("Running under service manager.")
	}
	p.exit = make(chan struct{})

	// Start should not block. Do the actual work async.
	go p.run()
	return nil
}
func (p *program) run() error {
	logger.Infof("I'm running %v.", service.Platform())
	ticker := time.NewTicker(20 * time.Second)
	go run()
	for {
		select {
		case tm := <-ticker.C:
			logger.Infof("Still running at %v...", tm)
			if checkNetwork() {
				log.Println("ok")
			} else {
				setState(-1)
				log.Println("detected network offline, restarting...........")
				err := handle.WritePacketData([]byte(AppName)) // test network device
				if err != nil {
					log.Println("detected error", err)
					go run()
				} else {
					relogin(5)
				}

			}
		case <-p.exit:
			ticker.Stop()
			return nil
		}
	}
}

func (p *program) Stop(s service.Service) error {
	// Any work in Stop should be quick, usually a few seconds at most.
	logger.Info("I'm Stopping!")
	close(p.exit)
	return nil
}

func main() {
	var configFile string
	flag.StringVar(&configFile, "c", "config.ini", "specify config file")
	svcFlag := flag.String("service", "", "Control the system service.")
	flag.Parse()
	loadConfig(configFile) // load configuration file

	svcConfig := &service.Config{
		Name:        "GoServiceExampleLogging",
		DisplayName: "Go Service Example for Logging",
		Description: "This is an example Go service that outputs log messages.",
	}

	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}
	errs := make(chan error, 5)
	logger, err = s.Logger(errs)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			err := <-errs
			if err != nil {
				log.Print(err)
			}
		}
	}()

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
		logger.Error(err)
	}
}
