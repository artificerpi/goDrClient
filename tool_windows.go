package main

// +build windows,!cgo
import (
	"errors"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"syscall"
	"systraydemo/systray"
	"time"
	"unsafe"

	"github.com/golang/glog"
)

const (
	TrayMenu1 string = "Reload"
	TrayMenu2 string = "AutoStart"
	TrayMenu3 string = "Quit"

	workingIcon string = "working.ico"
	idleIcon    string = "idle.ico"
	problemIco  string = "problem.ico"

	bootScript string = "autostart.bat"
)

var (
	dataFolder string
	bootEntry  string
)

func init() {
	// Get home dir
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}

	dataFolder = usr.HomeDir + "/AppData/Roaming/" + AppName + "/"
	bootEntry = usr.HomeDir + "/AppData/Roaming/" + "Microsoft/Windows/Start Menu/Programs/Startup/" + AppName + ".lnk"
	loadRes()
}

// get device adapter in windows
func getDeviceAdapterName(Index int) (string, error) {
	if runtime.GOOS != "windows" {
		err := errors.New("You can not use the method while not on windows")
		return "", err
	}
	b := make([]byte, 1000)
	l := uint32(len(b))
	aList := (*syscall.IpAdapterInfo)(unsafe.Pointer(&b[0]))
	// TODO(mikio): GetAdaptersInfo returns IP_ADAPTER_INFO that
	// contains IPv4 address list only. We should use another API
	// for fetching IPv6 stuff from the kernel.
	err := syscall.GetAdaptersInfo(aList, &l)
	if err == syscall.ERROR_BUFFER_OVERFLOW {
		b = make([]byte, l)
		aList = (*syscall.IpAdapterInfo)(unsafe.Pointer(&b[0]))
		err = syscall.GetAdaptersInfo(aList, &l)
	}
	if err != nil {
		return "", os.NewSyscallError("GetAdaptersInfo", err)
	}

	// get right adapter of the device
	for ai := aList; ai != nil; ai = ai.Next {
		if int(ai.Index) == Index {
			return string(ai.AdapterName[:]), nil
		}
	}

	err = errors.New("invalid index as parameter")
	return "", err
}

func loadRes() {
	var isIntact bool = true
	// check whether files are already there; if not,create t
	if _, err := os.Stat(dataFolder); os.IsNotExist(err) {
		// path/to/whatever does not exist
		log.Println("data folder not exists")
		isIntact = false
	}
	if _, err := os.Stat(dataFolder + workingIcon); os.IsNotExist(err) {
		// path/to/whatever does not exist
		log.Println("working icon not exists")
		isIntact = false
	}
	if _, err := os.Stat(dataFolder + idleIcon); os.IsNotExist(err) {
		// path/to/whatever does not exist
		log.Println("idle icon not exists")
		isIntact = false
	}
	if _, err := os.Stat(dataFolder + problemIco); os.IsNotExist(err) {
		// path/to/whatever does not exist
		log.Println("problem icon not exists")
		isIntact = false
	}
	if _, err := os.Stat(dataFolder + "autostart.bat"); os.IsNotExist(err) {
		// path/to/whatever does not exist
		log.Println("autostart script not exists")
		isIntact = false
	}
	if !isIntact {
		// mkdir -p
		err := os.MkdirAll(dataFolder, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
		copyIcons(dataFolder) // generate resource files
	}
}

func copyIcons(dstPath string) {
	working, err := systray.Asset("icons/working.ico")
	if err != nil {
		log.Println(err)
	}
	idle, err := systray.Asset("icons/idle.ico")
	if err != nil {
		log.Println(err)
	}
	problem, err := systray.Asset("icons/problem.ico")
	if err != nil {
		// Asset was not found.
		log.Println("Asset not found!")
	}
	// convert []byte to image for saving to file
	//	img, _, _ := image.Decode(bytes.NewReader(imgByte))
	err = ioutil.WriteFile(dstPath+"working.ico", working, 0644)
	if err != nil {
		log.Println(err)
	}
	err = ioutil.WriteFile(dstPath+"idle.ico", idle, 0644)
	if err != nil {
		log.Println(err)
	}
	err = ioutil.WriteFile(dstPath+"problem.ico", problem, 0644)
	if err != nil {
		log.Println(err)
	}

	cmdScript, err := Asset("autostart.bat")
	if err != nil {
		log.Println(err)
	}
	err = ioutil.WriteFile(dstPath+bootScript, cmdScript, 0755)
	if err != nil {
		log.Println(err)
	}
}

func showSysTray() {
	tray := systray.New(dataFolder, ".")

	//// Set some test menu items
	items := make([]systray.CallbackInfo, 0, 10)
	items = append(items, systray.CallbackInfo{
		ItemName: TrayMenu1,
		Callback: func() {
			//TODO change logo color
			err := tray.Show(idleIcon, "gofsnet=>idle")
			reload()
			// change logo color
			err = tray.Show(workingIcon, AppName)
			if err != nil {
				println(err.Error())
			}

		},
	})

	var trayMenu2Show string
	if EnableAutoStart {
		trayMenu2Show = TrayMenu2 + " *"
	} else {
		trayMenu2Show = TrayMenu2 + " -"
	}
	items = append(items, systray.CallbackInfo{
		ItemName: trayMenu2Show,
		Callback: func() {
			// *AutoStart , -AutoStart
			if EnableAutoStart {
				rmBootEntry()
				items[1].ItemName = TrayMenu2 + " -"
			} else {
				addBootEntry()
				items[1].ItemName = TrayMenu2 + " *"
			}
			// update systray
			tray.ClearSystrayMenuItems()
			tray.AddSystrayMenuItems(items)
		},
	})
	items = append(items, systray.CallbackInfo{
		ItemName: TrayMenu3,
		Callback: func() {
			println("Exiting...")
			os.Exit(0)
		},
	})
	tray.AddSystrayMenuItems(items)

	err := tray.Show(workingIcon, AppName)
	if err != nil {
		glog.Infoln(err.Error())
	}

	runtime.LockOSThread()
	tray.Run()
	runtime.UnlockOSThread()
}

// reload from config file
func reload() {
	loadConfig(ConfigFileName)
	logoff()
	time.Sleep(3 * time.Second)
	startRequest()
	log.Println("reloading from config file...")
}

// make program auto start at os boot
func addBootEntry() {
	// invoke add to boot script
	os.Setenv("GOFSNET_BOOT_ENTRY", bootEntry)
	os.Setenv("GOFSNET_TARGET", os.Args[0])
	err := exec.Command(dataFolder + bootScript).Run()
	if err != nil {
		log.Println(err)
	}
	updateConfigOption(ConfigFileName, "preference", "autostart", "true")
	EnableAutoStart = true
	log.Println("Enable program autostart")
}

func rmBootEntry() {
	if _, err := os.Stat(bootEntry); os.IsNotExist(err) {
		log.Println("rm failed: boot entry not exists")
		return
	}
	// rm add to boot script
	err := os.Remove(bootEntry)
	if err != nil {
		log.Println(err)
	}
	updateConfigOption(ConfigFileName, "preference", "autostart", "false")
	EnableAutoStart = false
	log.Println("Disable program autostart")
}
