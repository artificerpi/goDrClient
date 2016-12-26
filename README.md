# gofsnet 
  A simple project to learn IEEE 802.1X protocol and drcom protocol (version: 5.2.x) with golang.

- [中文](https://github.com/artificerpi/gofsnet/blob/master/README-zh.md)

## Test it 
* This project is using gopacket packages, so if you want to build it, you should make sure you have  done following things before start.

Install the prerequisites. You will need go, libpcap and the gopacket package. Since gopacket is built on top of libpcap, I highly recommend you understand how that library works. You can learn how to use libpcap in C for a deeper understanding. These examples should work in Linux/Mac using libpcap and on Windows with WinPcap. You may need to set GOARCH=386 if you get an error like cc1.exe: sorry, unimplemented: 64-bit mode not compiled in.

```bash
	# Get the gopacket package from GitHub
	go get github.com/google/gopacket
	# Pcap dev headers might be necessary
	sudo apt-get install libpcap-dev
```

You might also want to check out the [gopacket project on GitHub](https://github.com/google/gopacket) and documentation on [GoDoc gopacket](https://godoc.org/github.com/google/gopacket).

Currently there is a [problem to decode EAP packet](https://github.com/google/gopacket/issues/249), you may need replace the eapol.go with this [one](https://github.com/artificerpi/gopacket/blob/master/layers/eapol.go). 

There is also a [wiki about how to build it](https://github.com/artificerpi/gofsnet/wiki/Build-this-project).



## Reference
* [Understanding 802.1X](https://sites.google.com/site/amitsciscozone/home/switching/802-1x)
* [Blog of cuberl](http://cuberl.com/2016/09/17/make-a-drcom-client-by-yourself/)



## Inspiration & Ideas
* [fsn_server By @YSunLIN](https://github.com/YSunLIN/fsn_server) A c version of drcom client.
* [pyscutclient_drcom by @7forz](https://github.com/scutclient/pyscutclient_drcom) A python version of drcom client.

## Warning
This project is only for learn and test, you should not apply it for any illegal usage.

## LICENSE
[GNU GENERAL PUBLIC LICENSE](https://www.gnu.org/licenses/gpl-3.0.en.html)
