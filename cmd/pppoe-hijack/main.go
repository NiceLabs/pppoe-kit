package main

import (
	"flag"
	"github.com/NiceLabs/pppoe-kit/pppoe"
	"log"
)

var device string

func init() {
	flag.StringVar(&device, "device", "eth0", "specified network devices")
	flag.Parse()
}

func main() {
	log.Fatalln(pppoe.Hijack(device, onCredentials))
}

func onCredentials(credentials *pppoe.PAPCredentials) {
	log.Println(credentials)
}
