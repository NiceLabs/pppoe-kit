package main

import (
	"encoding/csv"
	"flag"
	"github.com/NiceLabs/pppoe-kit/pppoe"
	"log"
	"os"
)

var device string
var csvOutput bool

func init() {
	flag.StringVar(&device, "device", "eth0", "specified network devices")
	flag.BoolVar(&csvOutput, "csv", false, "CSV format output")
	flag.Parse()
}

func main() {
	var err error
	if csvOutput {
		writer := csv.NewWriter(os.Stdout)
		_ = writer.Write([]string{"timestamp", "peer-id", "password", "mac-address"})
		err = pppoe.Hijack(device, func(c *pppoe.PAPCredentials) {
			_ = writer.Write([]string{c.Timestamp.String(), c.PeerID, c.Password, c.MACAddress.String()})
		})
	} else {
		err = pppoe.Hijack(device, func(c *pppoe.PAPCredentials) { log.Println(c) })
	}
	if err != nil {
		log.Fatalln(err)
	}
}

func onCredentials(credentials *pppoe.PAPCredentials) {
	log.Println(credentials)
}
