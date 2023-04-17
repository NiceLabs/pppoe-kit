package pppoe

import (
	"fmt"
	"net"
	"time"
)

type PAPCredentials struct {
	PeerID     string           `json:"peer-id"`
	Password   string           `json:"password"`
	MACAddress net.HardwareAddr `json:"mac-address"`
	Timestamp  time.Time        `json:"timestamp"`
}

func (c *PAPCredentials) String() string {
	return fmt.Sprintf("PeerID=%q, Password=%q, MACAddress=%q", c.PeerID, c.Password, c.MACAddress)
}
