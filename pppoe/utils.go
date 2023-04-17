package pppoe

import "encoding/binary"

func getHostUniq(payload []byte) []byte {
	hostUniqIndex := 0
	for i := 0; i < len(payload)-1; i++ {
		if payload[i] == 0x01 && payload[i+1] == 0x03 {
			hostUniqIndex = i
			break
		}
	}
	hostUniqLengthIndex := hostUniqIndex + 2
	length := binary.BigEndian.Uint16(payload[hostUniqLengthIndex : hostUniqLengthIndex+2])
	return payload[hostUniqIndex : hostUniqLengthIndex+2+int(length)]
}
