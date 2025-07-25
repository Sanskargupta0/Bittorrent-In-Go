package utils

import (
	"fmt"
	"net"
	"encoding/binary"
)

// GetPeerId returns a fixed peer ID for this client
func GetPeerId() string {
	return "00112233445566778899"
}

// DecodePeers decodes the compact peer format from tracker response
func DecodePeers(data []byte) ([]string, error) {
	if len(data)%6 != 0 {
		return nil, fmt.Errorf("invalid peers data length")
	}
	
	var peers []string
	for i := 0; i < len(data); i += 6 {
		ip := fmt.Sprintf("%d.%d.%d.%d", data[i], data[i+1], data[i+2], data[i+3])
		port := binary.BigEndian.Uint16(data[i+4:i+6])
		peers = append(peers, fmt.Sprintf("%s:%d", ip, port))
	}
	
	return peers, nil
}

// MakeConnection establishes a TCP connection to the given peer
func MakeConnection(peerAddress string) (net.Conn, error) {
	conn, err := net.Dial("tcp", peerAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to peer %s: %v", peerAddress, err)
	}
	return conn, nil
}
