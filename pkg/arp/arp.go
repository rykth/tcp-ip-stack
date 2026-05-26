package arp

import (
	"encoding/binary"
	"errors"

	"github.com/rykth/tcp-ip-stack/pkg/ethernet"
)

// wire constants for Ethernet/IPv4 ARP (RFC 826)
const (
	hwTypeEthernet uint16 = 1
	protoTypeIPv4  uint16 = 0x0800
	hwAddrLen      uint8  = 6
	protoAddrLen   uint8  = 4

	// fixed byte length of an Ethernet/IPv4 ARP packet
	PacketLen = 28
)

var (
	ErrPacketTooShort          = errors.New("arp: packet too short")
	ErrUnsupportedHardwareType = errors.New("arp: unsupported hardware type (want Ethernet)")
	ErrUnsupportedProtocolType = errors.New("arp: unsupported protocol type (want IPv4)")
)

// Operation identifies whether an ARP packet is a request or a reply
type Operation uint16

const (
	OperationRequest Operation = 1
	OperationReply   Operation = 2
)

// Packet is a parsed ARP packet for Ethernet/IPv4 (the only combination this
// stack supports)
type Packet struct {
	Operation Operation
	SenderMAC ethernet.Addr
	SenderIP  [4]byte
	TargetMAC ethernet.Addr
	TargetIP  [4]byte
}

// Parse decodes an ARP packet
func Parse(b []byte) (Packet, error) {
	if len(b) < PacketLen {
		return Packet{}, ErrPacketTooShort
	}

	if binary.BigEndian.Uint16(b[0:2]) != hwTypeEthernet {
		return Packet{}, ErrUnsupportedHardwareType
	}

	if binary.BigEndian.Uint16(b[2:4]) != protoTypeIPv4 {
		return Packet{}, ErrUnsupportedProtocolType
	}

	// b[4] = hw addr len (6)
	// b[5] = proto addr len (4)

	var p Packet
	p.Operation = Operation(binary.BigEndian.Uint16(b[6:8]))
	copy(p.SenderMAC[:], b[8:14])
	copy(p.SenderIP[:], b[14:18])
	copy(p.TargetMAC[:], b[18:24])
	copy(p.TargetIP[:], b[24:28])
	return p, nil
}

// Marshal encodes p into dst
func Marshal(dst []byte, p Packet) error {
	if len(dst) < PacketLen {
		return ErrPacketTooShort
	}
	binary.BigEndian.PutUint16(dst[0:2], hwTypeEthernet)
	binary.BigEndian.PutUint16(dst[2:4], protoTypeIPv4)
	dst[4] = hwAddrLen
	dst[5] = protoAddrLen
	binary.BigEndian.PutUint16(dst[6:8], uint16(p.Operation))
	copy(dst[8:14], p.SenderMAC[:])
	copy(dst[14:18], p.SenderIP[:])
	copy(dst[18:24], p.TargetMAC[:])
	copy(dst[24:28], p.TargetIP[:])
	return nil
}
