package icmp

import (
	"encoding/binary"
	"errors"

	"github.com/rykth/tcp-ip-stack/pkg/ip"
)

// HeaderLen is the fixed byte length of an ICMP header (Type + Code + Checksum
// + Identifier + Sequence Number)
const HeaderLen = 8

var (
	ErrPacketTooShort = errors.New("icmp: packet too short")
	ErrBadChecksum    = errors.New("icmp: bad checksum")
)

type Type uint8

const (
	TypeEchoReply   Type = 0
	TypeEchoRequest Type = 8
)

// Packet is a parsed ICMP echo request or reply
type Packet struct {
	Type     Type
	Code     uint8
	Checksum uint16
	ID       uint16
	Seq      uint16
	Data     []byte
}

// Parse decodes an ICMP packet
func Parse(b []byte) (Packet, error) {
	if len(b) < HeaderLen {
		return Packet{}, ErrPacketTooShort
	}

	// checksum covers the full ICMP message (header + data)
	if ip.Checksum(b) != 0 {
		return Packet{}, ErrBadChecksum
	}

	var p Packet
	p.Type = Type(b[0])
	p.Code = b[1]
	p.Checksum = binary.BigEndian.Uint16(b[2:4])
	p.ID = binary.BigEndian.Uint16(b[4:6])
	p.Seq = binary.BigEndian.Uint16(b[6:8])
	if len(b) > HeaderLen {
		p.Data = make([]byte, len(b)-HeaderLen)
		copy(p.Data, b[HeaderLen:])
	}
	return p, nil
}

// Marshal encodes p into dst and returns the number of bytes written
func Marshal(dst []byte, p Packet) (int, error) {
	need := HeaderLen + len(p.Data)
	if len(dst) < need {
		return 0, ErrPacketTooShort
	}

	dst[0] = uint8(p.Type)
	dst[1] = p.Code
	dst[2], dst[3] = 0, 0 // zero before checksum computation
	binary.BigEndian.PutUint16(dst[4:6], p.ID)
	binary.BigEndian.PutUint16(dst[6:8], p.Seq)
	copy(dst[8:], p.Data)
	check := ip.Checksum(dst[:need])
	binary.BigEndian.PutUint16(dst[2:4], check)

	return need, nil
}
