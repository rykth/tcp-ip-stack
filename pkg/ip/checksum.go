package ip

import "encoding/binary"

// Checksum computes the RFC 1071 ones'-complement checksum over b.
//
// When generating a header checksum, zero the checksum field before calling.
// When verifying, include the checksum field as-is: a return value of 0 means
// the packet is valid
func Checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	// if b has an odd number of bytes, pad the last byte with a zero on the right
	if len(b)%2 != 0 {
		sum += uint32(b[len(b)-1]) << 8
	}
	// fold 32-bit sum to 16 bits: add carries until no more carry
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// Add16 combines two ones'-complement 16-bit checksums.
//
// Use this when the checksum must span discontiguous data.  For example, the
// TCP and UDP checksum covers both the IPv4 pseudo-header and the L4 segment,
// which are not stored contiguously in memory:
//
//	pseudo := ip.PseudoHeaderChecksum(src, dst, proto, l4Len)
//	l4     := ip.Checksum(l4Segment) // with checksum field zeroed
//	h.Checksum = ip.Add16(pseudo, l4)
//
// Mathematical property: Add16(Checksum(A), Checksum(B)) == Checksum(A||B)
// where A||B is A concatenated with B (assuming even total length).
func Add16(a, b uint16) uint16 {
	sum := uint32(a) + uint32(b)
	if sum > 0xFFFF {
		sum++ // ones'-complement carry
	}
	return uint16(sum)
}

// PseudoHeaderChecksum computes the ones'-complement checksum of the 12-byte
// IPv4 TCP/UDP pseudo-header defined in RFC 793 §3.1 and RFC 768 §Format.
//
// Combine with the L4 segment checksum using Add16 to produce the final
// transport-layer checksum (see Add16 documentation for the full pattern).
func PseudoHeaderChecksum(src, dst [4]byte, proto Protocol, l4Len uint16) uint16 {
	var b [12]byte
	copy(b[0:4], src[:])
	copy(b[4:8], dst[:])
	b[8] = 0 // zero byte
	b[9] = uint8(proto)
	binary.BigEndian.PutUint16(b[10:12], l4Len)
	return Checksum(b[:])
}
