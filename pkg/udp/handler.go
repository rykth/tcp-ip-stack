package udp

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/rykth/tcp-ip-stack/pkg/ip"
)

var (
	ErrPortInUse       = errors.New("udp: port already in use")
	ErrNoEphemeralPort = errors.New("udp: ephemeral port range exhausted")
)

const (
	minEphemeralPort = uint16(40000)
	maxEphemeralPort = uint16(65535)
	ephemeralRange   = uint32(maxEphemeralPort) - uint32(minEphemeralPort) + 1
)

// Sender transmits IPv4 datagrams
type Sender interface {
	Send(ctx context.Context, dst [4]byte, proto ip.Protocol, payload []byte) error
}

// Handler implements ip.UpperHandler for ProtocolUDP
type Handler struct {
	sender  Sender
	localIP [4]byte

	mu      sync.RWMutex
	conns   map[uint16]*Conn
	nextEph uint32
}

// NewHandler returns a UDP handler that sends outgoing datagrams via sender
func NewHandler(sender Sender, localIP [4]byte) *Handler {
	return &Handler{
		sender:  sender,
		localIP: localIP,
		conns:   make(map[uint16]*Conn),
	}
}

// Protocol satisfies ip.UpperHandler.
func (h *Handler) Protocol() ip.Protocol {
	return ip.ProtocolUDP
}

// Deliver satisfies ip.UpperHandler and it's called by ip.Handler with
// reassembled UDP payloads. Malformed frames and checksum errors are silently
// dropped
func (h *Handler) Deliver(src, dst [4]byte, payload []byte) {
	hdr, err := Parse(payload)
	if err != nil {
		return
	}
	data := Payload(payload)

	if hdr.Checksum != 0 {
		if ComputeChecksum(src, dst, hdr, data) != hdr.Checksum {
			return // bad checksum(drop silently)
		}
	}

	h.mu.RLock()
	conn, ok := h.conns[hdr.DstPort]
	h.mu.RUnlock()
	if !ok {
		return // no listener for this port
	}

	// connected Conns only accept datagrams from their specific remote
	if conn.remote != nil {
		if conn.remote.IP != src || conn.remote.Port != hdr.SrcPort {
			return
		}
	}

	cp := make([]byte, len(data))
	copy(cp, data)
	conn.deliver(Datagram{
		Src:     Addr{IP: src, Port: hdr.SrcPort},
		Dst:     Addr{IP: dst, Port: hdr.DstPort},
		Payload: cp,
	})
}

// Listen creates an unconnected Conn bound to port
func (h *Handler) Listen(port uint16) (*Conn, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.conns[port]; exists {
		return nil, ErrPortInUse
	}
	c := newConn(Addr{IP: h.localIP, Port: port}, nil, h)
	h.conns[port] = c
	return c, nil
}

// Dial creates a connected Conn to remote
func (h *Handler) Dial(_ context.Context, remote Addr) (*Conn, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	port, err := h.allocEphemeralLocked()
	if err != nil {
		return nil, err
	}
	c := newConn(Addr{IP: h.localIP, Port: port}, &remote, h)
	h.conns[port] = c
	return c, nil
}

// allocEphemeralLocked finds an unused port in [40000, 65535].
// Must be called with h.mu held for writing
func (h *Handler) allocEphemeralLocked() (uint16, error) {
	n := h.nextEph
	h.nextEph++
	for i := uint32(0); i < ephemeralRange; i++ {
		port := uint16(uint32(minEphemeralPort) + (n+i)%ephemeralRange)
		if _, exists := h.conns[port]; !exists {
			return port, nil
		}
	}
	return 0, ErrNoEphemeralPort
}

func (h *Handler) deregister(port uint16) {
	h.mu.Lock()
	delete(h.conns, port)
	h.mu.Unlock()
}

func (h *Handler) send(ctx context.Context, src, dst Addr, payload []byte) error {
	length := uint16(HeaderLen + len(payload))
	hdr := Header{
		SrcPort: src.Port,
		DstPort: dst.Port,
		Length:  length,
	}
	hdr.Checksum = ComputeChecksum(src.IP, dst.IP, hdr, payload)

	buf := make([]byte, int(length))
	if err := Marshal(buf, hdr); err != nil {
		return fmt.Errorf("udp: marshal header: %w", err)
	}
	copy(buf[HeaderLen:], payload)

	return h.sender.Send(ctx, dst.IP, ip.ProtocolUDP, buf)
}
