package ip

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/rykth/tcp-ip-stack/pkg/ethernet"
	netpkg "github.com/rykth/tcp-ip-stack/pkg/net"
)

var ErrDuplicateProto = errors.New("ip: upper-layer protocol already registered")

// UpperHandler processes reassembled datagrams for a single IP protocol
type UpperHandler interface {
	Protocol() Protocol
	Deliver(src, dst [4]byte, payload []byte)
}

// ARPResolver maps IPv4 addresses to Ethernet MAC addresses
type ARPResolver interface {
	Resolve(ctx context.Context, ip [4]byte) (ethernet.Addr, error)
}

// Handler implements net.ProtocolHandler for EtherTypeIPv4
type Handler struct {
	localMAC    ethernet.Addr
	localIP     [4]byte
	arp         ARPResolver
	table       *Table
	reassembler *Reassembler
	rxCh        chan netpkg.Frame

	mu     sync.RWMutex
	uppers map[Protocol]UpperHandler

	nextID atomic.Uint32 // auto-incrementing datagram ID
}

type HandlerOption func(*Handler)

// WithReassembler replaces the default Reassembler (useful for tests)
func WithReassembler(ra *Reassembler) HandlerOption {
	return func(h *Handler) {
		h.reassembler = ra
	}
}

// NewHandler returns a new Handler for the given local interface
func NewHandler(localMAC ethernet.Addr, localIP [4]byte, arp ARPResolver, table *Table, opts ...HandlerOption) *Handler {
	h := &Handler{
		localMAC:    localMAC,
		localIP:     localIP,
		arp:         arp,
		table:       table,
		reassembler: NewReassembler(),
		rxCh:        make(chan netpkg.Frame, 64),
		uppers:      make(map[Protocol]UpperHandler),
	}
	for _, o := range opts {
		o(h)
	}
	return h
}

// EtherType satisfies net.ProtocolHandler
func (h *Handler) EtherType() ethernet.EtherType {
	return ethernet.EtherTypeIPv4
}

// RxChan satisfies net.ProtocolHandler
func (h *Handler) RxChan() chan netpkg.Frame {
	return h.rxCh
}

// RegisterUpper registers an UpperHandler (must be called before Start)
func (h *Handler) RegisterUpper(u UpperHandler) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.uppers[u.Protocol()]; exists {
		return ErrDuplicateProto
	}
	h.uppers[u.Protocol()] = u
	return nil
}

// Start runs the handler's event loop
func (h *Handler) Start(ctx context.Context, errCh chan<- error) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.reassembler.Start(ctx)
	}()
	defer wg.Wait()

	for {
		select {
		case <-ctx.Done():
			return
		case frame, ok := <-h.rxCh:
			if !ok {
				return
			}
			h.process(frame)
		}
	}
}

func (h *Handler) process(frame netpkg.Frame) {
	hdr, err := Parse(frame.Payload)
	if err != nil {
		return // drop malformed or non-IPv4 frames
	}

	payload := Payload(frame.Payload, hdr)

	// fragmentation
	if hdr.Flags&FlagMF != 0 || hdr.FragOffset > 0 {
		var complete bool
		payload, complete = h.reassembler.Add(hdr, payload)
		if !complete {
			return
		}
	} else {
		// non-fragmented(copy so the caller can reuse the frame buffer)
		cp := make([]byte, len(payload))
		copy(cp, payload)
		payload = cp
	}

	h.mu.RLock()
	upper, ok := h.uppers[hdr.Protocol]
	h.mu.RUnlock()
	if !ok {
		return // no handler for this protocol
	}
	upper.Deliver(hdr.Src, hdr.Dst, payload)
}

// Send transmits a datagram to dst
func (h *Handler) Send(ctx context.Context, dst [4]byte, proto Protocol, payload []byte) error {
	route, err := h.table.Lookup(dst)
	if err != nil {
		return fmt.Errorf("ip: send to %v: %w", dst, err)
	}

	// resolve next-hop(use gateway if set, otherwise dst is on-link)
	nextHop := dst
	if route.Gateway != ([4]byte{}) {
		nextHop = route.Gateway
	}

	dstMAC, err := h.arp.Resolve(ctx, nextHop)
	if err != nil {
		return fmt.Errorf("ip: ARP resolve %v: %w", nextHop, err)
	}

	mtu := route.Dev.MTU()
	// maxPayload must be a multiple of 8 so non-last fragment offsets align
	maxPayload := (mtu - MinHeaderLen) / 8 * 8

	id := uint16(h.nextID.Add(1))

	if len(payload) <= maxPayload || maxPayload <= 0 {
		// single datagram(no fragmentation)
		return h.sendDatagram(route.Dev, dstMAC, id, dst, proto, 0, 0, payload)
	}

	// fragmentation required
	offset := 0
	for offset < len(payload) {
		chunkSize := maxPayload
		if remaining := len(payload) - offset; remaining < chunkSize {
			chunkSize = remaining
		}
		chunk := payload[offset : offset+chunkSize]

		var flags uint8
		if offset+chunkSize < len(payload) {
			flags = FlagMF
		}
		fragOffset := uint16(offset / 8)

		if err := h.sendDatagram(route.Dev, dstMAC, id, dst, proto, flags, fragOffset, chunk); err != nil {
			return err
		}
		offset += chunkSize
	}
	return nil
}

// sendDatagram constructs and transmits a single IP datagram (possibly a fragment).
func (h *Handler) sendDatagram(dev netpkg.LinkDevice, dstMAC ethernet.Addr, id uint16, dst [4]byte, proto Protocol, flags uint8, fragOffset uint16, payload []byte) error {
	hdr := Header{
		Version:    4,
		IHL:        MinHeaderLen / 4,
		TOS:        0,
		TotalLen:   uint16(MinHeaderLen + len(payload)),
		ID:         id,
		Flags:      flags,
		FragOffset: fragOffset,
		TTL:        64,
		Protocol:   proto,
		Src:        h.localIP,
		Dst:        dst,
	}

	frameLen := ethernet.HeaderLen + MinHeaderLen + len(payload)
	buf := make([]byte, frameLen)

	if err := Marshal(buf[ethernet.HeaderLen:], hdr, payload); err != nil {
		return fmt.Errorf("ip: marshal: %w", err)
	}

	ethHdr := ethernet.Header{
		Dst:       dstMAC,
		Src:       h.localMAC,
		EtherType: ethernet.EtherTypeIPv4,
	}
	// ethernet payload is already in buf[14:] (Marshal copies it in-place)
	if _, err := ethernet.Marshal(buf, ethHdr, buf[ethernet.HeaderLen:]); err != nil {
		return fmt.Errorf("ip: ethernet marshal: %w", err)
	}
	_, err := dev.Write(buf)
	return err
}
