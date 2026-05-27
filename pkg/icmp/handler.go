package icmp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rykth/tcp-ip-stack/pkg/ip"
)

var ErrPingTimeout = errors.New("icmp: ping timed out")

// Sender transmits IPv4 datagrams
type Sender interface {
	Send(ctx context.Context, dst [4]byte, proto ip.Protocol, payload []byte) error
}

// Handler implements ip.UpperHandler for ProtocolICMP
type Handler struct {
	sender Sender
	nextID atomic.Uint32

	mu      sync.Mutex
	pending map[uint16]chan time.Time // ID => channel that receives reply arrival time
}

// NewHandler returns a Handler that sends outgoing ICMP
func NewHandler(sender Sender) *Handler {
	return &Handler{
		sender:  sender,
		pending: make(map[uint16]chan time.Time),
	}
}

// Protocol satisfies ip.UpperHandler
func (h *Handler) Protocol() ip.Protocol { return ip.ProtocolICMP }

// Deliver is called by ip.Handler's event loop with reassembled ICMP payloads.
func (h *Handler) Deliver(src, dst [4]byte, payload []byte) {
	p, err := Parse(payload)
	if err != nil {
		return // drop malformed packets silently
	}

	switch p.Type {
	case TypeEchoRequest:
		// build and send a reply without blocking the caller's goroutine
		go h.sendReply(src, p)

	case TypeEchoReply:
		h.mu.Lock()
		ch, ok := h.pending[p.ID]
		h.mu.Unlock()
		if ok {
			// Non-blocking: channel has capacity 1; if full the reply is a duplicate.
			select {
			case ch <- time.Now():
			default:
			}
		}
	}
}

// Ping sends one ICMP echo request to dst and returns the round-trip time
func (h *Handler) Ping(ctx context.Context, dst [4]byte) (time.Duration, error) {
	id := uint16(h.nextID.Add(1))

	// register the channel before sending to prevent a race where the reply
	// arrives before we've registered
	ch := make(chan time.Time, 1)
	h.mu.Lock()
	h.pending[id] = ch
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.pending, id)
		h.mu.Unlock()
	}()

	// embed the send timestamp in the echo data so the receiver can measure RTT
	// independently, and so this function can verify data integrity
	var data [8]byte
	sent := time.Now()
	binary.BigEndian.PutUint64(data[:], uint64(sent.UnixNano()))

	pkt := Packet{
		Type: TypeEchoRequest,
		ID:   id,
		Seq:  0,
		Data: data[:],
	}

	buf := make([]byte, HeaderLen+len(pkt.Data))
	if _, err := Marshal(buf, pkt); err != nil {
		return 0, fmt.Errorf("icmp: marshal echo request: %w", err)
	}

	if err := h.sender.Send(ctx, dst, ip.ProtocolICMP, buf); err != nil {
		return 0, fmt.Errorf("icmp: send echo request: %w", err)
	}

	select {
	case received := <-ch:
		return received.Sub(sent), nil
	case <-ctx.Done():
		return 0, ErrPingTimeout
	}
}

func (h *Handler) sendReply(dst [4]byte, req Packet) {
	reply := Packet{
		Type: TypeEchoReply,
		Code: 0,
		ID:   req.ID,
		Seq:  req.Seq,
		Data: req.Data,
	}
	buf := make([]byte, HeaderLen+len(reply.Data))
	if _, err := Marshal(buf, reply); err != nil {
		return
	}

	h.sender.Send(context.Background(), dst, ip.ProtocolICMP, buf) //nolint:errcheck
}
