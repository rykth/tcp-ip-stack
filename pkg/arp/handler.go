package arp

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/rykth/tcp-ip-stack/pkg/ethernet"
	netpkg "github.com/rykth/tcp-ip-stack/pkg/net"
)

var ErrResolveFailed = errors.New("arp: resolve timed out")

// Handler implements net.ProtocolHandler for EtherTypeARP
type Handler struct {
	localMAC ethernet.Addr
	localIP  [4]byte
	dev      netpkg.LinkDevice
	cache    *Cache
	rxCh     chan netpkg.Frame

	mu      sync.Mutex
	pending map[[4]byte][]chan ethernet.Addr // waiters keyed by target IP
}

// HandlerOption configures a Handler
type HandlerOption func(*Handler)

// WithHandlerCache replaces the Handler's ARP cache (useful for injecting a
// pre-seeded cache in tests)
func WithHandlerCache(c *Cache) HandlerOption {
	return func(h *Handler) {
		h.cache = c
	}
}

// NewHandler returns a Handler configured for the given local interface
func NewHandler(localMAC ethernet.Addr, localIP [4]byte, dev netpkg.LinkDevice, opts ...HandlerOption) *Handler {
	h := &Handler{
		localMAC: localMAC,
		localIP:  localIP,
		dev:      dev,
		cache:    NewCache(),
		rxCh:     make(chan netpkg.Frame, 64),
		pending:  make(map[[4]byte][]chan ethernet.Addr),
	}
	for _, o := range opts {
		o(h)
	}
	return h
}

// EtherType satisfies net.ProtocolHandler
func (h *Handler) EtherType() ethernet.EtherType {
	return ethernet.EtherTypeARP
}

// RxChan satisfies net.ProtocolHandler - the Registry writes received ARP
// frames here
func (h *Handler) RxChan() chan netpkg.Frame {
	return h.rxCh
}

// Start runs the handler's event loop until ctx is cancelled
func (h *Handler) Start(ctx context.Context, errCh chan<- error) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.cache.Start(ctx)
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
			if err := h.handle(frame); err != nil {
				// malformed or unsupported packets are silently dropped.
				// they are not fatal.
				_ = err
			}
		}
	}
}

func (h *Handler) handle(frame netpkg.Frame) error {
	p, err := Parse(frame.Payload)
	if err != nil {
		return err
	}

	// always merge sender info into the cache, whether this is a request or a
	// reply.
	h.cache.Store(p.SenderIP, p.SenderMAC)

	switch p.Operation {
	case OperationRequest:
		if p.TargetIP != h.localIP {
			return nil // request is not for us
		}
		reply := Packet{
			Operation: OperationReply,
			SenderMAC: h.localMAC,
			SenderIP:  h.localIP,
			TargetMAC: p.SenderMAC,
			TargetIP:  p.SenderIP,
		}
		if err := h.sendPacket(p.SenderMAC, reply); err != nil {
			return fmt.Errorf("arp: send reply: %w", err)
		}

	case OperationReply:
		// notify any goroutines blocked in Resolve waiting for this IP
		h.notifyWaiters(p.SenderIP, p.SenderMAC)
	}
	return nil
}

// Resolve returns the Ethernet address for targetIP
//
// Cache hit: returns immediately with no network traffic.
//
// Cache miss: broadcasts an ARP request and waits for a reply. Concurrent
// callers for the same targetIP register as waiters - only the first caller
// sends the broadcast; all are notified when the reply arrives.
func (h *Handler) Resolve(ctx context.Context, targetIP [4]byte) (ethernet.Addr, error) {
	if mac, ok := h.cache.Lookup(targetIP); ok {
		return mac, nil
	}

	// slow path: register as a waiter, send a broadcast request if first
	ch := make(chan ethernet.Addr, 1)
	first := h.registerWaiter(targetIP, ch)
	if first {
		req := Packet{
			Operation: OperationRequest,
			SenderMAC: h.localMAC,
			SenderIP:  h.localIP,
			TargetMAC: ethernet.Addr{}, // unknown - zero on request
			TargetIP:  targetIP,
		}
		if err := h.sendPacket(ethernet.Broadcast, req); err != nil {
			h.removeWaiter(targetIP, ch)
			return ethernet.Addr{}, fmt.Errorf("arp: send request: %w", err)
		}
	}

	select {
	case mac := <-ch:
		return mac, nil
	case <-ctx.Done():
		h.removeWaiter(targetIP, ch)
		return ethernet.Addr{}, ErrResolveFailed
	}
}

func (h *Handler) registerWaiter(targetIP [4]byte, ch chan ethernet.Addr) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	first := len(h.pending[targetIP]) == 0
	h.pending[targetIP] = append(h.pending[targetIP], ch)
	return first
}

func (h *Handler) removeWaiter(targetIP [4]byte, ch chan ethernet.Addr) {
	h.mu.Lock()
	defer h.mu.Unlock()
	waiters := h.pending[targetIP]
	for i, w := range waiters {
		if w == ch {
			h.pending[targetIP] = append(waiters[:i], waiters[i+1:]...)
			break
		}
	}
	if len(h.pending[targetIP]) == 0 {
		delete(h.pending, targetIP)
	}
}

func (h *Handler) notifyWaiters(targetIP [4]byte, mac ethernet.Addr) {
	h.mu.Lock()
	waiters := h.pending[targetIP]
	delete(h.pending, targetIP)
	h.mu.Unlock()
	for _, ch := range waiters {
		ch <- mac
	}
}

func (h *Handler) sendPacket(dstMAC ethernet.Addr, p Packet) error {
	buf := make([]byte, ethernet.HeaderLen+PacketLen)
	if err := Marshal(buf[ethernet.HeaderLen:], p); err != nil {
		return err
	}
	hdr := ethernet.Header{
		Dst:       dstMAC,
		Src:       h.localMAC,
		EtherType: ethernet.EtherTypeARP,
	}
	// payload is already in buf[14:]; ethernet.Marshal copies it in-place
	if _, err := ethernet.Marshal(buf, hdr, buf[ethernet.HeaderLen:]); err != nil {
		return err
	}
	_, err := h.dev.Write(buf)
	return err
}
