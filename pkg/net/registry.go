package net

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/rykth/tcp-ip-stack/pkg/ethernet"
)

var (
	ErrDeviceAlreadyRegistered = errors.New("net: device already registered")
	ErrDuplicateEtherType      = errors.New("net: duplicate EtherType")
)

// Registry wires LinkDevices to ProtocolHandlers.
type Registry struct {
	mu       sync.Mutex
	devices  []LinkDevice
	handlers map[ethernet.EtherType]ProtocolHandler
	drops    atomic.Int64
}

func New() *Registry {
	return &Registry{
		handlers: make(map[ethernet.EtherType]ProtocolHandler),
	}
}

// AddDevice registers dev with the Registry (must be called before Start)
func (r *Registry) AddDevice(dev LinkDevice) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.devices {
		if d.Name() == dev.Name() {
			return ErrDeviceAlreadyRegistered
		}
	}
	r.devices = append(r.devices, dev)
	return nil
}

// AddHandler registers h with the Registry(must be called before Start)
func (r *Registry) AddHandler(h ProtocolHandler) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.handlers[h.EtherType()]; exists {
		return ErrDuplicateEtherType
	}
	r.handlers[h.EtherType()] = h
	return nil
}

// Drops returns the total number of frames dropped because a handler's receive
// channel was full at the moment of delivery.
func (r *Registry) Drops() int64 {
	return r.drops.Load()
}

// Start launches one goroutine per device (rxLoop) and one per handler (Start)
func (r *Registry) Start(ctx context.Context) error {
	r.mu.Lock()
	devices := append([]LinkDevice(nil), r.devices...)
	handlers := make([]ProtocolHandler, 0, len(r.handlers))
	for _, h := range r.handlers {
		handlers = append(handlers, h)
	}
	r.mu.Unlock()

	errCh := make(chan error, len(devices)+len(handlers))

	var wg sync.WaitGroup

	// launch handler goroutines first so they are ready before frames arrive
	for _, h := range handlers {
		wg.Add(1)
		go func(h ProtocolHandler) {
			defer wg.Done()
			h.Start(ctx, errCh)
		}(h)
	}

	// launch one rxLoop per device
	for _, dev := range devices {
		wg.Add(1)
		go func(dev LinkDevice) {
			defer wg.Done()
			r.rxLoop(ctx, dev, errCh)
		}(dev)
	}

	go func() {
		<-ctx.Done()
		for _, dev := range devices {
			dev.Close()
		}
	}()

	wg.Wait()
	close(errCh)

	var errs []error
	for err := range errCh {
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// rxLoop reads frames from dev, parses the Ethernet header, and dispatches to
// the appropriate handler
func (r *Registry) rxLoop(ctx context.Context, dev LinkDevice, errCh chan<- error) {
	buf := make([]byte, dev.MTU()+ethernet.HeaderLen)
	for {
		n, err := dev.Read(buf)
		if err != nil {
			select {
			case <-ctx.Done():
			default:
				errCh <- fmt.Errorf("net: device %s: %w", dev.Name(), err)
			}
			return
		}

		f, err := ethernet.Parse(buf[:n])
		if err != nil {
			continue // drop malformed frames
		}

		r.mu.Lock()
		h, ok := r.handlers[f.EtherType]
		r.mu.Unlock()
		if !ok {
			continue // no handler registered for this EtherType
		}

		// copy payload (buf is reused on the next Read)
		payload := make([]byte, len(f.Payload))
		copy(payload, f.Payload)

		frame := Frame{Dst: f.Dst, Src: f.Src, Payload: payload, Dev: dev}
		select {
		case h.RxChan() <- frame:
		default:
			r.drops.Add(1)
		}
	}
}
