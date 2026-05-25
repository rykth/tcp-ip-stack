package net_test

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/rykth/tcp-ip-stack/pkg/ethernet"
	"github.com/rykth/tcp-ip-stack/pkg/loopback"
	netpkg "github.com/rykth/tcp-ip-stack/pkg/net"
)

type mockHandler struct {
	et ethernet.EtherType
	ch chan netpkg.Frame
}

func newMockHandler(et ethernet.EtherType, bufSize int) *mockHandler {
	return &mockHandler{et: et, ch: make(chan netpkg.Frame, bufSize)}
}

func (h *mockHandler) EtherType() ethernet.EtherType {
	return h.et
}

func (h *mockHandler) RxChan() chan netpkg.Frame {
	return h.ch
}

func (h *mockHandler) Start(ctx context.Context, _ chan<- error) {
	<-ctx.Done() // block until shutdown; let the test read from h.ch directly
}

func buildFrame(dst, src ethernet.Addr, et ethernet.EtherType, payload []byte) []byte {
	b := make([]byte, ethernet.HeaderLen+len(payload))
	copy(b[0:6], dst[:])
	copy(b[6:12], src[:])
	binary.BigEndian.PutUint16(b[12:14], uint16(et))
	copy(b[14:], payload)
	return b
}

var (
	macA = ethernet.Addr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
	macB = ethernet.Addr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02}
)

func startRegistry(t *testing.T, dev netpkg.LinkDevice, handlers ...netpkg.ProtocolHandler) (context.CancelFunc, <-chan error) {
	t.Helper()
	r := netpkg.New()
	if err := r.AddDevice(dev); err != nil {
		t.Fatalf("AddDevice: %v", err)
	}

	for _, h := range handlers {
		if err := r.AddHandler(h); err != nil {
			t.Fatalf("AddHandler: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.Start(ctx)
	}()

	return cancel, done
}

func TestRegistry_DispatchToHandler(t *testing.T) {
	defer goleak.VerifyNone(t)

	dev := loopback.New(loopback.WithName("lo-dispatch"), loopback.WithMTU(1500))
	h := newMockHandler(ethernet.EtherTypeIPv4, 8)

	cancel, done := startRegistry(t, dev, h)
	defer func() {
		cancel()
		<-done
	}()

	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	raw := buildFrame(macB, macA, ethernet.EtherTypeIPv4, payload)
	if _, err := dev.Write(raw); err != nil {
		t.Fatalf("Write: %v", err)
	}

	select {
	case f := <-h.ch:
		if f.Src != macA {
			t.Errorf("Src: got %v, want %v", f.Src, macA)
		}

		if f.Dst != macB {
			t.Errorf("Dst: got %v, want %v", f.Dst, macB)
		}

		if len(f.Payload) != len(payload) {
			t.Fatalf("Payload len: got %d, want %d", len(f.Payload), len(payload))
		}

		for i, b := range payload {
			if f.Payload[i] != b {
				t.Errorf("Payload[%d]: got %#x, want %#x", i, f.Payload[i], b)
			}
		}

		if f.Dev.Name() != dev.Name() {
			t.Errorf("Dev: got %q, want %q", f.Dev.Name(), dev.Name())
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for frame delivery")
	}
}

func TestRegistry_UnknownEtherType_Dropped(t *testing.T) {
	defer goleak.VerifyNone(t)

	dev := loopback.New(loopback.WithName("lo-unknown"))
	r := netpkg.New()
	if err := r.AddDevice(dev); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.Start(ctx)
	}()

	// no handler registered for EtherTypeIPv6
	raw := buildFrame(macB, macA, ethernet.EtherTypeIPv6, []byte{0x01})
	if _, err := dev.Write(raw); err != nil {
		t.Fatal(err)
	}

	// Give the rxLoop time to process.
	time.Sleep(20 * time.Millisecond)

	if got := r.Drops(); got != 0 {
		t.Errorf("Drops() = %d, want 0 (unknown EtherType should not count as a drop)", got)
	}

	cancel()
	<-done
}

func TestRegistry_Backpressure_Drop(t *testing.T) {
	defer goleak.VerifyNone(t)

	dev := loopback.New(loopback.WithName("lo-backpressure"), loopback.WithBufferSize(32))

	h := &mockHandler{
		et: ethernet.EtherTypeIPv4,
		ch: make(chan netpkg.Frame, 1),
	}

	r := netpkg.New()
	if err := r.AddDevice(dev); err != nil {
		t.Fatal(err)
	}
	if err := r.AddHandler(h); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.Start(ctx)
	}()

	raw := buildFrame(macB, macA, ethernet.EtherTypeIPv4, []byte{0x01})
	for i := 0; i < 10; i++ {
		dev.Write(raw) //nolint:errcheck
	}

	// Allow the rxLoop time to process all writes.
	time.Sleep(50 * time.Millisecond)

	if r.Drops() == 0 {
		t.Error("expected at least one drop due to back-pressure, got 0")
	}

	cancel()
	<-done
}

func TestRegistry_Shutdown_NoLeak(t *testing.T) {
	defer goleak.VerifyNone(t)

	dev := loopback.New(loopback.WithName("lo-shutdown"))
	h := newMockHandler(ethernet.EtherTypeIPv4, 8)

	cancel, done := startRegistry(t, dev, h)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned non-nil error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after ctx cancel")
	}
}

func TestRegistry_AddDevice_Duplicate(t *testing.T) {
	r := netpkg.New()
	dev1 := loopback.New(loopback.WithName("lo-dup"))
	dev2 := loopback.New(loopback.WithName("lo-dup"))

	if err := r.AddDevice(dev1); err != nil {
		t.Fatalf("first AddDevice: %v", err)
	}
	if err := r.AddDevice(dev2); !errors.Is(err, netpkg.ErrDeviceAlreadyRegistered) {
		t.Errorf("second AddDevice: got %v, want ErrDeviceAlreadyRegistered", err)
	}
}

func TestRegistry_AddHandler_Duplicate(t *testing.T) {
	r := netpkg.New()
	h1 := newMockHandler(ethernet.EtherTypeIPv4, 8)
	h2 := newMockHandler(ethernet.EtherTypeIPv4, 8)

	if err := r.AddHandler(h1); err != nil {
		t.Fatalf("first AddHandler: %v", err)
	}
	if err := r.AddHandler(h2); !errors.Is(err, netpkg.ErrDuplicateEtherType) {
		t.Errorf("second AddHandler: got %v, want ErrDuplicateEtherType", err)
	}
}

func TestRegistry_MultipleDevices(t *testing.T) {
	defer goleak.VerifyNone(t)

	dev1 := loopback.New(loopback.WithName("lo-multi-1"), loopback.WithMTU(1500))
	dev2 := loopback.New(loopback.WithName("lo-multi-2"), loopback.WithMTU(1500))
	h := newMockHandler(ethernet.EtherTypeARP, 8)

	r := netpkg.New()
	if err := r.AddDevice(dev1); err != nil {
		t.Fatal(err)
	}
	if err := r.AddDevice(dev2); err != nil {
		t.Fatal(err)
	}
	if err := r.AddHandler(h); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.Start(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()

	raw := buildFrame(macB, macA, ethernet.EtherTypeARP, []byte{0x01, 0x02})
	if _, err := dev1.Write(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := dev2.Write(raw); err != nil {
		t.Fatal(err)
	}

	received := make(map[string]bool)
	for i := 0; i < 2; i++ {
		select {
		case f := <-h.ch:
			received[f.Dev.Name()] = true
		case <-time.After(time.Second):
			t.Fatalf("timed out after receiving %d/2 frames", i)
		}
	}

	if !received[dev1.Name()] {
		t.Errorf("no frame received from %s", dev1.Name())
	}
	if !received[dev2.Name()] {
		t.Errorf("no frame received from %s", dev2.Name())
	}
}

func TestRegistry_PayloadIsCopied(t *testing.T) {
	defer goleak.VerifyNone(t)

	dev := loopback.New(loopback.WithName("lo-copy"), loopback.WithMTU(1500))
	h := newMockHandler(ethernet.EtherTypeIPv4, 8)

	cancel, done := startRegistry(t, dev, h)
	defer func() {
		cancel()
		<-done
	}()

	payload := []byte{0x11, 0x22, 0x33}
	raw := buildFrame(macB, macA, ethernet.EtherTypeIPv4, payload)
	if _, err := dev.Write(raw); err != nil {
		t.Fatal(err)
	}

	var f netpkg.Frame
	select {
	case f = <-h.ch:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for frame")
	}

	// write a second frame to cause the rxLoop to overwrite its buffer
	payload2 := []byte{0xff, 0xff, 0xff}
	raw2 := buildFrame(macB, macA, ethernet.EtherTypeIPv4, payload2)
	dev.Write(raw2) //nolint:errcheck
	time.Sleep(20 * time.Millisecond)

	// first frames payload must be unchanged
	if f.Payload[0] != 0x11 {
		t.Errorf("Payload[0] = %#x after buffer overwrite; want 0x11 (payload must be copied)", f.Payload[0])
	}
}
