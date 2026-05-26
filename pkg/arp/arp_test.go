package arp_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/rykth/tcp-ip-stack/pkg/arp"
	"github.com/rykth/tcp-ip-stack/pkg/ethernet"
	netpkg "github.com/rykth/tcp-ip-stack/pkg/net"
)

var (
	macA = ethernet.Addr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
	macB = ethernet.Addr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02}
	ipA  = [4]byte{192, 168, 1, 1}
	ipB  = [4]byte{192, 168, 1, 2}
	ipC  = [4]byte{192, 168, 1, 3} // unrelated - not registered with any handler
)

// spyDevice records every Write call - read blocks until Close is called
type spyDevice struct {
	mu      sync.Mutex
	writes  [][]byte
	written chan struct{} // notified (non-blocking) on each Write
	closed  chan struct{}
	name    string
	mtu     int
}

func newSpyDevice(name string, mtu int) *spyDevice {
	return &spyDevice{
		written: make(chan struct{}, 64),
		closed:  make(chan struct{}),
		name:    name,
		mtu:     mtu,
	}
}

func (d *spyDevice) Name() string {
	return d.name
}

func (d *spyDevice) MTU() int {
	return d.mtu
}

func (d *spyDevice) Read(p []byte) (int, error) {
	<-d.closed
	return 0, errors.New("device closed")
}

func (d *spyDevice) Write(p []byte) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	d.mu.Lock()
	d.writes = append(d.writes, cp)
	d.mu.Unlock()
	select {
	case d.written <- struct{}{}:
	default:
	}
	return len(p), nil
}

func (d *spyDevice) Close() error {
	select {
	case <-d.closed:
	default:
		close(d.closed)
	}
	return nil
}

func (d *spyDevice) Recorded() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([][]byte, len(d.writes))
	copy(out, d.writes)
	return out
}

func (d *spyDevice) waitWrite(t *testing.T, n int) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		d.mu.Lock()
		got := len(d.writes)
		d.mu.Unlock()
		if got >= n {
			return
		}
		select {
		case <-d.written:
		case <-deadline:
			t.Fatalf("timed out waiting for %d writes; got %d", n, got)
		}
	}
}

func buildRequestFrame(senderMAC ethernet.Addr, senderIP, targetIP [4]byte) netpkg.Frame {
	p := arp.Packet{
		Operation: arp.OperationRequest,
		SenderMAC: senderMAC,
		SenderIP:  senderIP,
		TargetIP:  targetIP,
	}
	var buf [arp.PacketLen]byte
	_ = arp.Marshal(buf[:], p)
	payload := make([]byte, arp.PacketLen)
	copy(payload, buf[:])
	return netpkg.Frame{
		Dst:     ethernet.Broadcast,
		Src:     senderMAC,
		Payload: payload,
	}
}

func buildReplyFrame(senderMAC ethernet.Addr, senderIP [4]byte, targetMAC ethernet.Addr, targetIP [4]byte) netpkg.Frame {
	p := arp.Packet{
		Operation: arp.OperationReply,
		SenderMAC: senderMAC,
		SenderIP:  senderIP,
		TargetMAC: targetMAC,
		TargetIP:  targetIP,
	}
	var buf [arp.PacketLen]byte
	_ = arp.Marshal(buf[:], p)
	payload := make([]byte, arp.PacketLen)
	copy(payload, buf[:])
	return netpkg.Frame{
		Dst:     targetMAC,
		Src:     senderMAC,
		Payload: payload,
	}
}

func startHandler(t *testing.T, h *arp.Handler) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.Start(ctx, make(chan error, 4))
	}()
	return cancel, done
}

func TestParse_Valid(t *testing.T) {
	p := arp.Packet{
		Operation: arp.OperationRequest,
		SenderMAC: macA,
		SenderIP:  ipA,
		TargetMAC: ethernet.Addr{},
		TargetIP:  ipB,
	}
	var buf [arp.PacketLen]byte
	if err := arp.Marshal(buf[:], p); err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	got, err := arp.Parse(buf[:])
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Operation != p.Operation {
		t.Errorf("Operation: got %d, want %d", got.Operation, p.Operation)
	}
	if got.SenderMAC != p.SenderMAC {
		t.Errorf("SenderMAC: got %v, want %v", got.SenderMAC, p.SenderMAC)
	}
	if got.SenderIP != p.SenderIP {
		t.Errorf("SenderIP: got %v, want %v", got.SenderIP, p.SenderIP)
	}
	if got.TargetIP != p.TargetIP {
		t.Errorf("TargetIP: got %v, want %v", got.TargetIP, p.TargetIP)
	}
}

func TestParse_TooShort(t *testing.T) {
	_, err := arp.Parse(make([]byte, arp.PacketLen-1))
	if !errors.Is(err, arp.ErrPacketTooShort) {
		t.Errorf("got %v, want ErrPacketTooShort", err)
	}
}

func TestParse_WrongHardwareType(t *testing.T) {
	var buf [arp.PacketLen]byte
	buf[0], buf[1] = 0x00, 0x06 // IEEE 802.2 - not Ethernet
	_, err := arp.Parse(buf[:])
	if !errors.Is(err, arp.ErrUnsupportedHardwareType) {
		t.Errorf("got %v, want ErrUnsupportedHardwareType", err)
	}
}

func TestParse_WrongProtocolType(t *testing.T) {
	var buf [arp.PacketLen]byte
	buf[0], buf[1] = 0x00, 0x01 // Ethernet hardware type
	buf[2], buf[3] = 0x86, 0xDD // IPv6 protocol - not IPv4
	_, err := arp.Parse(buf[:])
	if !errors.Is(err, arp.ErrUnsupportedProtocolType) {
		t.Errorf("got %v, want ErrUnsupportedProtocolType", err)
	}
}

func TestMarshal_RoundTrip(t *testing.T) {
	cases := []arp.Packet{
		{Operation: arp.OperationRequest, SenderMAC: macA, SenderIP: ipA, TargetIP: ipB},
		{Operation: arp.OperationReply, SenderMAC: macB, SenderIP: ipB, TargetMAC: macA, TargetIP: ipA},
	}
	for _, want := range cases {
		var buf [arp.PacketLen]byte
		if err := arp.Marshal(buf[:], want); err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		got, err := arp.Parse(buf[:])
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if got != want {
			t.Errorf("round-trip mismatch: got %+v, want %+v", got, want)
		}
	}
}

func TestMarshal_TooSmall(t *testing.T) {
	err := arp.Marshal(make([]byte, arp.PacketLen-1), arp.Packet{})
	if !errors.Is(err, arp.ErrPacketTooShort) {
		t.Errorf("got %v, want ErrPacketTooShort", err)
	}
}

func TestCache_StoreAndLookup(t *testing.T) {
	c := arp.NewCache()
	c.Store(ipA, macA)
	got, ok := c.Lookup(ipA)
	if !ok {
		t.Fatal("Lookup returned false after Store")
	}
	if got != macA {
		t.Errorf("Lookup: got %v, want %v", got, macA)
	}
}

func TestCache_LookupMiss(t *testing.T) {
	c := arp.NewCache()
	_, ok := c.Lookup(ipA)
	if ok {
		t.Error("Lookup returned true for unknown IP")
	}
}

func TestCache_TTLExpiry(t *testing.T) {
	c := arp.NewCache(arp.WithTTL(10 * time.Millisecond))
	c.Store(ipA, macA)
	time.Sleep(20 * time.Millisecond)
	_, ok := c.Lookup(ipA)
	if ok {
		t.Error("Lookup returned true after TTL expired")
	}
}

func TestCache_Delete(t *testing.T) {
	c := arp.NewCache()
	c.Store(ipA, macA)
	c.Delete(ipA)
	_, ok := c.Lookup(ipA)
	if ok {
		t.Error("Lookup returned true after Delete")
	}
}

func TestCache_GC_RemovesExpiredEntries(t *testing.T) {
	c := arp.NewCache(
		arp.WithTTL(5*time.Millisecond),
		arp.WithGCInterval(10*time.Millisecond),
	)
	c.Store(ipA, macA)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.Start(ctx)
	}()

	// wait long enough for TTL to expire and at least one GC cycle to run
	time.Sleep(50 * time.Millisecond)

	cancel()
	<-done

	_, ok := c.Lookup(ipA)
	if ok {
		t.Error("GC did not remove expired entry")
	}
}

func TestCache_ConcurrentAccess(t *testing.T) {
	c := arp.NewCache()
	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			c.Store(ipA, macA)
		}()
		go func() {
			defer wg.Done()
			c.Lookup(ipA)
		}()
	}
	wg.Wait()
}

func TestHandler_RepliesTo_Request(t *testing.T) {
	defer goleak.VerifyNone(t)

	dev := newSpyDevice("spy", 1500)
	h := arp.NewHandler(macA, ipA, dev)

	cancel, done := startHandler(t, h)
	defer func() { cancel(); <-done }()

	// inject an ARP request from macB/ipB asking for ipA's MAC
	h.RxChan() <- buildRequestFrame(macB, ipB, ipA)

	dev.waitWrite(t, 1)

	cancel()
	<-done

	recorded := dev.Recorded()
	if len(recorded) == 0 {
		t.Fatal("handler did not send any packet")
	}

	ethFrame, err := ethernet.Parse(recorded[0])
	if err != nil {
		t.Fatalf("ethernet.Parse: %v", err)
	}
	if ethFrame.EtherType != ethernet.EtherTypeARP {
		t.Errorf("EtherType: got %#x, want %#x", ethFrame.EtherType, ethernet.EtherTypeARP)
	}

	reply, err := arp.Parse(ethFrame.Payload)
	if err != nil {
		t.Fatalf("arp.Parse: %v", err)
	}
	if reply.Operation != arp.OperationReply {
		t.Errorf("Operation: got %d, want OperationReply", reply.Operation)
	}
	if reply.SenderMAC != macA {
		t.Errorf("SenderMAC: got %v, want %v", reply.SenderMAC, macA)
	}
	if reply.SenderIP != ipA {
		t.Errorf("SenderIP: got %v, want %v", reply.SenderIP, ipA)
	}
	if reply.TargetMAC != macB {
		t.Errorf("TargetMAC: got %v, want %v", reply.TargetMAC, macB)
	}
	if reply.TargetIP != ipB {
		t.Errorf("TargetIP: got %v, want %v", reply.TargetIP, ipB)
	}
}

func TestHandler_Ignores_Request_NotForUs(t *testing.T) {
	defer goleak.VerifyNone(t)

	dev := newSpyDevice("spy", 1500)
	h := arp.NewHandler(macA, ipA, dev)

	cancel, done := startHandler(t, h)
	defer func() { cancel(); <-done }()

	// Request for ipC — not our IP.
	h.RxChan() <- buildRequestFrame(macB, ipB, ipC)

	// Give the handler time to process.
	time.Sleep(20 * time.Millisecond)

	if n := len(dev.Recorded()); n != 0 {
		t.Errorf("handler sent %d packet(s) for a request not targeting it; want 0", n)
	}
}

func TestHandler_UpdatesCache_OnRequest(t *testing.T) {
	defer goleak.VerifyNone(t)

	dev := newSpyDevice("spy", 1500)
	cache := arp.NewCache()
	h := arp.NewHandler(macA, ipA, dev, arp.WithHandlerCache(cache))

	cancel, done := startHandler(t, h)
	defer func() {
		cancel()
		<-done
	}()

	h.RxChan() <- buildRequestFrame(macB, ipB, ipA)

	// wait for handler to process (it will also send a reply)
	dev.waitWrite(t, 1)

	got, ok := cache.Lookup(ipB)
	if !ok {
		t.Fatal("cache does not contain sender IP after handling request")
	}
	if got != macB {
		t.Errorf("cache MAC for ipB: got %v, want %v", got, macB)
	}
}

func TestHandler_UpdatesCache_OnReply(t *testing.T) {
	defer goleak.VerifyNone(t)

	dev := newSpyDevice("spy", 1500)
	cache := arp.NewCache()
	h := arp.NewHandler(macA, ipA, dev, arp.WithHandlerCache(cache))

	cancel, done := startHandler(t, h)
	defer func() {
		cancel()
		<-done
	}()

	h.RxChan() <- buildReplyFrame(macB, ipB, macA, ipA)

	// Give handler time to process — no write expected for a reply.
	time.Sleep(20 * time.Millisecond)

	got, ok := cache.Lookup(ipB)
	if !ok {
		t.Fatal("cache does not contain sender IP after handling reply")
	}
	if got != macB {
		t.Errorf("cache MAC for ipB: got %v, want %v", got, macB)
	}
}

func TestHandler_Resolve_CacheHit(t *testing.T) {
	defer goleak.VerifyNone(t)

	dev := newSpyDevice("spy", 1500)
	cache := arp.NewCache()
	cache.Store(ipB, macB)
	h := arp.NewHandler(macA, ipA, dev, arp.WithHandlerCache(cache))

	cancel, done := startHandler(t, h)
	defer func() {
		cancel()
		<-done
	}()

	ctx := context.Background()
	got, err := h.Resolve(ctx, ipB)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != macB {
		t.Errorf("Resolve: got %v, want %v", got, macB)
	}

	// no packets should have been sent: it was a cache hit
	if n := len(dev.Recorded()); n != 0 {
		t.Errorf("Resolve sent %d packet(s) on cache hit; want 0", n)
	}
}

func TestHandler_Resolve_CacheMiss(t *testing.T) {
	defer goleak.VerifyNone(t)

	dev := newSpyDevice("spy", 1500)
	h := arp.NewHandler(macA, ipA, dev)

	cancel, done := startHandler(t, h)
	defer func() {
		cancel()
		<-done
	}()

	// call Resolve in a goroutine; it will block waiting for a reply
	type result struct {
		mac ethernet.Addr
		err error
	}
	resultCh := make(chan result, 1)
	go func() {
		ctx := context.Background()
		mac, err := h.Resolve(ctx, ipB)
		resultCh <- result{mac, err}
	}()

	// wait for Resolve to send the ARP request
	dev.waitWrite(t, 1)

	// verify the outgoing request.
	ethFrame, err := ethernet.Parse(dev.Recorded()[0])
	if err != nil {
		t.Fatalf("parse outgoing frame: %v", err)
	}

	req, err := arp.Parse(ethFrame.Payload)
	if err != nil {
		t.Fatalf("parse outgoing ARP: %v", err)
	}
	if req.Operation != arp.OperationRequest {
		t.Errorf("outgoing operation: got %d, want OperationRequest", req.Operation)
	}
	if req.TargetIP != ipB {
		t.Errorf("outgoing TargetIP: got %v, want %v", req.TargetIP, ipB)
	}
	if ethFrame.Dst != ethernet.Broadcast {
		t.Errorf("outgoing Dst: got %v, want broadcast", ethFrame.Dst)
	}

	// simulate the remote host replying
	h.RxChan() <- buildReplyFrame(macB, ipB, macA, ipA)

	select {
	case r := <-resultCh:
		if r.err != nil {
			t.Fatalf("Resolve error: %v", r.err)
		}
		if r.mac != macB {
			t.Errorf("Resolve MAC: got %v, want %v", r.mac, macB)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Resolve did not return after reply was injected")
	}
}

func TestHandler_Resolve_MultipleWaiters(t *testing.T) {
	defer goleak.VerifyNone(t)

	dev := newSpyDevice("spy", 1500)
	h := arp.NewHandler(macA, ipA, dev)

	cancel, done := startHandler(t, h)
	defer func() {
		cancel()
		<-done
	}()

	const n = 5
	type result struct {
		mac ethernet.Addr
		err error
	}
	results := make(chan result, n)
	for i := 0; i < n; i++ {
		go func() {
			mac, err := h.Resolve(context.Background(), ipB)
			results <- result{mac, err}
		}()
	}

	// wait for at least one ARP request to be sent
	dev.waitWrite(t, 1)

	// inject a single reply - all waiters should be satisfied
	h.RxChan() <- buildReplyFrame(macB, ipB, macA, ipA)

	for i := 0; i < n; i++ {
		select {
		case r := <-results:
			if r.err != nil {
				t.Errorf("waiter %d: error %v", i, r.err)
			}
			if r.mac != macB {
				t.Errorf("waiter %d: MAC %v, want %v", i, r.mac, macB)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out after %d/%d waiters resolved", i, n)
		}
	}

	// only one ARP request should have been broadcast
	if n := len(dev.Recorded()); n != 1 {
		t.Errorf("sent %d ARP request(s); want exactly 1", n)
	}
}

func TestHandler_Resolve_Timeout(t *testing.T) {
	defer goleak.VerifyNone(t)

	dev := newSpyDevice("spy", 1500)
	h := arp.NewHandler(macA, ipA, dev)

	cancel, done := startHandler(t, h)
	defer func() {
		cancel()
		<-done
	}()

	ctx, cancelResolve := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelResolve()

	_, err := h.Resolve(ctx, ipC)
	if !errors.Is(err, arp.ErrResolveFailed) {
		t.Errorf("Resolve error: got %v, want ErrResolveFailed", err)
	}
}

func TestHandler_Shutdown_NoLeak(t *testing.T) {
	defer goleak.VerifyNone(t)

	dev := newSpyDevice("spy", 1500)
	h := arp.NewHandler(macA, ipA, dev)

	cancel, done := startHandler(t, h)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not shut down after context cancellation")
	}
}
