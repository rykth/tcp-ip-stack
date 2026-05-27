package ip_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/rykth/tcp-ip-stack/pkg/ethernet"
	"github.com/rykth/tcp-ip-stack/pkg/ip"
	netpkg "github.com/rykth/tcp-ip-stack/pkg/net"
)

var (
	macA = ethernet.Addr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
	macB = ethernet.Addr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02}
	ipA  = [4]byte{10, 0, 0, 1}
	ipB  = [4]byte{10, 0, 0, 2}
)

type spyDevice struct {
	mu      sync.Mutex
	writes  [][]byte
	written chan struct{}
	closed  chan struct{}
	name    string
	mtu     int
}

func newSpy(name string, mtu int) *spyDevice {
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
	return 0, errors.New("closed")
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
		// no-op
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

type mockARP struct {
	mac ethernet.Addr
	err error
}

func (m *mockARP) Resolve(_ context.Context, _ [4]byte) (ethernet.Addr, error) {
	return m.mac, m.err
}

type mockUpper struct {
	proto   ip.Protocol
	mu      sync.Mutex
	packets []upperPacket
	notify  chan struct{}
}

type upperPacket struct {
	src, dst [4]byte
	payload  []byte
}

func newMockUpper(proto ip.Protocol) *mockUpper {
	return &mockUpper{
		proto:  proto,
		notify: make(chan struct{}, 64),
	}
}

func (u *mockUpper) Protocol() ip.Protocol {
	return u.proto
}

func (u *mockUpper) Deliver(src, dst [4]byte, payload []byte) {
	cp := make([]byte, len(payload))
	copy(cp, payload)

	u.mu.Lock()
	u.packets = append(u.packets, upperPacket{src, dst, cp})
	u.mu.Unlock()

	select {
	case u.notify <- struct{}{}:
	default:
	}
}

func (u *mockUpper) wait(t *testing.T, n int) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		u.mu.Lock()
		got := len(u.packets)
		u.mu.Unlock()
		if got >= n {
			return
		}
		select {
		case <-u.notify:
		case <-deadline:
			t.Fatalf("timed out waiting for %d deliveries; got %d", n, got)
		}
	}
}

func (u *mockUpper) Received() []upperPacket {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]upperPacket, len(u.packets))
	copy(out, u.packets)
	return out
}

func buildIPFrame(t *testing.T, src, dst [4]byte, proto ip.Protocol, payload []byte, flags uint8, fragOffset uint16) netpkg.Frame {
	t.Helper()
	hdr := ip.Header{
		Version:    4,
		IHL:        ip.MinHeaderLen / 4,
		TOS:        0,
		TotalLen:   uint16(ip.MinHeaderLen + len(payload)),
		ID:         1,
		Flags:      flags,
		FragOffset: fragOffset,
		TTL:        64,
		Protocol:   proto,
		Src:        src,
		Dst:        dst,
	}

	buf := make([]byte, ip.MinHeaderLen+len(payload))
	if err := ip.Marshal(buf, hdr, payload); err != nil {
		t.Fatalf("ip.Marshal: %v", err)
	}

	// ethernet frame
	ethBuf := make([]byte, ethernet.HeaderLen+len(buf))
	ethHdr := ethernet.Header{
		Dst:       macB,
		Src:       macA,
		EtherType: ethernet.EtherTypeIPv4,
	}
	if _, err := ethernet.Marshal(ethBuf, ethHdr, buf); err != nil {
		t.Fatalf("ethernet.Marshal: %v", err)
	}

	return netpkg.Frame{
		Dst:     macB,
		Src:     macA,
		Payload: buf,
	}
}

func startHandler(t *testing.T, h *ip.Handler) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.Start(ctx, make(chan error, 4))
	}()
	return cancel, done
}

func TestChecksum_RFC1071Vector(t *testing.T) {
	// RFC 1071 example: bytes 00 01 f2 03 f4 f5 f6 f7 -> checksum 0x220d
	data := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
	got := ip.Checksum(data)
	if got != 0x220d {
		t.Errorf("Checksum = %#x, want 0x220d", got)
	}
}

func TestChecksum_Verification(t *testing.T) {
	data := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
	check := ip.Checksum(data)

	// new slice including the checksum
	withCheck := []byte{
		0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7,
		byte(check >> 8), byte(check),
	}

	if ip.Checksum(withCheck) != 0 {
		t.Errorf("verification checksum != 0: got %#x", ip.Checksum(withCheck))
	}
}

func TestChecksum_OddLength(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	got := ip.Checksum(data)

	// manually: 0x0102 + 0x0300 = 0x0402; ~0x0402 = 0xFBFD
	if got != 0xFBFD {
		t.Errorf("Checksum(odd) = %#x, want 0xFBFD", got)
	}
}

func TestAdd16_CombinesChecksums(t *testing.T) {
	a := []byte{0x00, 0x01, 0xf2, 0x03}
	b := []byte{0xf4, 0xf5, 0xf6, 0xf7}
	ab := append(a, b...)

	want := ip.Checksum(ab)
	got := ip.Add16(ip.Checksum(a), ip.Checksum(b))
	if got != want {
		t.Errorf("Add16 = %#x, want %#x", got, want)
	}
}

func TestPseudoHeaderChecksum_NotZero(t *testing.T) {
	src := [4]byte{10, 0, 0, 1}
	dst := [4]byte{10, 0, 0, 2}
	got := ip.PseudoHeaderChecksum(src, dst, ip.ProtocolTCP, 100)
	if got == 0 {
		t.Error("PseudoHeaderChecksum returned 0 for non-trivial input")
	}
}

func BenchmarkChecksum(b *testing.B) {
	data := make([]byte, 1500)
	for i := range data {
		data[i] = byte(i)
	}
	b.ResetTimer()
	for b.Loop() {
		ip.Checksum(data)
	}
}

func TestParse_ValidMinimal(t *testing.T) {
	hdr := ip.Header{
		Version:  4,
		IHL:      5,
		TOS:      0,
		TotalLen: ip.MinHeaderLen,
		ID:       0x1234,
		TTL:      64,
		Protocol: ip.ProtocolICMP,
		Src:      ipA,
		Dst:      ipB,
	}

	buf := make([]byte, ip.MinHeaderLen)
	if err := ip.Marshal(buf, hdr, nil); err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	got, err := ip.Parse(buf)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Version != 4 {
		t.Errorf("Version: got %d, want 4", got.Version)
	}
	if got.Src != ipA {
		t.Errorf("Src: got %v, want %v", got.Src, ipA)
	}
	if got.Dst != ipB {
		t.Errorf("Dst: got %v, want %v", got.Dst, ipB)
	}
	if got.Protocol != ip.ProtocolICMP {
		t.Errorf("Protocol: got %d, want ICMP", got.Protocol)
	}
}

func TestParse_TooShort(t *testing.T) {
	_, err := ip.Parse(make([]byte, ip.MinHeaderLen-1))
	if !errors.Is(err, ip.ErrHeaderTooShort) {
		t.Errorf("got %v, want ErrHeaderTooShort", err)
	}
}

func TestParse_BadVersion(t *testing.T) {
	buf := make([]byte, ip.MinHeaderLen)
	buf[0] = 0x65 // version=6, ihl=5
	_, err := ip.Parse(buf)
	if !errors.Is(err, ip.ErrBadVersion) {
		t.Errorf("got %v, want ErrBadVersion", err)
	}
}

func TestParse_BadChecksum(t *testing.T) {
	hdr := ip.Header{Version: 4, IHL: 5, TotalLen: ip.MinHeaderLen, TTL: 64, Protocol: ip.ProtocolICMP, Src: ipA, Dst: ipB}
	buf := make([]byte, ip.MinHeaderLen)
	if err := ip.Marshal(buf, hdr, nil); err != nil {
		t.Fatal(err)
	}
	buf[10] ^= 0xFF // corrupt the checksum
	_, err := ip.Parse(buf)
	if !errors.Is(err, ip.ErrBadChecksum) {
		t.Errorf("got %v, want ErrBadChecksum", err)
	}
}

func TestMarshal_RoundTrip(t *testing.T) {
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	hdr := ip.Header{
		Version:    4,
		IHL:        5,
		TOS:        0x10,
		TotalLen:   uint16(ip.MinHeaderLen + len(payload)),
		ID:         0xABCD,
		Flags:      ip.FlagDF,
		FragOffset: 0,
		TTL:        128,
		Protocol:   ip.ProtocolUDP,
		Src:        ipA,
		Dst:        ipB,
	}

	buf := make([]byte, ip.MinHeaderLen+len(payload))
	if err := ip.Marshal(buf, hdr, payload); err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	got, err := ip.Parse(buf)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.TOS != hdr.TOS {
		t.Errorf("TOS: got %d, want %d", got.TOS, hdr.TOS)
	}
	if got.ID != hdr.ID {
		t.Errorf("ID: got %#x, want %#x", got.ID, hdr.ID)
	}
	if got.Flags != hdr.Flags {
		t.Errorf("Flags: got %#x, want %#x", got.Flags, hdr.Flags)
	}
	if got.TTL != hdr.TTL {
		t.Errorf("TTL: got %d, want %d", got.TTL, hdr.TTL)
	}
	p := ip.Payload(buf, got)
	if len(p) != len(payload) {
		t.Fatalf("Payload len: got %d, want %d", len(p), len(payload))
	}
	for i, b := range payload {
		if p[i] != b {
			t.Errorf("Payload[%d]: got %#x, want %#x", i, p[i], b)
		}
	}
}

func TestMarshal_FlagsMF(t *testing.T) {
	hdr := ip.Header{
		Version:  4,
		IHL:      5,
		TotalLen: ip.MinHeaderLen,
		TTL:      64,
		Protocol: ip.ProtocolTCP,
		Flags:    ip.FlagMF,
		Src:      ipA,
		Dst:      ipB,
	}

	buf := make([]byte, ip.MinHeaderLen)
	if err := ip.Marshal(buf, hdr, nil); err != nil {
		t.Fatal(err)
	}

	got, err := ip.Parse(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Flags&ip.FlagMF == 0 {
		t.Error("FlagMF not preserved through marshal/parse")
	}
}

func TestTable_LPM(t *testing.T) {
	dev := newSpy("eth0", 1500)
	table := ip.NewTable()

	net24, _ := ip.ParseNetwork("10.0.0.0/24")
	net16, _ := ip.ParseNetwork("10.0.0.0/16")
	netDefault, _ := ip.ParseNetwork("0.0.0.0/0")

	table.Add(ip.Route{Network: net16, Dev: dev})
	table.Add(ip.Route{Network: net24, Dev: dev})
	table.Add(ip.Route{Network: netDefault, Dev: dev})

	// 10.0.0.5 should match /24 (most specific)
	r, err := table.Lookup([4]byte{10, 0, 0, 5})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if r.Network.Prefix != 24 {
		t.Errorf("expected /24 match, got /%d", r.Network.Prefix)
	}

	// 10.0.1.1 should match /16 (next most specific)
	r, err = table.Lookup([4]byte{10, 0, 1, 1})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if r.Network.Prefix != 16 {
		t.Errorf("expected /16 match, got /%d", r.Network.Prefix)
	}

	// 192.168.1.1 falls back to default route
	r, err = table.Lookup([4]byte{192, 168, 1, 1})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if r.Network.Prefix != 0 {
		t.Errorf("expected /0 default, got /%d", r.Network.Prefix)
	}
}

func TestTable_NoRoute(t *testing.T) {
	table := ip.NewTable()
	_, err := table.Lookup([4]byte{1, 2, 3, 4})
	if !errors.Is(err, ip.ErrNoRoute) {
		t.Errorf("got %v, want ErrNoRoute", err)
	}
}

func TestTable_Delete(t *testing.T) {
	dev := newSpy("eth0", 1500)
	table := ip.NewTable()
	net24, _ := ip.ParseNetwork("10.0.0.0/24")
	table.Add(ip.Route{Network: net24, Dev: dev})

	r, err := table.Lookup([4]byte{10, 0, 0, 1})
	if err != nil || r.Network.Prefix != 24 {
		t.Fatal("route should exist before delete")
	}

	table.Delete(net24)
	_, err = table.Lookup([4]byte{10, 0, 0, 1})
	if !errors.Is(err, ip.ErrNoRoute) {
		t.Errorf("after Delete: got %v, want ErrNoRoute", err)
	}
}

func TestTable_MetricTieBreak(t *testing.T) {
	dev1 := newSpy("eth0", 1500)
	dev2 := newSpy("eth1", 1500)
	table := ip.NewTable()
	net, _ := ip.ParseNetwork("10.0.0.0/24")
	// lower-metric (preferred) route second
	table.Add(ip.Route{Network: net, Dev: dev2, Metric: 10})
	table.Add(ip.Route{Network: net, Dev: dev1, Metric: 1})

	r, err := table.Lookup([4]byte{10, 0, 0, 1})
	if err != nil {
		t.Fatal(err)
	}
	if r.Dev.Name() != "eth0" {
		t.Errorf("expected eth0 (metric 1), got %s", r.Dev.Name())
	}
}

func TestReassembler_NonFragment(t *testing.T) {
	ra := ip.NewReassembler()
	hdr := ip.Header{
		Version:    4,
		IHL:        5,
		ID:         1,
		Flags:      0,
		FragOffset: 0,
		Src:        ipA,
		Dst:        ipB,
		Protocol:   ip.ProtocolTCP,
	}
	payload := []byte{1, 2, 3, 4}
	result, ok := ra.Add(hdr, payload)
	if !ok {
		t.Error("non-fragment (MF=0, offset=0) should complete immediately")
	}
	if string(result) != string(payload) {
		t.Errorf("reassembled: got %v, want %v", result, payload)
	}
}

func TestReassembler_TwoFragmentsInOrder(t *testing.T) {
	ra := ip.NewReassembler()
	base := ip.Header{
		Version:  4,
		IHL:      5,
		ID:       42,
		Src:      ipA,
		Dst:      ipB,
		Protocol: ip.ProtocolTCP,
	}

	// first fragment: offset 0, MF set
	h1 := base
	h1.Flags = ip.FlagMF
	h1.FragOffset = 0
	frag1 := []byte{1, 2, 3, 4, 5, 6, 7, 8} // 8 bytes

	_, ok := ra.Add(h1, frag1)
	if ok {
		t.Fatal("first fragment should not complete reassembly")
	}

	// second (last) fragment: offset 1 (= 8 bytes), MF clear
	h2 := base
	h2.Flags = 0
	h2.FragOffset = 1 // 1 * 8 = 8 bytes
	frag2 := []byte{9, 10, 11, 12}

	result, ok := ra.Add(h2, frag2)
	if !ok {
		t.Fatal("second fragment should complete reassembly")
	}
	want := append(frag1, frag2...)
	if string(result) != string(want) {
		t.Errorf("reassembled: got %v, want %v", result, want)
	}
}

func TestReassembler_TwoFragmentsOutOfOrder(t *testing.T) {
	ra := ip.NewReassembler()
	base := ip.Header{
		Version:  4,
		IHL:      5,
		ID:       99,
		Src:      ipA,
		Dst:      ipB,
		Protocol: ip.ProtocolUDP,
	}

	// last fragment arrives first
	h2 := base
	h2.Flags = 0
	h2.FragOffset = 1 // offset 8
	frag2 := []byte{9, 10, 11, 12}

	_, ok := ra.Add(h2, frag2)
	if ok {
		t.Fatal("out-of-order last fragment alone should not complete reassembly")
	}

	// first fragment arrives second
	h1 := base
	h1.Flags = ip.FlagMF
	h1.FragOffset = 0
	frag1 := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	result, ok := ra.Add(h1, frag1)
	if !ok {
		t.Fatal("receiving both fragments should complete reassembly")
	}
	want := append(frag1, frag2...)
	if string(result) != string(want) {
		t.Errorf("reassembled: got %v, want %v", result, want)
	}
}

func TestReassembler_GC_DropsExpiredGroups(t *testing.T) {
	ra := ip.NewReassembler(ip.WithReassemblyTimeout(10 * time.Millisecond))

	h1 := ip.Header{
		Version:    4,
		IHL:        5,
		ID:         7,
		Flags:      ip.FlagMF,
		FragOffset: 0,
		Src:        ipA,
		Dst:        ipB,
		Protocol:   ip.ProtocolICMP,
	}
	_, ok := ra.Add(h1, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	if ok {
		t.Fatal("incomplete group should not reassemble")
	}

	time.Sleep(20 * time.Millisecond)
	ra.GC()

	// should not complete (group was dropped)
	h2 := ip.Header{
		Version:    4,
		IHL:        5,
		ID:         7,
		Flags:      0,
		FragOffset: 1,
		Src:        ipA,
		Dst:        ipB,
		Protocol:   ip.ProtocolICMP,
	}
	_, ok = ra.Add(h2, []byte{9, 10})
	if ok {
		t.Error("GC should have dropped the incomplete group; reassembly should not complete")
	}
}

func TestHandler_DeliverToUpper(t *testing.T) {
	defer goleak.VerifyNone(t)

	dev := newSpy("eth0", 1500)
	table := ip.NewTable()
	net, _ := ip.ParseNetwork("10.0.0.0/8")
	table.Add(ip.Route{Network: net, Dev: dev})

	arpResolver := &mockARP{mac: macB}
	h := ip.NewHandler(macA, ipA, arpResolver, table)
	upper := newMockUpper(ip.ProtocolICMP)
	if err := h.RegisterUpper(upper); err != nil {
		t.Fatal(err)
	}

	cancel, done := startHandler(t, h)
	defer func() {
		cancel()
		<-done
	}()

	payload := []byte{0x08, 0x00, 0x00, 0x00} // ICMP-like
	h.RxChan() <- buildIPFrame(t, ipB, ipA, ip.ProtocolICMP, payload, 0, 0)

	upper.wait(t, 1)
	pkts := upper.Received()
	if len(pkts) == 0 {
		t.Fatal("no packets delivered to upper handler")
	}
	if pkts[0].src != ipB {
		t.Errorf("src: got %v, want %v", pkts[0].src, ipB)
	}
	if pkts[0].dst != ipA {
		t.Errorf("dst: got %v, want %v", pkts[0].dst, ipA)
	}
	if string(pkts[0].payload) != string(payload) {
		t.Errorf("payload mismatch")
	}
}

func TestHandler_UnknownProtocol_Dropped(t *testing.T) {
	defer goleak.VerifyNone(t)

	dev := newSpy("eth0", 1500)
	table := ip.NewTable()
	net, _ := ip.ParseNetwork("10.0.0.0/8")
	table.Add(ip.Route{Network: net, Dev: dev})
	h := ip.NewHandler(macA, ipA, &mockARP{mac: macB}, table)

	cancel, done := startHandler(t, h)
	defer func() { cancel(); <-done }()

	// protocol 253 no handler registered
	h.RxChan() <- buildIPFrame(t, ipB, ipA, 253, []byte{0x01, 0x02}, 0, 0)
	time.Sleep(20 * time.Millisecond) // should not panic or deadlock
}

func TestHandler_Send_NoFragmentation(t *testing.T) {
	defer goleak.VerifyNone(t)

	dev := newSpy("eth0", 1500)
	table := ip.NewTable()
	net, _ := ip.ParseNetwork("10.0.0.0/8")
	table.Add(ip.Route{Network: net, Dev: dev})

	h := ip.NewHandler(macA, ipA, &mockARP{mac: macB}, table)

	cancel, done := startHandler(t, h)
	defer func() { cancel(); <-done }()

	payload := []byte{0xca, 0xfe, 0xba, 0xbe}
	if err := h.Send(context.Background(), ipB, ip.ProtocolUDP, payload); err != nil {
		t.Fatalf("Send: %v", err)
	}

	dev.waitWrite(t, 1)
	recorded := dev.Recorded()
	if len(recorded) == 0 {
		t.Fatal("no frame written to device")
	}

	// parse the Ethernet frame
	ethFrame, err := ethernet.Parse(recorded[0])
	if err != nil {
		t.Fatalf("ethernet.Parse: %v", err)
	}
	if ethFrame.EtherType != ethernet.EtherTypeIPv4 {
		t.Errorf("EtherType: got %#x, want IPv4", ethFrame.EtherType)
	}

	// parse the IP header
	hdr, err := ip.Parse(ethFrame.Payload)
	if err != nil {
		t.Fatalf("ip.Parse: %v", err)
	}
	if hdr.Src != ipA {
		t.Errorf("Src: got %v, want %v", hdr.Src, ipA)
	}
	if hdr.Dst != ipB {
		t.Errorf("Dst: got %v, want %v", hdr.Dst, ipB)
	}
	if hdr.Protocol != ip.ProtocolUDP {
		t.Errorf("Protocol: got %d, want UDP", hdr.Protocol)
	}

	got := ip.Payload(ethFrame.Payload, hdr)
	if string(got) != string(payload) {
		t.Errorf("payload mismatch: got %v, want %v", got, payload)
	}
}

func TestHandler_Send_WithFragmentation(t *testing.T) {
	defer goleak.VerifyNone(t)

	// very small MTU to force fragmentation
	dev := newSpy("eth0", ethernet.HeaderLen+ip.MinHeaderLen+24) // 24 bytes of IP payload per fragment
	table := ip.NewTable()
	net, _ := ip.ParseNetwork("10.0.0.0/8")
	table.Add(ip.Route{Network: net, Dev: dev})

	h := ip.NewHandler(macA, ipA, &mockARP{mac: macB}, table)

	cancel, done := startHandler(t, h)
	defer func() { cancel(); <-done }()

	// 48 bytes needs 2 fragments of 24 bytes each
	payload := make([]byte, 48)
	for i := range payload {
		payload[i] = byte(i)
	}

	if err := h.Send(context.Background(), ipB, ip.ProtocolTCP, payload); err != nil {
		t.Fatalf("Send: %v", err)
	}

	dev.waitWrite(t, 2)
	recorded := dev.Recorded()
	if len(recorded) != 2 {
		t.Fatalf("expected 2 fragments, got %d", len(recorded))
	}

	// first fragment must have MF flag set
	eth1, _ := ethernet.Parse(recorded[0])
	h1, err := ip.Parse(eth1.Payload)
	if err != nil {
		t.Fatalf("parse fragment 1: %v", err)
	}
	if h1.Flags&ip.FlagMF == 0 {
		t.Error("first fragment must have MF flag set")
	}
	if h1.FragOffset != 0 {
		t.Errorf("first fragment offset: got %d, want 0", h1.FragOffset)
	}

	// second fragment must have MF=0 and correct offset
	eth2, _ := ethernet.Parse(recorded[1])
	h2, err := ip.Parse(eth2.Payload)
	if err != nil {
		t.Fatalf("parse fragment 2: %v", err)
	}
	if h2.Flags&ip.FlagMF != 0 {
		t.Error("last fragment must have MF=0")
	}
	if h2.FragOffset == 0 {
		t.Error("last fragment must have non-zero offset")
	}

	// both fragments must share the same ID
	if h1.ID != h2.ID {
		t.Errorf("fragment IDs differ: %d vs %d", h1.ID, h2.ID)
	}

	// reassemble and verify payload
	ra := ip.NewReassembler()
	p1 := ip.Payload(eth1.Payload, h1)
	p2 := ip.Payload(eth2.Payload, h2)
	_, _ = ra.Add(h1, p1)
	result, ok := ra.Add(h2, p2)
	if !ok {
		t.Fatal("reassembler could not combine the two fragments")
	}
	if string(result) != string(payload) {
		t.Errorf("reassembled payload mismatch")
	}
}

func TestHandler_RegisterUpper_Duplicate(t *testing.T) {
	h := ip.NewHandler(macA, ipA, &mockARP{}, ip.NewTable())
	u1 := newMockUpper(ip.ProtocolICMP)
	u2 := newMockUpper(ip.ProtocolICMP)
	if err := h.RegisterUpper(u1); err != nil {
		t.Fatal(err)
	}
	if err := h.RegisterUpper(u2); !errors.Is(err, ip.ErrDuplicateProto) {
		t.Errorf("got %v, want ErrDuplicateProto", err)
	}
}

func TestHandler_Shutdown_NoLeak(t *testing.T) {
	defer goleak.VerifyNone(t)

	h := ip.NewHandler(macA, ipA, &mockARP{mac: macB}, ip.NewTable())
	cancel, done := startHandler(t, h)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not shut down")
	}
}

func TestHandler_Reassembly_E2E(t *testing.T) {
	defer goleak.VerifyNone(t)

	dev := newSpy("eth0", 1500)
	table := ip.NewTable()
	net, _ := ip.ParseNetwork("10.0.0.0/8")
	table.Add(ip.Route{Network: net, Dev: dev})

	h := ip.NewHandler(macA, ipA, &mockARP{mac: macB}, table)
	upper := newMockUpper(ip.ProtocolTCP)
	if err := h.RegisterUpper(upper); err != nil {
		t.Fatal(err)
	}

	cancel, done := startHandler(t, h)
	defer func() { cancel(); <-done }()

	// inject two fragments (out of order) for the same datagram
	base := ip.Header{Version: 4, IHL: 5, ID: 42, TTL: 64, Protocol: ip.ProtocolTCP, Src: ipB, Dst: ipA}

	frag1 := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	frag2 := []byte{9, 10, 11, 12}

	h2hdr := base
	h2hdr.Flags = 0
	h2hdr.FragOffset = 1
	h2hdr.TotalLen = uint16(ip.MinHeaderLen + len(frag2))
	buf2 := make([]byte, ip.MinHeaderLen+len(frag2))
	ip.Marshal(buf2, h2hdr, frag2) //nolint:errcheck
	h.RxChan() <- netpkg.Frame{Src: macA, Dst: macB, Payload: buf2}

	h1hdr := base
	h1hdr.Flags = ip.FlagMF
	h1hdr.FragOffset = 0
	h1hdr.TotalLen = uint16(ip.MinHeaderLen + len(frag1))
	buf1 := make([]byte, ip.MinHeaderLen+len(frag1))
	ip.Marshal(buf1, h1hdr, frag1) //nolint:errcheck
	h.RxChan() <- netpkg.Frame{Src: macA, Dst: macB, Payload: buf1}

	upper.wait(t, 1)
	pkts := upper.Received()
	want := append(frag1, frag2...)
	if string(pkts[0].payload) != string(want) {
		t.Errorf("reassembled payload: got %v, want %v", pkts[0].payload, want)
	}
}
