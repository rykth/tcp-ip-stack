package udp_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/rykth/tcp-ip-stack/pkg/ip"
	"github.com/rykth/tcp-ip-stack/pkg/udp"
)

var (
	localIP  = [4]byte{10, 0, 0, 1}
	remoteIP = [4]byte{10, 0, 0, 2}
)

type sentPacket struct {
	dst   [4]byte
	proto ip.Protocol
	data  []byte
}

type mockSender struct {
	mu      sync.Mutex
	packets []sentPacket
	notify  chan struct{}
	err     error
}

func newMockSender() *mockSender {
	return &mockSender{notify: make(chan struct{}, 64)}
}

func (m *mockSender) Send(_ context.Context, dst [4]byte, proto ip.Protocol, payload []byte) error {
	if m.err != nil {
		return m.err
	}

	cp := make([]byte, len(payload))
	copy(cp, payload)

	m.mu.Lock()
	m.packets = append(m.packets, sentPacket{dst, proto, cp})
	m.mu.Unlock()

	select {
	case m.notify <- struct{}{}:
	default:
	}

	return nil
}

func (m *mockSender) waitSent(t *testing.T, n int) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		m.mu.Lock()
		got := len(m.packets)
		m.mu.Unlock()

		if got >= n {
			return
		}

		select {
		case <-m.notify:
		case <-deadline:
			t.Fatalf("timed out waiting for %d sends; got %d", n, got)
		}
	}
}

func (m *mockSender) Recorded() []sentPacket {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]sentPacket, len(m.packets))
	copy(out, m.packets)
	return out
}

func buildUDPFrame(t *testing.T, src, dst [4]byte, srcPort, dstPort uint16, data []byte) []byte {
	t.Helper()

	length := uint16(udp.HeaderLen + len(data))
	hdr := udp.Header{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  length,
	}
	hdr.Checksum = udp.ComputeChecksum(src, dst, hdr, data)

	buf := make([]byte, int(length))
	if err := udp.Marshal(buf, hdr); err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	copy(buf[udp.HeaderLen:], data)

	return buf
}

func TestParse_Valid(t *testing.T) {
	frame := buildUDPFrame(t, remoteIP, localIP, 12345, 80, []byte("hello"))
	hdr, err := udp.Parse(frame)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if hdr.SrcPort != 12345 {
		t.Errorf("SrcPort: got %d, want 12345", hdr.SrcPort)
	}

	if hdr.DstPort != 80 {
		t.Errorf("DstPort: got %d, want 80", hdr.DstPort)
	}

	if hdr.Length != uint16(udp.HeaderLen+5) {
		t.Errorf("Length: got %d, want %d", hdr.Length, udp.HeaderLen+5)
	}
}

func TestParse_TooShort(t *testing.T) {
	_, err := udp.Parse(make([]byte, udp.HeaderLen-1))
	if !errors.Is(err, udp.ErrHeaderTooShort) {
		t.Errorf("got %v, want ErrHeaderTooShort", err)
	}
}

func TestParse_LengthFieldTooSmall(t *testing.T) {
	buf := make([]byte, udp.HeaderLen)
	buf[4], buf[5] = 0, 7 // length = 7 < 8
	_, err := udp.Parse(buf)
	if !errors.Is(err, udp.ErrHeaderTooShort) {
		t.Errorf("got %v, want ErrHeaderTooShort", err)
	}
}

func TestMarshal_RoundTrip(t *testing.T) {
	cases := []struct {
		srcPort, dstPort uint16
		data             []byte
	}{
		{12345, 80, []byte("hello")},
		{0, 9999, nil},
		{65535, 1, []byte{0xDE, 0xAD, 0xBE, 0xEF}},
	}
	for _, tc := range cases {
		frame := buildUDPFrame(t, remoteIP, localIP, tc.srcPort, tc.dstPort, tc.data)
		hdr, err := udp.Parse(frame)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}

		if hdr.SrcPort != tc.srcPort || hdr.DstPort != tc.dstPort {
			t.Errorf("ports: got %d/%d, want %d/%d", hdr.SrcPort, hdr.DstPort, tc.srcPort, tc.dstPort)
		}

		if string(udp.Payload(frame)) != string(tc.data) {
			t.Errorf("payload: got %q, want %q", udp.Payload(frame), tc.data)
		}
	}
}

func TestMarshal_TooSmall(t *testing.T) {
	err := udp.Marshal(make([]byte, udp.HeaderLen-1), udp.Header{})
	if !errors.Is(err, udp.ErrHeaderTooShort) {
		t.Errorf("got %v, want ErrHeaderTooShort", err)
	}
}

func TestComputeChecksum_Verify(t *testing.T) {
	data := []byte("checksum test")
	frame := buildUDPFrame(t, remoteIP, localIP, 1234, 5678, data)
	hdr, _ := udp.Parse(frame)

	// recompute should match the stored checksum
	computed := udp.ComputeChecksum(remoteIP, localIP, hdr, udp.Payload(frame))
	if computed != hdr.Checksum {
		t.Errorf("checksum mismatch: computed %#x, stored %#x", computed, hdr.Checksum)
	}
}

func TestComputeChecksum_Corruption(t *testing.T) {
	data := []byte("data")
	frame := buildUDPFrame(t, remoteIP, localIP, 1, 2, data)
	frame[udp.HeaderLen] ^= 0xFF // corrupt payload

	hdr, _ := udp.Parse(frame)
	computed := udp.ComputeChecksum(remoteIP, localIP, hdr, udp.Payload(frame))
	// stored checksum was for original data, so they should differ
	if computed == hdr.Checksum {
		t.Error("corrupted payload should produce different checksum")
	}
}

func TestHandler_Protocol(t *testing.T) {
	h := udp.NewHandler(newMockSender(), localIP)
	if h.Protocol() != ip.ProtocolUDP {
		t.Errorf("Protocol: got %d, want ProtocolUDP", h.Protocol())
	}
}

func TestHandler_Listen_Deliver(t *testing.T) {
	defer goleak.VerifyNone(t)

	sender := newMockSender()
	h := udp.NewHandler(sender, localIP)

	conn, err := h.Listen(9999)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer conn.Close()

	frame := buildUDPFrame(t, remoteIP, localIP, 12345, 9999, []byte("hello"))
	h.Deliver(remoteIP, localIP, frame)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	dg, err := conn.ReadFrom(ctx)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}

	if dg.Src.IP != remoteIP || dg.Src.Port != 12345 {
		t.Errorf("Src: got %v, want %v:12345", dg.Src, remoteIP)
	}

	if string(dg.Payload) != "hello" {
		t.Errorf("Payload: got %q, want %q", dg.Payload, "hello")
	}
}

func TestHandler_Listen_PortInUse(t *testing.T) {
	h := udp.NewHandler(newMockSender(), localIP)

	c1, err := h.Listen(7777)
	if err != nil {
		t.Fatalf("first Listen: %v", err)
	}
	defer c1.Close()

	_, err = h.Listen(7777)
	if !errors.Is(err, udp.ErrPortInUse) {
		t.Errorf("got %v, want ErrPortInUse", err)
	}
}

func TestHandler_Listen_UnknownPort_Drop(t *testing.T) {
	h := udp.NewHandler(newMockSender(), localIP)

	conn, _ := h.Listen(9999)
	defer conn.Close()

	// Deliver to port 8888 (no listener registered)
	frame := buildUDPFrame(t, remoteIP, localIP, 1111, 8888, []byte("drop me"))
	h.Deliver(remoteIP, localIP, frame)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := conn.ReadFrom(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected timeout, got %v", err)
	}
}

func TestHandler_BadChecksum_Drop(t *testing.T) {
	h := udp.NewHandler(newMockSender(), localIP)

	conn, _ := h.Listen(9999)
	defer conn.Close()

	frame := buildUDPFrame(t, remoteIP, localIP, 1, 9999, []byte("data"))
	frame[6] ^= 0xFF // corrupt checksum

	h.Deliver(remoteIP, localIP, frame)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := conn.ReadFrom(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected timeout (bad checksum dropped), got %v", err)
	}
}

func TestHandler_ZeroChecksum_Accepted(t *testing.T) {
	h := udp.NewHandler(newMockSender(), localIP)

	conn, _ := h.Listen(9999)
	defer conn.Close()

	// build frame with checksum = 0 (sender chose not to compute)
	length := uint16(udp.HeaderLen + 5)
	hdr := udp.Header{SrcPort: 1, DstPort: 9999, Length: length, Checksum: 0}
	buf := make([]byte, int(length))
	udp.Marshal(buf, hdr) //nolint:errcheck
	copy(buf[udp.HeaderLen:], "hello")

	h.Deliver(remoteIP, localIP, buf)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	dg, err := conn.ReadFrom(ctx)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(dg.Payload) != "hello" {
		t.Errorf("Payload: got %q, want %q", dg.Payload, "hello")
	}
}

func TestHandler_Dial(t *testing.T) {
	defer goleak.VerifyNone(t)

	h := udp.NewHandler(newMockSender(), localIP)
	remote := udp.Addr{IP: remoteIP, Port: 8080}

	c, err := h.Dial(context.Background(), remote)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if c.LocalAddr().IP != localIP {
		t.Errorf("LocalAddr IP: got %v, want %v", c.LocalAddr().IP, localIP)
	}
	if c.LocalAddr().Port < 40000 {
		t.Errorf("LocalAddr Port: got %d, expected ephemeral (>=40000)", c.LocalAddr().Port)
	}
	if c.RemoteAddr() == nil || *c.RemoteAddr() != remote {
		t.Errorf("RemoteAddr: got %v, want %v", c.RemoteAddr(), remote)
	}
}

func TestHandler_Dial_ConnectedFilter(t *testing.T) {
	defer goleak.VerifyNone(t)

	sender := newMockSender()
	h := udp.NewHandler(sender, localIP)
	remote := udp.Addr{IP: remoteIP, Port: 8080}

	conn, _ := h.Dial(context.Background(), remote)
	defer conn.Close()

	localPort := conn.LocalAddr().Port

	// frame from the correct remote should be delivered
	frame := buildUDPFrame(t, remoteIP, localIP, 8080, localPort, []byte("ok"))
	h.Deliver(remoteIP, localIP, frame)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	dg, err := conn.ReadFrom(ctx)
	if err != nil {
		t.Fatalf("ReadFrom (correct remote): %v", err)
	}

	if string(dg.Payload) != "ok" {
		t.Errorf("payload: got %q, want %q", dg.Payload, "ok")
	}

	// frame from a different source must NOT be delivered
	otherIP := [4]byte{10, 0, 0, 99}
	frame2 := buildUDPFrame(t, otherIP, localIP, 8080, localPort, []byte("nope"))
	h.Deliver(otherIP, localIP, frame2)

	ctx2, cancel2 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel2()
	_, err = conn.ReadFrom(ctx2)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected timeout for wrong source, got %v", err)
	}
}

func TestHandler_ConcurrentDial(t *testing.T) {
	defer goleak.VerifyNone(t)

	h := udp.NewHandler(newMockSender(), localIP)
	remote := udp.Addr{IP: remoteIP, Port: 8080}

	const n = 16
	conns := make([]*udp.Conn, n)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := h.Dial(context.Background(), remote)
			if err != nil {
				t.Errorf("Dial %d: %v", i, err)
				return
			}
			mu.Lock()
			conns[i] = c
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// all ports must be unique
	seen := make(map[uint16]bool)
	for _, c := range conns {
		if c == nil {
			continue
		}

		port := c.LocalAddr().Port
		if seen[port] {
			t.Errorf("duplicate ephemeral port %d", port)
		}

		seen[port] = true
		c.Close()
	}
}

func TestConn_ReadFrom_ContextCancel(t *testing.T) {
	defer goleak.VerifyNone(t)

	h := udp.NewHandler(newMockSender(), localIP)
	conn, _ := h.Listen(5555)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	_, err := conn.ReadFrom(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("got %v, want DeadlineExceeded", err)
	}
}

func TestConn_Close_UnblocksReadFrom(t *testing.T) {
	defer goleak.VerifyNone(t)

	h := udp.NewHandler(newMockSender(), localIP)
	conn, _ := h.Listen(6666)

	errCh := make(chan error, 1)
	go func() {
		_, err := conn.ReadFrom(context.Background())
		errCh <- err
	}()

	time.Sleep(5 * time.Millisecond)
	conn.Close()

	select {
	case err := <-errCh:
		if !errors.Is(err, udp.ErrConnClosed) {
			t.Errorf("got %v, want ErrConnClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock ReadFrom")
	}
}

func TestConn_Close_Idempotent(t *testing.T) {
	h := udp.NewHandler(newMockSender(), localIP)
	conn, _ := h.Listen(4444)
	if err := conn.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestConn_ReadFrom_AfterClose(t *testing.T) {
	defer goleak.VerifyNone(t)

	h := udp.NewHandler(newMockSender(), localIP)
	conn, _ := h.Listen(3333)
	conn.Close()

	_, err := conn.ReadFrom(context.Background())
	if !errors.Is(err, udp.ErrConnClosed) {
		t.Errorf("got %v, want ErrConnClosed", err)
	}
}

func TestConn_Write_NotConnected(t *testing.T) {
	h := udp.NewHandler(newMockSender(), localIP)
	conn, _ := h.Listen(2222)
	defer conn.Close()

	err := conn.Write(context.Background(), []byte("test"))
	if !errors.Is(err, udp.ErrNotConnected) {
		t.Errorf("got %v, want ErrNotConnected", err)
	}
}

func TestConn_Read_NotConnected(t *testing.T) {
	h := udp.NewHandler(newMockSender(), localIP)
	conn, _ := h.Listen(1111)
	defer conn.Close()

	_, err := conn.Read(context.Background())
	if !errors.Is(err, udp.ErrNotConnected) {
		t.Errorf("got %v, want ErrNotConnected", err)
	}
}

func TestConn_WriteTo_Sends(t *testing.T) {
	sender := newMockSender()
	h := udp.NewHandler(sender, localIP)

	conn, _ := h.Listen(9999)
	defer conn.Close()

	dst := udp.Addr{IP: remoteIP, Port: 8080}
	if err := conn.WriteTo(context.Background(), []byte("hello"), dst); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	sender.waitSent(t, 1)
	pkts := sender.Recorded()
	if pkts[0].dst != remoteIP {
		t.Errorf("dst IP: got %v, want %v", pkts[0].dst, remoteIP)
	}
	if pkts[0].proto != ip.ProtocolUDP {
		t.Errorf("proto: got %d, want UDP", pkts[0].proto)
	}

	// parse the sent UDP segment and verify fields
	sent, err := udp.Parse(pkts[0].data)
	if err != nil {
		t.Fatalf("parse sent segment: %v", err)
	}
	if sent.SrcPort != 9999 || sent.DstPort != 8080 {
		t.Errorf("ports: got %d→%d, want 9999→8080", sent.SrcPort, sent.DstPort)
	}
	if string(udp.Payload(pkts[0].data)) != "hello" {
		t.Errorf("payload: got %q, want %q", udp.Payload(pkts[0].data), "hello")
	}
}

func TestConn_Connected_ReadWrite(t *testing.T) {
	defer goleak.VerifyNone(t)

	sender := newMockSender()
	h := udp.NewHandler(sender, localIP)
	remote := udp.Addr{IP: remoteIP, Port: 8080}

	conn, _ := h.Dial(context.Background(), remote)
	defer conn.Close()

	localPort := conn.LocalAddr().Port

	// Write sends to the remote.
	if err := conn.Write(context.Background(), []byte("request")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	sender.waitSent(t, 1)
	pkts := sender.Recorded()
	sent, _ := udp.Parse(pkts[0].data)
	if sent.DstPort != 8080 {
		t.Errorf("DstPort: got %d, want 8080", sent.DstPort)
	}

	// simulate a reply from the remote
	replyFrame := buildUDPFrame(t, remoteIP, localIP, 8080, localPort, []byte("response"))
	h.Deliver(remoteIP, localIP, replyFrame)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reply, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(reply) != "response" {
		t.Errorf("reply: got %q, want %q", reply, "response")
	}
}

func TestConn_LocalAddr_String(t *testing.T) {
	a := udp.Addr{IP: [4]byte{192, 168, 1, 1}, Port: 8080}
	if a.String() != "192.168.1.1:8080" {
		t.Errorf("String: got %q, want %q", a.String(), "192.168.1.1:8080")
	}
}
