package icmp_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/rykth/tcp-ip-stack/pkg/icmp"
	"github.com/rykth/tcp-ip-stack/pkg/ip"
)

var (
	ipA = [4]byte{10, 0, 0, 1}
	ipB = [4]byte{10, 0, 0, 2}
)

type sentPacket struct {
	dst     [4]byte
	proto   ip.Protocol
	payload []byte
}

type mockSender struct {
	mu      sync.Mutex
	packets []sentPacket
	notify  chan struct{}
	err     error // if set, Send returns this error
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

func buildRequest(t *testing.T, id, seq uint16, data []byte) []byte {
	t.Helper()
	p := icmp.Packet{Type: icmp.TypeEchoRequest, ID: id, Seq: seq, Data: data}
	buf := make([]byte, icmp.HeaderLen+len(data))
	if _, err := icmp.Marshal(buf, p); err != nil {
		t.Fatalf("Marshal echo request: %v", err)
	}
	return buf
}

func buildReply(t *testing.T, id, seq uint16, data []byte) []byte {
	t.Helper()
	p := icmp.Packet{Type: icmp.TypeEchoReply, ID: id, Seq: seq, Data: data}
	buf := make([]byte, icmp.HeaderLen+len(data))
	if _, err := icmp.Marshal(buf, p); err != nil {
		t.Fatalf("Marshal echo reply: %v", err)
	}
	return buf
}

func TestParse_ValidEchoRequest(t *testing.T) {
	raw := buildRequest(t, 0x1234, 0x0001, []byte("hello"))
	p, err := icmp.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if p.Type != icmp.TypeEchoRequest {
		t.Errorf("Type: got %d, want EchoRequest", p.Type)
	}
	if p.ID != 0x1234 {
		t.Errorf("ID: got %#x, want 0x1234", p.ID)
	}
	if p.Seq != 0x0001 {
		t.Errorf("Seq: got %d, want 1", p.Seq)
	}
	if string(p.Data) != "hello" {
		t.Errorf("Data: got %q, want %q", p.Data, "hello")
	}
}

func TestParse_ValidEchoReply(t *testing.T) {
	raw := buildReply(t, 0xABCD, 0x0005, []byte{0xde, 0xad})
	p, err := icmp.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if p.Type != icmp.TypeEchoReply {
		t.Errorf("Type: got %d, want EchoReply", p.Type)
	}
	if p.ID != 0xABCD {
		t.Errorf("ID: got %#x, want 0xABCD", p.ID)
	}
}

func TestParse_TooShort(t *testing.T) {
	_, err := icmp.Parse(make([]byte, icmp.HeaderLen-1))
	if !errors.Is(err, icmp.ErrPacketTooShort) {
		t.Errorf("got %v, want ErrPacketTooShort", err)
	}
}

func TestParse_BadChecksum(t *testing.T) {
	raw := buildRequest(t, 1, 1, []byte("data"))
	raw[2] ^= 0xFF // corrupt the checksum
	_, err := icmp.Parse(raw)
	if !errors.Is(err, icmp.ErrBadChecksum) {
		t.Errorf("got %v, want ErrBadChecksum", err)
	}
}

func TestParse_EmptyData(t *testing.T) {
	raw := buildRequest(t, 1, 0, nil)
	p, err := icmp.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(p.Data) != 0 {
		t.Errorf("expected nil/empty Data, got %d bytes", len(p.Data))
	}
}

func TestMarshal_RoundTrip(t *testing.T) {
	cases := []icmp.Packet{
		{Type: icmp.TypeEchoRequest, Code: 0, ID: 0x1234, Seq: 7, Data: []byte("roundtrip")},
		{Type: icmp.TypeEchoReply, Code: 0, ID: 0xABCD, Seq: 42, Data: nil},
		{Type: icmp.TypeEchoRequest, Code: 0, ID: 1, Seq: 0, Data: []byte{0x00, 0xFF}},
	}
	for _, want := range cases {
		buf := make([]byte, icmp.HeaderLen+len(want.Data))

		n, err := icmp.Marshal(buf, want)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}

		got, err := icmp.Parse(buf[:n])
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if got.Type != want.Type || got.ID != want.ID || got.Seq != want.Seq {
			t.Errorf("round-trip: got %+v, want %+v", got, want)
		}
		if string(got.Data) != string(want.Data) {
			t.Errorf("Data round-trip: got %v, want %v", got.Data, want.Data)
		}
	}
}

func TestMarshal_TooSmall(t *testing.T) {
	_, err := icmp.Marshal(make([]byte, icmp.HeaderLen-1), icmp.Packet{})
	if !errors.Is(err, icmp.ErrPacketTooShort) {
		t.Errorf("got %v, want ErrPacketTooShort", err)
	}
}

func TestMarshal_PayloadIsCopied(t *testing.T) {
	data := []byte{1, 2, 3}
	p := icmp.Packet{Type: icmp.TypeEchoRequest, ID: 1, Data: data}
	buf := make([]byte, icmp.HeaderLen+len(data))
	icmp.Marshal(buf, p) //nolint:errcheck

	// mutate original data (marshalled bytes should be unaffected)
	data[0] = 0xFF
	got, _ := icmp.Parse(buf)
	if got.Data[0] == 0xFF {
		t.Error("marshal did not copy data before encoding")
	}
}

func TestHandler_RepliesTo_EchoRequest(t *testing.T) {
	defer goleak.VerifyNone(t)

	sender := newMockSender()
	h := icmp.NewHandler(sender)

	request := buildRequest(t, 0x0042, 3, []byte("ping"))
	h.Deliver(ipB, ipA, request)

	// the reply is sent in a goroutine; wait for it
	sender.waitSent(t, 1)

	pkts := sender.Recorded()
	if len(pkts) == 0 {
		t.Fatal("no packet sent")
	}
	if pkts[0].dst != ipB {
		t.Errorf("reply dst: got %v, want %v", pkts[0].dst, ipB)
	}
	if pkts[0].proto != ip.ProtocolICMP {
		t.Errorf("reply proto: got %d, want ICMP", pkts[0].proto)
	}

	// parse and verify the reply
	reply, err := icmp.Parse(pkts[0].payload)
	if err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	if reply.Type != icmp.TypeEchoReply {
		t.Errorf("Type: got %d, want EchoReply", reply.Type)
	}
	if reply.ID != 0x0042 {
		t.Errorf("ID: got %#x, want 0x0042", reply.ID)
	}
	if reply.Seq != 3 {
		t.Errorf("Seq: got %d, want 3", reply.Seq)
	}
	if string(reply.Data) != "ping" {
		t.Errorf("Data: got %q, want %q", reply.Data, "ping")
	}
}

func TestHandler_Ignores_Malformed(t *testing.T) {
	sender := newMockSender()
	h := icmp.NewHandler(sender)
	h.Deliver(ipB, ipA, []byte{0x08}) // too short
	time.Sleep(10 * time.Millisecond)
	if n := len(sender.Recorded()); n != 0 {
		t.Errorf("expected 0 sends for malformed packet, got %d", n)
	}
}

func TestHandler_Ping_CacheMiss(t *testing.T) {
	defer goleak.VerifyNone(t)

	sender := newMockSender()
	h := icmp.NewHandler(sender)

	rttCh := make(chan time.Duration, 1)
	errCh := make(chan error, 1)
	go func() {
		rtt, err := h.Ping(context.Background(), ipB)
		rttCh <- rtt
		errCh <- err
	}()

	sender.waitSent(t, 1)

	// parse the request to extract the ID, then inject a matching reply
	pkts := sender.Recorded()
	req, err := icmp.Parse(pkts[0].payload)
	if err != nil {
		t.Fatalf("parse sent request: %v", err)
	}
	if req.Type != icmp.TypeEchoRequest {
		t.Fatalf("expected EchoRequest, got type %d", req.Type)
	}

	// deliver a matching reply
	replyPayload := buildReply(t, req.ID, req.Seq, req.Data)
	h.Deliver(ipB, ipA, replyPayload)

	select {
	case rtt := <-rttCh:
		if err := <-errCh; err != nil {
			t.Fatalf("Ping returned error: %v", err)
		}
		if rtt <= 0 {
			t.Errorf("RTT should be positive, got %v", rtt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Ping did not return after reply was injected")
	}
}

func TestHandler_Ping_Timeout(t *testing.T) {
	defer goleak.VerifyNone(t)

	sender := newMockSender()
	h := icmp.NewHandler(sender)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	_, err := h.Ping(ctx, ipB)
	if !errors.Is(err, icmp.ErrPingTimeout) {
		t.Errorf("got %v, want ErrPingTimeout", err)
	}
}

func TestHandler_Ping_ConcurrentIDs(t *testing.T) {
	defer goleak.VerifyNone(t)

	sender := newMockSender()
	h := icmp.NewHandler(sender)

	const n = 4
	type result struct {
		rtt time.Duration
		err error
	}
	results := make(chan result, n)

	for range n {
		go func() {
			rtt, err := h.Ping(context.Background(), ipB)
			results <- result{rtt, err}
		}()
	}

	sender.waitSent(t, n)

	pkts := sender.Recorded()
	for i := n - 1; i >= 0; i-- {
		req, err := icmp.Parse(pkts[i].payload)
		if err != nil {
			t.Fatalf("parse request %d: %v", i, err)
		}
		reply := buildReply(t, req.ID, req.Seq, req.Data)
		h.Deliver(ipB, ipA, reply)
	}

	for range n {
		select {
		case r := <-results:
			if r.err != nil {
				t.Errorf("Ping error: %v", r.err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for all Pings to resolve")
		}
	}
}

func TestHandler_Protocol(t *testing.T) {
	h := icmp.NewHandler(newMockSender())
	if h.Protocol() != ip.ProtocolICMP {
		t.Errorf("Protocol: got %d, want %d", h.Protocol(), ip.ProtocolICMP)
	}
}
