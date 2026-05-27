// Command ping sends ICMP echo requests using the userspace TCP/IP stack.
//
// It requires CAP_NET_ADMIN (or root) to open a TAP interface.
//
// Usage:
//
//	sudo go run ./examples/ping -iface tap0 -src 10.0.0.2 -dst 10.0.0.1 -count 4
//
// Before running, create and configure the TAP device on the host:
//
//	sudo ip tuntap add mode tap tap0
//	sudo ip addr add 10.0.0.1/24 dev tap0
//	sudo ip link set tap0 up
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rykth/tcp-ip-stack/pkg/arp"
	"github.com/rykth/tcp-ip-stack/pkg/ethernet"
	"github.com/rykth/tcp-ip-stack/pkg/icmp"
	"github.com/rykth/tcp-ip-stack/pkg/ip"
	netpkg "github.com/rykth/tcp-ip-stack/pkg/net"
	"github.com/rykth/tcp-ip-stack/pkg/raw/tuntap"
)

func main() {
	ifaceName := flag.String("iface", "tap0", "TAP interface name (must already exist)")
	srcStr := flag.String("src", "10.0.0.2", "source IPv4 address assigned to the TAP interface")
	dstStr := flag.String("dst", "10.0.0.1", "destination IPv4 address to ping")
	count := flag.Int("count", 4, "number of echo requests to send")
	timeout := flag.Duration("timeout", 3*time.Second, "per-ping timeout")
	interval := flag.Duration("interval", time.Second, "interval between pings")
	flag.Parse()

	srcIP, err := parseIPv4(*srcStr)
	if err != nil {
		log.Fatalf("invalid -src: %v", err)
	}

	dstIP, err := parseIPv4(*dstStr)
	if err != nil {
		log.Fatalf("invalid -dst: %v", err)
	}

	dev, err := tuntap.New(*ifaceName, tuntap.DeviceTAP)
	if err != nil {
		log.Fatalf("open TAP %q: %v\n(hint: run with sudo, and create the interface first)", *ifaceName, err)
	}

	// assign a locally administered MAC address to this virtual interface
	localMAC := ethernet.Addr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01}

	arpH := arp.NewHandler(localMAC, srcIP, dev)

	table := ip.NewTable()
	lanNet, err := ip.ParseNetwork("0.0.0.0/0")
	if err != nil {
		log.Fatalf("parse network: %v", err)
	}

	table.Add(ip.Route{Network: lanNet, Dev: dev})

	ipH := ip.NewHandler(localMAC, srcIP, arpH, table)
	icmpH := icmp.NewHandler(ipH)
	if err := ipH.RegisterUpper(icmpH); err != nil {
		log.Fatalf("register ICMP: %v", err)
	}

	r := netpkg.New()
	if err := r.AddDevice(dev); err != nil {
		log.Fatalf("AddDevice: %v", err)
	}
	if err := r.AddHandler(arpH); err != nil {
		log.Fatalf("AddHandler(arp): %v", err)
	}
	if err := r.AddHandler(ipH); err != nil {
		log.Fatalf("AddHandler(ip): %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println()
		cancel()
	}()

	stackDone := make(chan error, 1)
	go func() {
		stackDone <- r.Start(ctx)
	}()

	// give the stack a moment to initialise before sending
	time.Sleep(50 * time.Millisecond)

	fmt.Printf("PING %v from %v via %s\n", *dstStr, *srcStr, *ifaceName)

	sent, received := 0, 0
	for i := 1; i <= *count; i++ {
		select {
		case <-ctx.Done():
			goto done
		default:
		}

		pingCtx, pingCancel := context.WithTimeout(ctx, *timeout)
		rtt, err := icmpH.Ping(pingCtx, dstIP)
		pingCancel()

		sent++
		if err != nil {
			fmt.Printf("ping seq=%d: %v\n", i, err)
		} else {
			received++
			fmt.Printf("reply seq=%d time=%v\n", i, rtt.Round(time.Microsecond))
		}

		if i < *count {
			select {
			case <-ctx.Done():
				goto done
			case <-time.After(*interval):
			}
		}
	}

done:
	loss := 100
	if sent > 0 {
		loss = (sent - received) * 100 / sent
	}
	fmt.Printf("\n--- %s ping statistics ---\n", *dstStr)
	fmt.Printf("%d packets transmitted, %d received, %d%% packet loss\n", sent, received, loss)

	cancel()
	if err := <-stackDone; err != nil {
		log.Fatalf("stack error: %v", err)
	}
}

func parseIPv4(s string) ([4]byte, error) {
	var a, b, c, d int
	n, err := fmt.Sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d)
	if err != nil || n != 4 || a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255 {
		return [4]byte{}, fmt.Errorf("invalid IPv4 address %q", s)
	}
	return [4]byte{byte(a), byte(b), byte(c), byte(d)}, nil
}
