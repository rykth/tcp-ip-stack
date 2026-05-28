// Command udp-echo demonstrates a UDP echo exchange using the userspace TCP/IP stack.
//
// By default it runs a full loopback echo test entirely within one process - no
// root access or TAP device required. A server goroutine listens on UDP port
// 9999; a client goroutine sends N messages and prints each echoed reply.
//
// Usage:
//
//	go run ./examples/udp-echo
//	go run ./examples/udp-echo -count 10 -port 7777
//
// To use a real TAP device instead of loopback (requires CAP_NET_ADMIN):
//
//	sudo ip tuntap add mode tap tap0
//	sudo ip addr add 10.0.0.1/24 dev tap0
//	sudo ip link set tap0 up
//	sudo go run ./examples/udp-echo -iface tap0 -src 10.0.0.2 -port 9999
//
//	# Then from the host:
//
//	# GNU netcat: wait 1s after EOF before quitting
//	echo "hello" | nc -u -q 1 10.0.0.2 9999
//
//	# OpenBSD nc: quit after receiving 1 packet (or 1s timeout)
//	echo "hello" | nc -u -W 1 -w 1 10.0.0.2 9999
//
//	# ncat (nmap) is the most reliable UDP client
//	echo "hello" | ncat -u 10.0.0.2 9999
//
//	# Or interactive — just type and press Enter
//	nc -u 10.0.0.2 9999
//
// In TAP mode the program runs the echo server only and waits for SIGINT,
// since packets sent to our own address would go out on the wire rather than
// looping back through the stack.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rykth/tcp-ip-stack/pkg/arp"
	"github.com/rykth/tcp-ip-stack/pkg/ethernet"
	"github.com/rykth/tcp-ip-stack/pkg/ip"
	"github.com/rykth/tcp-ip-stack/pkg/loopback"
	netpkg "github.com/rykth/tcp-ip-stack/pkg/net"
	"github.com/rykth/tcp-ip-stack/pkg/raw/tuntap"
	"github.com/rykth/tcp-ip-stack/pkg/udp"
)

func main() {
	iface := flag.String("iface", "", "TAP device name (e.g. tap0); empty uses in-process loopback")
	srcStr := flag.String("src", "10.0.0.1", "local IPv4 address for the stack")
	serverPort := flag.Uint("port", 9999, "UDP port the echo server listens on")
	count := flag.Int("count", 5, "number of echo messages to send (loopback mode only)")
	flag.Parse()

	addr, err := netip.ParseAddr(*srcStr)
	if err != nil || !addr.Is4() {
		log.Fatalf("parse src IP %q: invalid IPv4 address", *srcStr)
	}
	localIP := addr.As4()
	localMAC := ethernet.Addr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	useTAP := *iface != ""

	var dev netpkg.LinkDevice
	if useTAP {
		tap, err := tuntap.New(*iface, tuntap.DeviceTAP)
		if err != nil {
			log.Fatalf("open TAP %q: %v", *iface, err)
		}
		defer tap.Close()
		dev = tap
	} else {
		dev = loopback.New()
	}

	var arpOpts []arp.HandlerOption
	if !useTAP {
		// pre-populate the ARP cache so Resolve returns immediately on loopback
		// (no broadcast is possible on a loopback device)
		cache := arp.NewCache(arp.WithTTL(time.Hour))
		cache.Store(localIP, localMAC)
		arpOpts = append(arpOpts, arp.WithHandlerCache(cache))
	}
	arpH := arp.NewHandler(localMAC, localIP, dev, arpOpts...)

	table := ip.NewTable()
	net0, err := ip.ParseNetwork("0.0.0.0/0")
	if err != nil {
		log.Fatalf("parse network: %v", err)
	}
	table.Add(ip.Route{Network: net0, Dev: dev})

	ipH := ip.NewHandler(localMAC, localIP, arpH, table)
	udpH := udp.NewHandler(ipH, localIP)
	if err := ipH.RegisterUpper(udpH); err != nil {
		log.Fatalf("register UDP: %v", err)
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

	stackDone := make(chan error, 1)
	go func() {
		stackDone <- r.Start(ctx)
	}()

	// allow the stack goroutines to start before sending
	time.Sleep(10 * time.Millisecond)

	// server: echo datagrams back to sender
	port := uint16(*serverPort)
	server, err := udpH.Listen(port)
	if err != nil {
		log.Fatalf("listen :%d: %v", port, err)
	}
	defer server.Close()

	go func() {
		for {
			dg, err := server.ReadFrom(ctx)
			if err != nil {
				return // ctx cancelled or server closed
			}
			if err := server.WriteTo(ctx, dg.Payload, dg.Src); err != nil {
				log.Printf("server WriteTo: %v", err)
			}
		}
	}()

	if useTAP {
		fmt.Printf("UDP echo - listening on %s:%d via %s; Ctrl+C to exit\n",
			netip.AddrFrom4(localIP), port, *iface)
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		fmt.Println("\nshutting down")
		cancel()
		<-stackDone
		return
	}

	// cient: dial the server and exchange messages
	serverAddr := udp.Addr{IP: localIP, Port: port}
	client, err := udpH.Dial(ctx, serverAddr)
	if err != nil {
		log.Fatalf("dial %v: %v", serverAddr, err)
	}
	defer client.Close()

	fmt.Printf("UDP echo - %d messages via loopback (server :%d, client :%d)\n\n",
		*count, port, client.LocalAddr().Port)

	sent, received := 0, 0
	for i := 1; i <= *count; i++ {
		msg := fmt.Sprintf("message-%d", i)

		if err := client.Write(ctx, []byte(msg)); err != nil {
			log.Printf("write %d: %v", i, err)
			sent++
			continue
		}
		sent++

		rCtx, rCancel := context.WithTimeout(ctx, 2*time.Second)
		reply, err := client.Read(rCtx)
		rCancel()
		if err != nil {
			fmt.Printf("seq=%d send=%q recv=<timeout: %v>\n", i, msg, err)
		} else {
			received++
			fmt.Printf("seq=%d send=%q recv=%q\n", i, msg, string(reply))
		}
	}

	fmt.Printf("\n%d sent, %d received, %d%% loss\n",
		sent, received, loss(sent, received))

	cancel()
	if err := <-stackDone; err != nil {
		log.Fatalf("stack: %v", err)
	}
}

func loss(sent, received int) int {
	if sent == 0 {
		return 0
	}
	return (sent - received) * 100 / sent
}
