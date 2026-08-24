package userspace

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func newTestNet(t *testing.T, addrs ...string) *netstack.Net {
	t.Helper()
	ips := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, netip.MustParseAddr(a))
	}
	dev, tnet, err := netstack.CreateNetTUN(ips, nil, 1280)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	t.Cleanup(func() {
		_ = dev.Close()
	})
	return tnet
}

func udpPort(t *testing.T, addr net.Addr) uint16 {
	t.Helper()
	uaddr, err := net.ResolveUDPAddr(addr.Network(), addr.String())
	if err != nil {
		t.Fatalf("ResolveUDPAddr(%q): %v", addr, err)
	}
	return uint16(uaddr.Port)
}

func TestUserspaceSocketBindOpenDualStack(t *testing.T) {
	tnet := newTestNet(t, "10.44.0.1", "fd44::1")
	bind := NewBind(tnet).(*UserspaceSocketBind)

	fns, port, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = bind.Close() })

	if port == 0 {
		t.Fatal("Open returned port 0")
	}
	if len(fns) != 2 {
		t.Fatalf("receive funcs: got %d, want 2", len(fns))
	}
	if bind.ipv4 == nil || bind.ipv6 == nil {
		t.Fatal("expected both ipv4 and ipv6 sockets")
	}
	if bind.ipv4 == bind.ipv6 {
		t.Fatal("ipv4 and ipv6 sockets must be distinct")
	}

	p4 := udpPort(t, bind.ipv4.LocalAddr())
	p6 := udpPort(t, bind.ipv6.LocalAddr())
	if p4 != port || p6 != port {
		t.Fatalf("mismatched ports: returned=%d ipv4=%d ipv6=%d", port, p4, p6)
	}

	if _, _, err := bind.Open(0); !errors.Is(err, conn.ErrBindAlreadyOpen) {
		t.Fatalf("second Open: got %v, want ErrBindAlreadyOpen", err)
	}
}

func TestUserspaceSocketBindExplicitPort(t *testing.T) {
	tnet := newTestNet(t, "10.44.0.1", "fd44::1")
	bind := NewBind(tnet).(*UserspaceSocketBind)

	const want = uint16(51820)
	fns, port, err := bind.Open(want)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = bind.Close() })

	if port != want {
		t.Fatalf("port: got %d, want %d", port, want)
	}
	if len(fns) != 2 {
		t.Fatalf("receive funcs: got %d, want 2", len(fns))
	}
	if udpPort(t, bind.ipv4.LocalAddr()) != want {
		t.Fatalf("ipv4 port: got %d, want %d", udpPort(t, bind.ipv4.LocalAddr()), want)
	}
	if udpPort(t, bind.ipv6.LocalAddr()) != want {
		t.Fatalf("ipv6 port: got %d, want %d", udpPort(t, bind.ipv6.LocalAddr()), want)
	}
}

func TestUserspaceSocketBindCloseClearsBoth(t *testing.T) {
	tnet := newTestNet(t, "10.44.0.1", "fd44::1")
	bind := NewBind(tnet).(*UserspaceSocketBind)

	if _, _, err := bind.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := bind.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if bind.ipv4 != nil || bind.ipv6 != nil {
		t.Fatal("Close left sockets set")
	}

	fns, port, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open after Close: %v", err)
	}
	t.Cleanup(func() { _ = bind.Close() })
	if len(fns) != 2 || port == 0 || bind.ipv4 == nil || bind.ipv6 == nil {
		t.Fatal("Open after Close did not recreate dual-stack sockets")
	}
}

func TestUserspaceSocketBindSendAndReceive(t *testing.T) {
	v4 := netip.MustParseAddr("10.44.0.1")
	v6 := netip.MustParseAddr("fd44::1")
	tnet := newTestNet(t, v4.String(), v6.String())
	bind := NewBind(tnet).(*UserspaceSocketBind)

	fns, port, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = bind.Close() })
	if len(fns) != 2 {
		t.Fatalf("receive funcs: got %d, want 2", len(fns))
	}

	type recvd struct {
		n   int
		ep  conn.Endpoint
		err error
		buf []byte
	}
	recv := func(fn conn.ReceiveFunc) recvd {
		buf := make([]byte, 1500)
		sizes := make([]int, 1)
		eps := make([]conn.Endpoint, 1)
		n, err := fn([][]byte{buf}, sizes, eps)
		out := recvd{n: n, err: err, buf: buf[:sizes[0]]}
		if err == nil {
			out.ep = eps[0]
		}
		return out
	}

	got4 := make(chan recvd, 1)
	got6 := make(chan recvd, 1)
	go func() { got4 <- recv(fns[0]) }()
	go func() { got6 <- recv(fns[1]) }()

	// Give the receive goroutines time to block in ReadFrom before sending.
	time.Sleep(50 * time.Millisecond)

	c4, err := tnet.DialUDPAddrPort(
		netip.AddrPortFrom(v4, 40000),
		netip.AddrPortFrom(v4, port),
	)
	if err != nil {
		t.Fatalf("DialUDP IPv4: %v", err)
	}
	defer func() { _ = c4.Close() }()
	c6, err := tnet.DialUDPAddrPort(
		netip.AddrPortFrom(v6, 40000),
		netip.AddrPortFrom(v6, port),
	)
	if err != nil {
		t.Fatalf("DialUDP IPv6: %v", err)
	}
	defer func() { _ = c6.Close() }()

	if _, err := c4.Write([]byte("hello4")); err != nil {
		t.Fatalf("Write IPv4: %v", err)
	}
	if _, err := c6.Write([]byte("hello6")); err != nil {
		t.Fatalf("Write IPv6: %v", err)
	}

	select {
	case r := <-got4:
		if r.err != nil {
			t.Fatalf("IPv4 receive: %v", r.err)
		}
		if !bytes.Equal(r.buf, []byte("hello4")) {
			t.Fatalf("IPv4 payload: got %q", r.buf)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for IPv4 receive")
	}
	select {
	case r := <-got6:
		if r.err != nil {
			t.Fatalf("IPv6 receive: %v", r.err)
		}
		if !bytes.Equal(r.buf, []byte("hello6")) {
			t.Fatalf("IPv6 payload: got %q", r.buf)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for IPv6 receive")
	}

	l4, err := tnet.ListenUDPAddrPort(netip.AddrPortFrom(v4, 0))
	if err != nil {
		t.Fatalf("ListenUDP IPv4: %v", err)
	}
	defer func() { _ = l4.Close() }()
	l6, err := tnet.ListenUDPAddrPort(netip.AddrPortFrom(v6, 0))
	if err != nil {
		t.Fatalf("ListenUDP IPv6: %v", err)
	}
	defer func() { _ = l6.Close() }()

	dst4 := UserspaceEndpoint(netip.AddrPortFrom(v4, udpPort(t, l4.LocalAddr())))
	dst6 := UserspaceEndpoint(netip.AddrPortFrom(v6, udpPort(t, l6.LocalAddr())))
	if err := bind.Send([][]byte{[]byte("from4")}, dst4); err != nil {
		t.Fatalf("Send IPv4: %v", err)
	}
	if err := bind.Send([][]byte{[]byte("from6")}, dst6); err != nil {
		t.Fatalf("Send IPv6: %v", err)
	}

	_ = l4.SetReadDeadline(time.Now().Add(2 * time.Second))
	_ = l6.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := l4.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Read IPv4 dest: %v", err)
	}
	if !bytes.Equal(buf[:n], []byte("from4")) {
		t.Fatalf("IPv4 dest payload: got %q", buf[:n])
	}
	n, _, err = l6.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Read IPv6 dest: %v", err)
	}
	if !bytes.Equal(buf[:n], []byte("from6")) {
		t.Fatalf("IPv6 dest payload: got %q", buf[:n])
	}
}
