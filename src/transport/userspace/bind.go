// Package userspace handles configuring nested, E2EE WireGuard tunnels in userspace.
package userspace

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Implement Bind from wireguard/conn.
// Adapted from UserspaceSocketBind in wireguard.conn.
// https://github.com/WireGuard/wireguard-go/blob/master/conn/bind_std.go
type UserspaceSocketBind struct {
	mu         sync.Mutex // protects following fields
	tnet       *netstack.Net
	ipv4       *gonet.UDPConn
	ipv6       *gonet.UDPConn
	blackhole4 bool
	blackhole6 bool
}

func NewBind(tnet *netstack.Net) conn.Bind {
	return &UserspaceSocketBind{tnet: tnet}
}

type UserspaceEndpoint netip.AddrPort

func (*UserspaceSocketBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	return asEndpoint(e), err
}

func (UserspaceEndpoint) ClearSrc() {}

func (e UserspaceEndpoint) DstIP() netip.Addr {
	return (netip.AddrPort)(e).Addr()
}

func (e UserspaceEndpoint) SrcIP() netip.Addr {
	return netip.Addr{} // not supported
}

func (e UserspaceEndpoint) DstToBytes() []byte {
	b, _ := (netip.AddrPort)(e).MarshalBinary()
	return b
}

func (e UserspaceEndpoint) DstToString() string {
	return (netip.AddrPort)(e).String()
}

func (e UserspaceEndpoint) SrcToString() string {
	return ""
}

func listenNet(tnet *netstack.Net, network string, port int) (*gonet.UDPConn, int, error) {
	var pn tcpip.NetworkProtocolNumber
	switch network {
	case "udp4":
		pn = ipv4.ProtocolNumber
	case "udp6":
		pn = ipv6.ProtocolNumber
	default:
		return nil, port, errors.New("invalid network string")
	}

	var wq waiter.Queue
	ep, terr := tnet.Stack().NewEndpoint(udp.ProtocolNumber, pn, &wq)
	if terr != nil {
		return nil, port, errors.New(terr.String())
	}

	// Match Go's net.ListenPacket("udp6", ...) / WireGuard StdNetBind:
	// an IPv6 wildcard bind is dual-stack in gVisor unless V6Only is set,
	// which would also reserve the IPv4 port.
	if pn == ipv6.ProtocolNumber {
		ep.SocketOptions().SetV6Only(true)
	}

	if terr := ep.Bind(tcpip.FullAddress{NIC: 1, Port: uint16(port)}); terr != nil {
		ep.Close()
		return nil, port, &net.OpError{
			Op:  "bind",
			Net: network,
			Err: errors.New(terr.String()),
		}
	}

	conn := gonet.NewUDPConn(&wq, ep)

	// Retrieve port.
	laddr := conn.LocalAddr()
	uaddr, err := net.ResolveUDPAddr(
		laddr.Network(),
		laddr.String(),
	)
	if err != nil {
		_ = conn.Close()
		return nil, port, err
	}
	return conn, uaddr.Port, nil
}

func (bind *UserspaceSocketBind) Open(uport uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	var err error

	if bind.ipv4 != nil || bind.ipv6 != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	// Attempt to open ipv4 and ipv6 listeners on the same port.
	port := int(uport)
	var ipv4, ipv6 *gonet.UDPConn

	ipv4, port, err = listenNet(bind.tnet, "udp4", port)
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		return nil, 0, err
	}

	ipv6, port, err = listenNet(bind.tnet, "udp6", port)
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		if ipv4 != nil {
			_ = ipv4.Close()
		}
		return nil, 0, err
	}

	var fns []conn.ReceiveFunc
	if ipv4 != nil {
		fns = append(fns, bind.makeReceive(ipv4))
		bind.ipv4 = ipv4
	}
	if ipv6 != nil {
		fns = append(fns, bind.makeReceive(ipv6))
		bind.ipv6 = ipv6
	}
	if len(fns) == 0 {
		return nil, 0, syscall.EAFNOSUPPORT
	}
	return fns, uint16(port), nil
}

func (bind *UserspaceSocketBind) BatchSize() int {
	return 1
}

func (bind *UserspaceSocketBind) Close() error {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	var err1, err2 error
	if bind.ipv4 != nil {
		err1 = bind.ipv4.Close()
		bind.ipv4 = nil
	}
	if bind.ipv6 != nil {
		err2 = bind.ipv6.Close()
		bind.ipv6 = nil
	}
	bind.blackhole4 = false
	bind.blackhole6 = false
	if err1 != nil {
		return err1
	}
	return err2
}

func (bind *UserspaceSocketBind) SetMark(mark uint32) error {
	return nil
}

func (*UserspaceSocketBind) makeReceive(c *gonet.UDPConn) conn.ReceiveFunc {
	return func(buffs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, endpointAsAddr, err := c.ReadFrom(buffs[0])
		if err != nil {
			return 0, err
		}

		sizes[0] = n
		eps[0] = asEndpoint(netip.MustParseAddrPort(endpointAsAddr.String()))
		return 1, err
	}
}

func (bind *UserspaceSocketBind) Send(buff [][]byte, endpoint conn.Endpoint) error {
	var err error
	nend, ok := endpoint.(UserspaceEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	addrPort := netip.AddrPort(nend)

	bind.mu.Lock()
	blackhole := bind.blackhole4
	conn := bind.ipv4
	if addrPort.Addr().Is6() {
		blackhole = bind.blackhole6
		conn = bind.ipv6
	}
	bind.mu.Unlock()

	if blackhole {
		return nil
	}
	if conn == nil {
		return syscall.EAFNOSUPPORT
	}
	addr, err := net.ResolveUDPAddr("udp", addrPort.String())
	if err != nil {
		return err
	}
	for _, p := range buff {
		_, err = conn.WriteTo(p, addr)
		if err != nil {
			return err
		}
	}

	return nil
}

// endpointPool contains a re-usable set of mapping from netip.AddrPort to conn.Endpoint.
// This exists to reduce allocations: Putting a netip.AddrPort in an conn.Endpoint allocates,
// but conn.Endpoints are immutable, so we can re-use them.
var endpointPool = sync.Pool{
	New: func() any {
		return make(map[netip.AddrPort]conn.Endpoint)
	},
}

// asEndpoint returns an conn.Endpoint containing ap.
func asEndpoint(ap netip.AddrPort) conn.Endpoint {
	m := endpointPool.Get().(map[netip.AddrPort]conn.Endpoint)
	defer endpointPool.Put(m)
	e, ok := m[ap]
	if !ok {
		e = conn.Endpoint(UserspaceEndpoint(ap))
		m[ap] = e
	}
	return e
}
