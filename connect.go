package sockit

import (
	"net"
	"net/netip"
)

type connect struct {
	src net.Conn
	dst net.Conn
}

func (c *connect) Init(ip netip.AddrPort) (netip.AddrPort, error) {
	dst, err := net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(ip))
	if err != nil {
		return netip.AddrPort{}, err
	}

	bind, err := netip.ParseAddrPort(dst.LocalAddr().String())
	if err != nil {
		return netip.AddrPort{}, err
	}

	c.dst = dst

	return bind, nil
}

func (c *connect) Handle() error {
	return copyStreams(c.src, c.dst)
}
