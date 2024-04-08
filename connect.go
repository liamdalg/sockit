package sockit

import (
	"log/slog"
	"net"
	"net/netip"
)

type Connect struct {
	socket net.Conn
	remote net.Conn
	bind   netip.AddrPort
	logger *slog.Logger
}

func establishConnect(socket net.Conn, dst netip.AddrPort, logger *slog.Logger) (*Connect, error) {
	remote, err := net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(dst))
	if err != nil {
		return nil, err
	}

	bind, err := netip.ParseAddrPort(remote.LocalAddr().String())
	if err != nil {
		return nil, err
	}

	logger = logger.With(slog.String("command", "CONNECT"), slog.String("bind", bind.String()))
	logger.Info("New CONNECT client established")

	return &Connect{
		socket: socket,
		remote: remote,
		bind:   bind,
		logger: logger,
	}, nil
}

func (c *Connect) Process() error {
	return copyStreams(c.socket, c.remote)
}

func (c *Connect) Bind() netip.AddrPort {
	return c.bind
}

func (c *Connect) Close() error {
	c.socket.Close()
	c.remote.Close()
	return nil
}
