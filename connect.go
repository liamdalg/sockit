package sockit

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"golang.org/x/net/proxy"
)

type Connect struct {
	socket net.Conn
	remote net.Conn
	bind   netip.AddrPort
	logger *slog.Logger
}

func establishConnect(dialer proxy.Dialer, socket net.Conn, dst netip.AddrPort, logger *slog.Logger) (*Connect, error) {
	remote, err := dialer.Dial("tcp", dst.String())
	if err != nil {
		return nil, fmt.Errorf("failed to dial tcp: %w", err)
	}

	bind, err := netip.ParseAddrPort(remote.LocalAddr().String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse tcp address: %w", err)
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
