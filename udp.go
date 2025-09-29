package sockit

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
)

type UDP struct {
	socket   *net.UDPConn
	resolver *net.Resolver
	bind     netip.AddrPort
	logger   *slog.Logger
}

// in practice this is probably way too large.
const maxBufferSize = 65507

func establishUDP(dst netip.AddrPort, logger *slog.Logger) (*UDP, error) {
	socket, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   dst.Addr().AsSlice(),
		Port: 0,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create udp listener: %w", err)
	}

	bind, err := netip.ParseAddrPort(socket.LocalAddr().String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse udp address: %w", err)
	}

	logger = logger.With(slog.String("mode", "udp"), slog.String("bind", bind.String()))
	logger.Info("New UDP client established")

	return &UDP{
		socket: socket,
		bind:   bind,
		logger: logger,
	}, nil
}

func (u *UDP) Process() error {
	if err := u.beginForwarding(); err != nil {
		var reason string
		if errors.Is(err, net.ErrClosed) {
			reason = "closed"
		} else {
			reason = "error: " + err.Error()
		}
		u.logger.Info("UDP client disconnected", slog.String("reason", reason))
	}

	return nil
}

func (u *UDP) Bind() netip.AddrPort {
	return u.bind
}

func (u *UDP) Close() error {
	//nolint:wrapcheck
	return u.socket.Close()
}

func (u *UDP) beginForwarding() error {
	buf := make([]byte, maxBufferSize)
	for {
		n, _, _, _, err := u.socket.ReadMsgUDPAddrPort(buf, nil)
		if err != nil {
			return fmt.Errorf("failed to read UDP message: %w", err)
		}

		err = u.forwardMessage(buf[:n])
		if err != nil {
			u.logger.Error("Caught error when processing datagram", slog.String("error", err.Error()))
		}
	}
}

func (u *UDP) forwardMessage(datagram []byte) error {
	// TODO: support filtering by source address
	if datagram[0] != 0x00 && datagram[1] != 0x00 {
		u.logger.Debug("Ignoring malformed datagram")
		return nil
	}

	// TODO: implement fragmenting
	if datagram[2] != 0x00 {
		u.logger.Debug("Dropping fragmented datagram")
		return nil
	}

	reader := bytes.NewReader(datagram[4:])
	dst, err := parseAddress(reader, u.resolver, datagram[3])
	if err != nil {
		u.logger.Debug("Ignoring datagram with invalid address", slog.String("error", err.Error()))
		return nil
	}

	portOctets, err := readBytes(reader, 2)
	if err != nil {
		u.logger.Debug("Ignoring datagram with invalid port", slog.String("error", err.Error()))
		return nil
	}

	port := binary.BigEndian.Uint16(portOctets)

	data, err := io.ReadAll(reader)
	if err != nil {
		// this shouldn't ever happen since reader is wrapping an in memory buffer
		return fmt.Errorf("failed to read datagram: %w", err)
	}

	remote := netip.AddrPortFrom(dst, port)

	conn, err := net.DialUDP(
		"udp",
		nil,
		net.UDPAddrFromAddrPort(remote),
	)
	if err != nil {
		u.logger.Debug("Couldn't connect", slog.String("err", err.Error()), slog.String("remote", remote.String()))
		return nil
	}
	defer conn.Close()

	_, _, err = conn.WriteMsgUDP(data, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to write datagram: %w", err)
	}

	return nil
}
