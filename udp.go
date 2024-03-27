package sockit

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
)

func handleUDPCommand(args *CommandArgs) error {
	listener, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   args.dst.Addr().AsSlice(),
		Port: 0,
	})
	if err != nil {
		return err
	}
	defer listener.Close()

	bind, err := netip.ParseAddrPort(listener.LocalAddr().String())
	if err != nil {
		return err
	}

	// addr, err := netip.ParseAddrPort(args.conn.RemoteAddr().String())
	// if err != nil {
	// 	return err
	// }

	logger := args.logger.With(slog.String("mode", "udp"), slog.String("bind", bind.String()))

	if err := args.callback(bind); err != nil {
		return err
	}

	go waitForClose(args.conn, listener)

	return forwardUDP(listener, logger)
}

func forwardUDP(listener *net.UDPConn, logger *slog.Logger) error {
	for {
		// TODO: improve buffers
		buf := make([]byte, 2048)
		n, _, _, _, err := listener.ReadMsgUDPAddrPort(buf, nil)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		err = forwardMessage(buf[:n], logger)
		if err != nil {
			logger.Error("Caught error when processing datagram", slog.String("error", err.Error()))
		}
	}
}

func forwardMessage(datagram []byte, logger *slog.Logger) error {
	// TODO: support filtering by source address
	if datagram[0] != 0x00 && datagram[1] != 0x00 {
		logger.Debug("Ignoring malformed datagram")
		return nil
	}

	// TODO: implement fragmenting
	if datagram[2] == 0x02 {
		logger.Debug("Dropping fragmented datagram")
		return nil
	}

	reader := bytes.NewReader(datagram[4:])
	dst, err := parseAddress(datagram[3], reader)
	if err != nil {
		logger.Debug("Ignoring datagram with invalid address", slog.String("error", err.Error()))
		return nil
	}

	portOctets, err := readBytes(reader, 2)
	if err != nil {
		logger.Debug("Ignoring datagram with invalid port", slog.String("error", err.Error()))
		return nil
	}

	port := binary.BigEndian.Uint16(portOctets)

	data, err := io.ReadAll(reader)
	if err != nil {
		logger.Debug("You shouldn't see this log ever", slog.String("error", err.Error()))
		return nil
	}

	remote := netip.AddrPortFrom(dst, port)

	conn, err := net.DialUDP(
		"udp",
		nil,
		net.UDPAddrFromAddrPort(remote),
	)
	if err != nil {
		logger.Debug("Couldn't connect", slog.String("err", err.Error()), slog.String("remote", remote.String()))
		return nil
	}
	defer conn.Close()

	_, _, err = conn.WriteMsgUDP(data, nil, nil)
	if err != nil {
		logger.Debug("Stupid writing", slog.String("err", err.Error()))
		return nil
	}

	return nil
}
