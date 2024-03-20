package sockit

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
)

type udpAssociate struct {
	src        net.Conn
	srcAddress netip.AddrPort
	listener   *net.UDPConn
	bind       netip.AddrPort
	logger     *slog.Logger
}

func (u *udpAssociate) Init(ip netip.AddrPort) (netip.AddrPort, error) {
	listener, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   ip.Addr().AsSlice(),
		Port: 0,
	})
	if err != nil {
		return unspecifiedAddr, err
	}

	bind, err := netip.ParseAddrPort(listener.LocalAddr().String())
	if err != nil {
		return unspecifiedAddr, err
	}

	u.listener = listener
	u.bind = bind

	addr, err := netip.ParseAddrPort(u.src.RemoteAddr().String())
	if err != nil {
		return unspecifiedAddr, err
	}
	u.srcAddress = addr

	u.logger = u.logger.With(slog.String("bind", bind.String()))

	return bind, nil
}

func (u *udpAssociate) Handle() error {
	for {
		// TODO: improve buffers
		buf := make([]byte, 2048)
		n, _, _, _, err := u.listener.ReadMsgUDPAddrPort(buf, nil)
		if err != nil {
			return err
		}

		// TODO: support filtering by source address

		if buf[0] != 0x00 && buf[1] != 0x00 {
			u.logger.Debug("Ignoring malformed datagram", slog.String("error", err.Error()))
			continue
		}

		// frag := buf[2]
		reader := bytes.NewReader(buf[4:n])
		dst, err := parseAddress(buf[3], reader)
		if err != nil {
			u.logger.Debug("Ignoring datagram with invalid address", slog.String("error", err.Error()))
			continue
		}

		portOctets, err := readBytes(reader, 2)
		if err != nil {
			continue
		}

		port := binary.BigEndian.Uint16(portOctets)

		data, err := io.ReadAll(reader)
		if err != nil {
			u.logger.Debug("This shouldn't happen")
			continue
		}

		remote := netip.AddrPortFrom(dst, port)

		conn, err := net.DialUDP(
			"udp",
			nil,
			net.UDPAddrFromAddrPort(remote),
		)
		if err != nil {
			u.logger.Debug("Couldn't connect", slog.String("err", err.Error()), slog.String("remote", remote.String()))
			continue
		}
		defer conn.Close()

		u.logger.Debug("Writing", slog.String("remote", remote.String()), slog.String("msg", string(data)))

		_, _, err = conn.WriteMsgUDP(data, nil, nil)
		if err != nil {
			u.logger.Debug("Stupid writing", slog.String("err", err.Error()))
			continue
		}
	}
}
