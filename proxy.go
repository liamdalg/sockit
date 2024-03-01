package sockit

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strconv"
)

type Proxy struct {
	socket net.Listener

	_logger *slog.Logger
}

type ProxyOption func(*Proxy) error

func Listen(address string, options ...ProxyOption) (*Proxy, error) {
	socket, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to create tcp listener: %w", err)
	}

	p := &Proxy{
		socket: socket,
	}

	for _, o := range options {
		err := o(p)
		if err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	err = p.applyDefaults()
	if err != nil {
		return nil, fmt.Errorf("failed to apply defaults: %w", err)
	}

	return p, nil
}

func WithLogger(logger *slog.Logger) ProxyOption {
	return func(p *Proxy) error {
		p._logger = logger
		return nil
	}
}

func (p *Proxy) applyDefaults() error {
	if p._logger == nil {
		p._logger = slog.Default()
	}

	return nil
}

func (p *Proxy) Start() error {
	for {
		conn, err := p.socket.Accept()
		if err != nil {
			// TODO: make not fatal
			return fmt.Errorf("naughty connection: %w", err)
		}

		go p.handleConnection(conn)
	}
}

func (p *Proxy) handleConnection(conn net.Conn) {
	defer conn.Close()

	logger := p._logger.With(slog.String("conn", conn.RemoteAddr().String()))
	logger.Info("Accepted connection")

	err := p.handshake(conn, logger)
	if err != nil {
		logger.Error("Failed handshake", slog.String("error", err.Error()))
		conn.Write([]byte(err.Error()))
		return
	}

	err = p.handleRequest(conn, logger)
	if err != nil {
		logger.Error("Failed reply", slog.String("error", err.Error()))
		conn.Write([]byte(err.Error()))
		return
	}
}

func (p *Proxy) handshake(conn net.Conn, logger *slog.Logger) error {
	logger.Debug("Performing handshake with %s\n", conn.RemoteAddr())

	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return err
	}

	if buf[0] != 0x05 {
		return errors.New("invalid version")
	}

	methods := make([]byte, buf[1])
	_, err = io.ReadFull(conn, methods)
	if err != nil {
		return err
	}

	if !slices.Contains(methods, 0x00) {
		return errors.New("unsupported method(s)")
	}

	_, err = conn.Write([]byte{0x05, 0x00})
	if err != nil {
		return errors.New("failed to write response")
	}

	return nil
}

func (p *Proxy) handleRequest(conn net.Conn, logger *slog.Logger) error {
	logger.Debug("Handling request")

	buf := make([]byte, 4)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return err
	}

	if buf[0] != 0x05 {
		return errors.New("unsupported version")
	}

	if buf[1] != 0x01 {
		return errors.New("unsupported command")
	}

	if buf[2] != 0x00 {
		return errors.New("malformed request")
	}

	ip, err := p.parseAddress(buf[3], conn)
	if err != nil {
		return errors.New("bad host")
	}

	portOctets := make([]byte, 2)
	_, err = io.ReadFull(conn, portOctets)
	if err != nil {
		return err
	}

	port := binary.BigEndian.Uint16(portOctets)

	dst, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ip.String(), port))
	if err != nil {
		return err
	}

	bindAddrStr, bindPortStr, err := net.SplitHostPort(dst.RemoteAddr().String())
	if err != nil {
		return err
	}

	bindPort, err := strconv.Atoi(bindPortStr)
	if err != nil {
		return err
	}

	var response []byte
	response = append(response, 0x05, 0x00, 0x00, 0x01)
	response = append(response, net.ParseIP(bindAddrStr).To4()...)

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(bindPort))
	response = append(response, portBytes...)

	logger.Debug("Sending handshake reply", slog.String("buffer", hex.EncodeToString(response)))

	conn.Write(response)

	return copyStreams(conn, dst)
}

func (p *Proxy) parseAddress(addrType byte, conn net.Conn) (net.IP, error) {
	if addrType == 0x01 {
		buf := make([]byte, 4)
		_, err := io.ReadFull(conn, buf)
		if err != nil {
			return nil, err
		}

		return net.IPv4(buf[0], buf[1], buf[2], buf[3]), nil
	} else if addrType == 0x03 {
		len := make([]byte, 1)
		_, err := io.ReadFull(conn, len)
		if err != nil {
			return nil, err
		}

		domainOctets := make([]byte, len[0])
		_, err = io.ReadFull(conn, domainOctets)
		if err != nil {
			return nil, err
		}

		// TODO: return 0x04 HERE
		ips, err := net.LookupIP(string(domainOctets))
		if err != nil {
			return nil, err
		}

		return ips[0], nil
	} else if addrType == 0x04 {
		buf := make([]byte, 16)
		_, err := io.ReadFull(conn, buf)
		if err != nil {
			return nil, err
		}

		return net.IP(buf), nil
	} else {
		return nil, errors.New("malformed address type")
	}
}
