package sockit

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
)

type Proxy struct {
	socket  net.Listener
	methods map[byte]MethodNegotiator

	_logger *slog.Logger
}

type MethodNegotiator interface {
	Negotiate(conn net.Conn) error
}

type DefaultMethod struct{}

func (*DefaultMethod) Negotiate(net.Conn) error {
	return nil
}

type ProxyOption func(*Proxy) error

const (
	addressTypeIPV4   byte = 0x01
	addressTypeDomain byte = 0x03
	addressTypeIPV6   byte = 0x04
	socksVersion      byte = 0x05
)

var (
	errInvalidVersion = errors.New("unsupported protocol version")
)

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
	if p.methods == nil {
		p.methods = map[byte]MethodNegotiator{}
		p.methods[0x00] = &DefaultMethod{}
	}

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

		p._logger.Info("Accepted connection")
		go p.handleConnection(conn)
	}
}

func (p *Proxy) handleConnection(conn net.Conn) {
	defer conn.Close()

	logger := p._logger.With(slog.String("conn", conn.RemoteAddr().String()))

	logger.Debug("Performing handshake")
	err := p.handshake(conn)
	if err != nil {
		logger.Error("Failed handshake", slog.String("error", err.Error()))
		return
	}

	err = p.handleRequest(conn, logger)
	if err != nil {
		logger.Error("Failed reply", slog.String("error", err.Error()))
		return
	}
}

func (p *Proxy) handshake(conn net.Conn) error {
	buf, err := readBytes(conn, 1)
	if err != nil {
		return err
	}

	if buf[0] != socksVersion {
		return errInvalidVersion
	}

	methods, err := readBytesFromLength(conn)
	if err != nil {
		return err
	}

	method := byte(0xFF)
	for _, m := range methods {
		if _, ok := p.methods[m]; ok {
			method = m
		}
	}

	if method == 0xFF {
		_, err := conn.Write([]byte{socksVersion, 0xFF})
		if err != nil {
			return err
		}

		return errors.New("unsupported method(s)")
	}

	_, err = conn.Write([]byte{socksVersion, method})
	if err != nil {
		return errors.New("failed to write response")
	}

	err = p.methods[method].Negotiate(conn)

	return err
}

func (p *Proxy) handleRequest(conn net.Conn, logger *slog.Logger) error {
	logger.Debug("Handling request")

	buf, err := readBytes(conn, 4)
	if err != nil {
		return err
	}

	if buf[0] != socksVersion {
		return errors.New("unsupported version")
	}

	if buf[1] != 0x01 {
		return errors.New("unsupported command")
	}

	if buf[2] != 0x00 {
		return errors.New("malformed request")
	}

	ip, err := parseAddress(buf[3], conn)
	if err != nil {
		return errors.New("bad host")
	}

	portOctets, err := readBytes(conn, 2)
	if err != nil {
		return err
	}

	port := binary.BigEndian.Uint16(portOctets)

	dst, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ip.String(), port))
	if err != nil {
		return err
	}

	bind, err := netip.ParseAddrPort(dst.RemoteAddr().String())
	if err != nil {
		return err
	}

	addrType := addressTypeIPV4
	if bind.Addr().Is6() {
		addrType = 16
	}

	var response []byte
	response = append(response, socksVersion, 0x00, 0x00, addrType)
	response = append(response, bind.Addr().AsSlice()...)

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, bind.Port())
	response = append(response, portBytes...)

	logger.Debug("Sending handshake reply", slog.String("buffer", hex.EncodeToString(response)))

	conn.Write(response)

	return copyStreams(conn, dst)
}

func parseAddress(addrType byte, conn net.Conn) (netip.Addr, error) {
	if addrType == addressTypeDomain {
		domain, err := readBytesFromLength(conn)
		if err != nil {
			return netip.Addr{}, err
		}

		ips, err := net.LookupIP(string(domain))
		if err != nil {
			return netip.Addr{}, err
		}

		ip, ok := netip.AddrFromSlice(ips[0])
		if !ok {
			return netip.Addr{}, errors.New("domain resolved to invalid ip")
		}

		return ip, nil
	}

	var byteLength int
	if addrType == addressTypeIPV4 {
		byteLength = 4
	} else if addrType == addressTypeIPV6 {
		byteLength = 16
	} else {
		return netip.Addr{}, errors.New("malformed address")
	}

	buf, err := readBytes(conn, byteLength)
	if err != nil {
		return netip.Addr{}, err
	}

	ip, ok := netip.AddrFromSlice(buf)
	if !ok {
		return netip.Addr{}, errors.New("malformed ip in address")
	}

	return ip, nil
}
