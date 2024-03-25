package sockit

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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

type CommandArgs struct {
	conn     net.Conn
	dst      netip.AddrPort
	callback func(netip.AddrPort) error
	logger   *slog.Logger
}

type CommandFunc func(*CommandArgs) error

const (
	addressTypeIPV4   byte = 0x01
	addressTypeDomain byte = 0x03
	addressTypeIPV6   byte = 0x04
	socksVersion      byte = 0x05
)

var (
	errInvalidVersion = &SocksError{
		Message: "unsupported socks version",
		Code:    0xFF,
	}
	errNoAcceptableMethods = &SocksError{
		Message: "no acceptable methods",
		Code:    0xFF,
	}

	errNetworkUnreachable = &SocksError{
		Message: "network unreachable",
		Code:    0x03,
	}
	errHostUnreachable = &SocksError{
		Message: "host unreachable",
		Code:    0x04,
	}
	errUnsupportedCommand = &SocksError{
		Message: "unsupported command",
		Code:    0x07,
	}

	unspecifiedAddr = netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
)

type SocksError struct {
	Message string
	Code    byte
	Inner   error
}

func (e *SocksError) Error() string {
	return e.Message
}

func (e *SocksError) Unwrap() error {
	return e.Inner
}

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

		return errNoAcceptableMethods
	}

	_, err = conn.Write([]byte{socksVersion, method})
	if err != nil {
		return err
	}

	err = p.methods[method].Negotiate(conn)

	return err
}

func (p *Proxy) handleRequest(conn net.Conn, logger *slog.Logger) error {
	logger.Debug("Handling request")

	handler, ip, err := readRequest(conn)
	if err != nil {
		var socksErr *SocksError
		if errors.As(err, &socksErr) {
			sendReply(conn, socksErr.Code, unspecifiedAddr, logger)
		} else {
			sendReply(conn, 0x01, unspecifiedAddr, logger)
		}
		return err
	}

	args := CommandArgs{
		conn: conn,
		dst:  ip,
		callback: func(bind netip.AddrPort) error {
			return sendReply(conn, 0x00, bind, logger)
		},
		logger: logger,
	}

	return handler(&args)
}

func readRequest(conn net.Conn) (CommandFunc, netip.AddrPort, error) {
	buf, err := readBytes(conn, 4)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}

	if buf[0] != socksVersion {
		return nil, netip.AddrPort{}, errInvalidVersion
	}

	var command CommandFunc

	switch buf[1] {
	case 0x01:
		command = handleConnectCommand
	case 0x03:
		command = handleUDPCommand
	default:
		return nil, netip.AddrPort{}, errUnsupportedCommand
	}

	ip, err := parseAddress(buf[3], conn)
	if err != nil {
		return nil, netip.AddrPort{}, errHostUnreachable
	}

	portOctets, err := readBytes(conn, 2)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}

	port := binary.BigEndian.Uint16(portOctets)

	return command, netip.AddrPortFrom(ip, port), nil
}

func sendReply(conn net.Conn, status byte, bind netip.AddrPort, logger *slog.Logger) error {
	ipLength := 4
	addrType := addressTypeIPV4
	if bind.Addr().Is6() {
		addrType = addressTypeIPV6
		ipLength = 16
	}

	response := make([]byte, 0, 4+ipLength+2)
	response = append(response, socksVersion, status, 0x00, addrType)
	response = append(response, bind.Addr().AsSlice()...)

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, bind.Port())
	response = append(response, portBytes...)

	logger.Debug("Sending handshake reply", slog.String("buffer", hex.EncodeToString(response)))

	_, err := conn.Write(response)
	return err
}

func parseAddress(addrType byte, reader io.Reader) (netip.Addr, error) {
	if addrType == addressTypeDomain {
		domain, err := readBytesFromLength(reader)
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

	buf, err := readBytes(reader, byteLength)
	if err != nil {
		return netip.Addr{}, err
	}

	ip, ok := netip.AddrFromSlice(buf)
	if !ok {
		return netip.Addr{}, errors.New("malformed ip in address")
	}

	return ip, nil
}
