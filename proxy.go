package sockit

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"

	"golang.org/x/net/proxy"
)

type Proxy struct {
	listener net.Listener
	methods  map[byte]MethodNegotiator
	resolver *net.Resolver
	dialer   proxy.Dialer

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

type Command interface {
	Process() error
	Bind() netip.AddrPort
	Close() error
}

const (
	addressTypeIPV4   byte = 0x01
	addressTypeDomain byte = 0x03
	addressTypeIPV6   byte = 0x04

	methodNoAuth byte = 0x00
	methodAuth   byte = 0x02

	socksVersion byte = 0x05

	commandConnect byte = 0x01
	commandUDP     byte = 0x03
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

	errServerError = &SocksError{
		Message: "general SOCKS server failure",
		Code:    0x01,
	}
	// errNetworkUnreachable = &SocksError{
	// 	Message: "network unreachable",
	// 	Code:    0x03,
	// }
	errHostUnreachable = &SocksError{
		Message: "host unreachable",
		Code:    0x04,
	}
	errUnsupportedCommand = &SocksError{
		Message: "unsupported command",
		Code:    0x07,
	}
	errUnsupportedAddressType = &SocksError{
		Message: "unsupported address type",
		Code:    0x08,
	}

	unspecifiedAddr = netip.AddrPortFrom(netip.IPv4Unspecified(), 0)

	errMalformedIP       = errors.New("malformed IP address")
	errUnsupportedParent = errors.New("unsupported parent scheme")
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

func Listen(listener net.Listener, options ...ProxyOption) (*Proxy, error) {
	p := &Proxy{
		listener: listener,
	}

	for _, o := range options {
		err := o(p)
		if err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	err := p.applyDefaults()
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

func WithParent(parent *url.URL) ProxyOption {
	return func(p *Proxy) error {
		switch parent.Scheme {
		case "http":
			// TODO: support this
			break
		case "socks5":
		case "socks5h":
			// TODO: support auth better?
			var auth *proxy.Auth
			if parent.User != nil {
				password, _ := parent.User.Password()
				auth = &proxy.Auth{
					User:     parent.User.Username(),
					Password: password,
				}
			}

			dialer, err := proxy.SOCKS5("tcp", parent.Host, auth, nil)
			if err != nil {
				return fmt.Errorf("failed to create dialer for parent: %w", err)
			}

			p.dialer = dialer
		default:
			return fmt.Errorf("%w: %s", errUnsupportedParent, parent.Scheme)
		}

		return nil
	}
}

func (p *Proxy) applyDefaults() error {
	if p.methods == nil {
		p.methods = map[byte]MethodNegotiator{}
		p.methods[methodNoAuth] = &DefaultMethod{}
	}

	if p._logger == nil {
		p._logger = slog.Default()
	}

	if p.dialer == nil {
		p.dialer = &net.Dialer{}
	}

	return nil
}

func (p *Proxy) Start() error {
	for {
		conn, err := p.listener.Accept()
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
		// fine to ignore errors here, it's already fatal
		_, _ = conn.Write([]byte{socksVersion, 0xFF})
		return errNoAcceptableMethods
	}

	_, err = conn.Write([]byte{socksVersion, method})
	if err != nil {
		return fmt.Errorf("failed to send proxy method: %w", err)
	}

	if err = p.methods[method].Negotiate(conn); err != nil {
		return fmt.Errorf("failed to negotiate proxy method: %w", err)
	}

	return nil
}

func (p *Proxy) handleRequest(conn net.Conn, logger *slog.Logger) error {
	logger.Debug("Handling request")

	command, err := readRequest(conn, p.dialer, p.resolver, logger)
	if err != nil {
		var socksErr *SocksError
		if !errors.As(err, &socksErr) {
			logger.Error("caught unknown error", slog.String("err", err.Error()))
			socksErr = errServerError
		}
		_ = sendReply(conn, socksErr.Code, unspecifiedAddr, logger)
		return err
	}
	defer command.Close()

	if err := sendReply(conn, 0x00, command.Bind(), logger); err != nil {
		return err
	}

	if err := command.Process(); err != nil {
		return fmt.Errorf("failed to process command: %w", err)
	}

	return nil
}

// TODO: make these private methods?
func readRequest(conn net.Conn, dialer proxy.Dialer, resolver *net.Resolver, logger *slog.Logger) (Command, error) {
	buf, err := readBytes(conn, 4)
	if err != nil {
		return nil, err
	}

	if buf[0] != socksVersion {
		return nil, errInvalidVersion
	}

	ip, err := parseAddress(conn, resolver, buf[3])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errHostUnreachable, err)
	}

	portOctets, err := readBytes(conn, 2)
	if err != nil {
		return nil, err
	}

	port := binary.BigEndian.Uint16(portOctets)

	switch buf[1] {
	case commandConnect:
		return establishConnect(dialer, conn, netip.AddrPortFrom(ip, port), logger)
	default:
		return nil, errUnsupportedCommand
	}
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

	if _, err := conn.Write(response); err != nil {
		return fmt.Errorf("failed to write handshake: %w", err)
	}
	return nil
}

func parseAddress(reader io.Reader, resolver *net.Resolver, addrType byte) (netip.Addr, error) {
	if addrType == addressTypeDomain {
		domain, err := readBytesFromLength(reader)
		if err != nil {
			return netip.Addr{}, err
		}

		ips, err := resolver.LookupHost(context.TODO(), string(domain))
		if err != nil {
			return netip.Addr{}, fmt.Errorf("domain did not resolve: %w", err)
		}

		ip, err := netip.ParseAddr(ips[0])
		if err != nil {
			return netip.Addr{}, fmt.Errorf("failed to parse ip: %w", err)
		}

		return ip, nil
	}

	var byteLength int
	switch addrType {
	case addressTypeIPV4:
		byteLength = 4
	case addressTypeIPV6:
		byteLength = 16
	default:
		return netip.Addr{}, errUnsupportedAddressType
	}

	buf, err := readBytes(reader, byteLength)
	if err != nil {
		return netip.Addr{}, err
	}

	ip, ok := netip.AddrFromSlice(buf)
	if !ok {
		return netip.Addr{}, errMalformedIP
	}

	return ip, nil
}
