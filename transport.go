package sockit

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
)

type Proxy struct {
	socket net.Listener

	address string
}

func Listen(address string) (*Proxy, error) {
	socket, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to create tcp listener: %w", err)
	}

	return &Proxy{
		socket:  socket,
		address: strings.Split(address, ":")[0],
	}, nil
}

func (p *Proxy) ProxyConnections() error {
	for {
		conn, err := p.socket.Accept()
		if err != nil {
			// TODO: make not fatal
			return fmt.Errorf("naughty connection: %w", err)
		}

		fmt.Printf("Accepted connection from %s\n", conn.RemoteAddr())

		go p.initProxy(conn)
	}
}

func (p *Proxy) initProxy(conn net.Conn) {
	defer conn.Close()

	fmt.Printf("Performing handshake with %s\n", conn.RemoteAddr())

	err := p.handshake(conn)
	if err != nil {
		fmt.Printf("err: %v", err)
		conn.Write([]byte(err.Error()))
		return
	}

	fmt.Printf("Handling request for %s\n", conn.RemoteAddr())

	err = p.handleRequest(conn)
	if err != nil {
		fmt.Printf("err: %v", err)
		conn.Write([]byte(err.Error()))
		return
	}
}

func (p *Proxy) handshake(conn net.Conn) error {
	fmt.Println("Reading 2 bytes")
	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return err
	}

	if buf[0] != 0x05 {
		return errors.New("invalid version")
	}

	fmt.Println("Reading methods")
	fmt.Println(buf)

	methods := make([]byte, buf[1])
	_, err = io.ReadFull(conn, methods)
	if err != nil {
		return err
	}

	fmt.Println(methods)

	if !slices.Contains(methods, 0x00) {
		return errors.New("unsupported method(s)")
	}

	_, err = conn.Write([]byte{0x05, 0x00})
	if err != nil {
		return errors.New("failed to write response")
	}

	return nil
}

func (p *Proxy) handleRequest(conn net.Conn) error {
	fmt.Println("Reading 4 bytes")
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

	fmt.Println("Reading address")

	ip, err := p.parseAddress(buf[3], conn)
	if err != nil {
		return errors.New("bad host")
	}

	fmt.Println("Reading port")

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

	_, bindPortStr, err := net.SplitHostPort(dst.RemoteAddr().String())
	if err != nil {
		return err
	}

	bindPort, err := strconv.Atoi(bindPortStr)
	if err != nil {
		return err
	}

	var response []byte
	response = append(response, 0x05, 0x00, 0x00, 0x01)
	response = append(response, net.ParseIP(p.address)[12:]...)

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(bindPort))
	response = append(response, portBytes...)

	fmt.Printf("Big response %v\n", response)

	conn.Write(response)

	go func() {
		srcBuffer := make([]byte, 512)
		for {
			n, err := dst.Read(srcBuffer)
			if err != nil {
				return
			}

			fmt.Println(string(srcBuffer[:n]))

			_, err = conn.Write(srcBuffer[:n])
			if err != nil {
				return
			}
		}
	}()

	dstBuffer := make([]byte, 512)
	for {
		n, err := conn.Read(dstBuffer)
		if err != nil {
			return err
		}

		fmt.Println(string(dstBuffer[:n]))

		_, err = dst.Write(dstBuffer[:n])
		if err != nil {
			return err
		}
	}

	return errors.New("wtf")
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
