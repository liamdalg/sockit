package dialer

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
)

type Http struct {
	Address       string
	Authorization string
}

var errBadConnectStatusCode = errors.New("got bad status code response from CONNECT")

func (h *Http) Dial(network string, address string) (net.Conn, error) {
	//nolint:noctx
	conn, err := net.Dial(network, h.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to dial proxy: %w", err)
	}

	connect := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: address},
	}

	if h.Authorization != "" {
		connect.Header = make(http.Header)
		connect.Header.Add("Proxy-Authorization", h.Authorization)
	}

	err = connect.Write(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to write CONNECT request: %w", err)
	}

	bufReader := bufio.NewReader(conn)

	//nolint:bodyclose
	resp, err := http.ReadResponse(bufReader, connect)
	if err != nil {
		return nil, fmt.Errorf("failed to read CONNECT response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()

		return nil, fmt.Errorf("%w: %d", errBadConnectStatusCode, resp.StatusCode)
	}

	return conn, nil
}
