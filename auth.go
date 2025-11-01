package sockit

import (
	"errors"
	"fmt"
	"net"
)

type User struct {
	Username string
	Password string
}

type UserPassMethod struct {
	users []User
}

var (
	userPassAuthVersion byte = 0x01

	errUnauthorised = errors.New("unauthorised user")
	errInvalidUsers = errors.New("invalid user auth config")
)

func WithUserPassAuth(users ...User) ProxyOption {
	return func(p *Proxy) error {
		if len(users) == 0 {
			return errInvalidUsers
		}

		if p.methods == nil {
			p.methods = map[byte]MethodNegotiator{}
		}

		p.methods[methodAuth] = &UserPassMethod{users: users}
		return nil
	}
}

func (u *UserPassMethod) Negotiate(conn net.Conn) error {
	version, err := readBytes(conn, 1)
	if err != nil {
		return err
	}

	if version[0] != 0x01 {
		return errInvalidVersion
	}

	username, err := readBytesFromLength(conn)
	if err != nil {
		return err
	}

	password, err := readBytesFromLength(conn)
	if err != nil {
		return err
	}

	for _, user := range u.users {
		if user.Username == string(username) && user.Password == string(password) {
			if _, err := conn.Write([]byte{userPassAuthVersion, 0x00}); err != nil {
				return fmt.Errorf("failed to write auth success: %w", err)
			}
			return nil
		}
	}

	if _, err = conn.Write([]byte{userPassAuthVersion, 0x01}); err != nil {
		return fmt.Errorf("failed to write auth failure: %w", err)
	}

	return errUnauthorised
}
