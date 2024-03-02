package sockit

import (
	"errors"
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

		p.methods[0x02] = &UserPassMethod{users: users}
		return nil
	}
}

func (u *UserPassMethod) Negotiate(conn net.Conn) error {
	version, err := readN(conn, 1)
	if err != nil {
		return err
	}

	if version[0] != 0x01 {
		return errInvalidVersion
	}

	userLength, err := readN(conn, 1)
	if err != nil {
		return err
	}

	username, err := readN(conn, int(userLength[0]))
	if err != nil {
		return err
	}

	passLength, err := readN(conn, 1)
	if err != nil {
		return err
	}

	password, err := readN(conn, int(passLength[0]))
	if err != nil {
		return err
	}

	for _, user := range u.users {
		if user.Username == string(username) && user.Password == string(password) {
			_, err := conn.Write([]byte{socksVersion, 0x00})
			return err
		}
	}

	_, err = conn.Write([]byte{socksVersion, 0x01})
	if err != nil {
		return err
	}

	return errUnauthorised
}
