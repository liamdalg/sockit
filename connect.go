package sockit

import (
	"net"
	"net/netip"
)

func handleConnectCommand(args *CommandArgs) error {
	dst, err := net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(args.dst))
	if err != nil {
		return err
	}
	defer dst.Close()

	bind, err := netip.ParseAddrPort(dst.LocalAddr().String())
	if err != nil {
		return err
	}

	if err := args.callback(bind); err != nil {
		return err
	}

	return copyStreams(args.conn, dst)
}
