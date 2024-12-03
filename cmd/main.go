package main

import (
	"log/slog"
	"net"
	"os"

	"github.com/liamdalg/sockit"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	listener, err := net.Listen("tcp", ":1080")
	if err != nil {
		panic(err)
	}

	proxy, err := sockit.Listen(
		listener,
		sockit.WithLogger(logger),
		// sockit.WithUserPassAuth(
		// 	sockit.User{Username: "admin", Password: "password"},
		// 	sockit.User{Username: "admin2", Password: "password2"},
		// ),
	)
	if err != nil {
		panic(err)
	}

	err = proxy.Start()
	if err != nil {
		panic(err)
	}
}
