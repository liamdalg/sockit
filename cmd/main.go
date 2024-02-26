package main

import (
	"log/slog"
	"os"

	"github.com/liamdalg/sockit"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	proxy, err := sockit.Listen(
		"127.0.0.1:1080",
		sockit.WithLogger(logger),
	)
	if err != nil {
		panic(err)
	}

	err = proxy.ProxyConnections()
	if err != nil {
		panic(err)
	}
}
