package main

import (
	"flag"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/liamdalg/sockit"
)

func main() {
	parent := flag.String("parent", "", "address of parent proxy")
	address := flag.String("address", ":1080", "address to listen on")
	auth := flag.String("auth", "", "user:password authentication")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	listener, err := net.Listen("tcp", *address)
	if err != nil {
		panic(err)
	}

	opts := []sockit.ProxyOption{sockit.WithLogger(logger)}
	if parent != nil && *parent != "" {
		url, err := url.Parse(*parent)
		if err != nil {
			panic(err)
		}

		opts = append(opts, sockit.WithParent(url))
	}

	if auth != nil && *auth != "" {
		parts := strings.Split(*auth, ":")
		if len(parts) != 2 {
			panic("auth should be in the format user:pass")
		}

		opts = append(opts, sockit.WithUserPassAuth(
			sockit.User{Username: parts[0], Password: parts[1]},
		))
	}

	proxy, err := sockit.Listen(
		listener,
		opts...,
	)
	if err != nil {
		panic(err)
	}

	err = proxy.Start()
	if err != nil {
		panic(err)
	}
}
