package main

import (
	"log/slog"
	"os"

	"github.com/liamdalg/sockit"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	proxy, err := sockit.Listen(
		":1080",
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
