package main

import "github.com/liamdalg/sockit"

func main() {
	proxy, err := sockit.Listen("127.0.0.1:1080")
	if err != nil {
		panic(err)
	}

	err = proxy.ProxyConnections()
	if err != nil {
		panic(err)
	}
}
