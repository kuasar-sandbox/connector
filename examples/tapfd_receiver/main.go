// tapfd_receiver listens on a unix socket and prints the first tap fd +
// metadata it receives from vswitch-ctl. Pair it with:
//
//	TAPFD_SOCKET=/tmp/recv.sock vswitch-ctl open-port <sw> --port=N
//
// Build: go build ./examples/tapfd_receiver
// Run:   ./tapfd_receiver /tmp/recv.sock
package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/fullof-work/sandbox-vswitch/pkg/tapfd"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <socket-path>\n", os.Args[0])
		os.Exit(2)
	}
	path := os.Args[1]
	_ = os.Remove(path)

	ln, err := net.Listen("unix", path)
	if err != nil {
		log.Fatalf("listen %s: %v", path, err)
	}
	defer func() {
		ln.Close()
		os.Remove(path)
	}()
	fmt.Fprintf(os.Stderr, "listening on %s (waiting for vswitch-ctl)\n", path)

	c, err := ln.Accept()
	if err != nil {
		log.Fatalf("accept: %v", err)
	}
	defer c.Close()

	uc := c.(*net.UnixConn)
	f, meta, err := tapfd.RecvFd(uc)
	if err != nil {
		log.Fatalf("RecvFd: %v", err)
	}
	defer f.Close()

	fmt.Printf("port=%d mac=%s mtu=%d ip=%s fd_count=%d local_fd=%d\n",
		meta.Port, meta.MAC, meta.MTU, meta.InnerIP, meta.FDCount, f.Fd())
}
